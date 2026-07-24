// Command loadgen is the load generator used by the krouter performance gate
// (docs/spec/performance.md, docs/spec/acceptance.md criterion 10) and by the comparative benchmark suite
// (docs/spec/acceptance.md criterion 11). It only uses the Go standard library so it can be executed with
// `go run ./tests/src/loadgen` from a stock golang container attached to the kind
// docker network.
//
// Modes:
//
//   - hold: open -connections downstream keep-alive connections, hold them
//     for -duration while issuing one request per -interval on every
//     connection. Any transparent reconnect (detected with httptrace) is
//     counted as a disconnect. This validates the 10,000 concurrent
//     connection release gate and connection survival across reloads.
//
//   - load: run -connections closed-loop workers, each issuing requests as
//     fast as possible over its own keep-alive connection for -duration.
//     Reports throughput, latency percentiles and a per-second timeline so a
//     configuration reload window can be correlated with errors.
//
// The result is emitted as a single JSON document on stdout.
package main

import (
	"context"
	"flag"
	"fmt"

	"slices"
	"sort"

	"os"
	"os/signal"
	"syscall"

	"encoding/json"
	"io"

	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptrace"

	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type config struct {
	mode        string
	url         string
	host        string
	connections int
	duration    time.Duration
	interval    time.Duration
	timeout     time.Duration
	insecure    bool
	rampWorkers int
}

type second struct {
	Second      int   `json:"second"`
	Requests    int64 `json:"requests"`
	Errors      int64 `json:"errors"`
	Disconnects int64 `json:"disconnects"`
}

// reconnect is one transparent replacement of a held connection; the old
// local address is the join key into node-side packet captures.
type reconnect struct {
	AtSeconds float64 `json:"at_s"`
	Old       string  `json:"old"`
	New       string  `json:"new"`
}

type latency struct {
	MeanMs float64 `json:"mean_ms"`
	P50Ms  float64 `json:"p50_ms"`
	P95Ms  float64 `json:"p95_ms"`
	P99Ms  float64 `json:"p99_ms"`
	MaxMs  float64 `json:"max_ms"`
}

type report struct {
	Mode            string      `json:"mode"`
	URL             string      `json:"url"`
	Connections     int         `json:"connections"`
	DurationSeconds float64     `json:"duration_seconds"`
	Established     int64       `json:"established"`
	ConnectErrors   int64       `json:"connect_errors"`
	Requests        int64       `json:"requests"`
	RequestErrors   int64       `json:"request_errors"`
	Non2xx          int64       `json:"non_2xx"`
	Disconnects     int64       `json:"disconnects"`
	CloseDemanded   int64       `json:"close_demanded"`
	BytesIn         int64       `json:"bytes_in"`
	RequestsPerSec  float64     `json:"requests_per_sec"`
	Latency         latency     `json:"latency"`
	Timeline        []second    `json:"timeline"`
	Reconnects      []reconnect `json:"reconnects"`
}

type collector struct {
	established   atomic.Int64
	connectErrors atomic.Int64
	requests      atomic.Int64
	requestErrors atomic.Int64
	non2xx        atomic.Int64
	disconnects   atomic.Int64
	closeDemanded atomic.Int64
	bytesIn       atomic.Int64

	start time.Time

	mu         sync.Mutex
	latencies  []time.Duration
	timeline   map[int]*second
	reconnects []reconnect
}

func newCollector() *collector {
	return &collector{timeline: map[int]*second{}}
}

// cellLocked returns the timeline cell for the current second; c.mu must be
// held by the caller.
func (c *collector) cellLocked() *second {
	sec := int(time.Since(c.start).Seconds())

	cell, ok := c.timeline[sec]
	if !ok {
		cell = &second{Second: sec}
		c.timeline[sec] = cell
	}

	return cell
}

func (c *collector) record(d time.Duration, err bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cell := c.cellLocked()
	cell.Requests++

	if err {
		cell.Errors++
	} else {
		c.latencies = append(c.latencies, d)
	}
}

func (c *collector) recordDisconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cellLocked().Disconnects++
}

func (c *collector) recordReconnect(old, cur string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.reconnects = append(c.reconnects, reconnect{
		AtSeconds: time.Since(c.start).Seconds(),
		Old:       old,
		New:       cur,
	})
}

func (c *collector) report(cfg config, elapsed time.Duration) report {
	c.mu.Lock()
	defer c.mu.Unlock()

	slices.Sort(c.latencies)
	pct := func(p float64) float64 {
		if len(c.latencies) == 0 {
			return 0
		}

		idx := int(p * float64(len(c.latencies)-1))

		return float64(c.latencies[idx]) / float64(time.Millisecond)
	}

	var sum time.Duration
	for _, d := range c.latencies {
		sum += d
	}

	mean := 0.0
	if len(c.latencies) > 0 {
		mean = float64(sum) / float64(len(c.latencies)) / float64(time.Millisecond)
	}

	timeline := make([]second, 0, len(c.timeline))
	for _, cell := range c.timeline {
		timeline = append(timeline, *cell)
	}

	sort.Slice(timeline, func(i, j int) bool { return timeline[i].Second < timeline[j].Second })

	return report{
		Mode:            cfg.mode,
		URL:             cfg.url,
		Connections:     cfg.connections,
		DurationSeconds: elapsed.Seconds(),
		Established:     c.established.Load(),
		ConnectErrors:   c.connectErrors.Load(),
		Requests:        c.requests.Load(),
		RequestErrors:   c.requestErrors.Load(),
		Non2xx:          c.non2xx.Load(),
		Disconnects:     c.disconnects.Load(),
		CloseDemanded:   c.closeDemanded.Load(),
		BytesIn:         c.bytesIn.Load(),
		RequestsPerSec:  float64(c.requests.Load()) / elapsed.Seconds(),
		Latency: latency{
			MeanMs: mean,
			P50Ms:  pct(0.50),
			P95Ms:  pct(0.95),
			P99Ms:  pct(0.99),
			MaxMs:  pct(1.0),
		},
		Timeline:   timeline,
		Reconnects: append([]reconnect(nil), c.reconnects...),
	}
}

// disconnectTracker folds the failure of a request and the reconnect that
// necessarily follows it into a single disconnect event, so one dropped
// connection counts once. Consecutive failures likewise collapse: the
// connection died once, however long it takes to come back.
type disconnectTracker struct {
	dead bool
}

func (t *disconnectTracker) observe(col *collector, newConn bool, err error) {
	if err != nil {
		if !t.dead {
			col.disconnects.Add(1)
			col.recordDisconnect()
		}
		t.dead = true

		return
	}

	if newConn && !t.dead {
		col.disconnects.Add(1)
		col.recordDisconnect()
	}
	t.dead = false
}

// holdActive gates the close-stack tracing: the mass teardown at the end
// of the run is expected and must not print ten thousand stacks.
var holdActive atomic.Bool

// stackBudget caps how many close stacks get printed even while the hold
// is active, in case a systemic event closes many connections at once.
var stackBudget atomic.Int64

// tracedConn prints the goroutine stack of whoever closes it while the
// hold is active: the packet captures proved the loadgen process itself
// FINs healthy pooled connections moments after a successful exchange,
// and only the closing code path can say why.
type tracedConn struct {
	net.Conn
	col  *collector
	once sync.Once
}

func (c *tracedConn) Close() error {
	c.once.Do(func() {
		if !holdActive.Load() || stackBudget.Add(-1) < 0 {
			return
		}

		buf := make([]byte, 8192)
		n := runtime.Stack(buf, false)
		fmt.Fprintf(
			os.Stderr,
			"loadgen: conn %s closed at t=%.1fs by:\n%s\n",
			c.Conn.LocalAddr(),
			time.Since(c.col.start).Seconds(),
			buf[:n],
		)
	})

	return c.Conn.Close()
}

// newClient builds an HTTP client owning exactly one TCP connection, so that
// N clients == N downstream connections and transparent reconnects are
// observable per connection.
func newClient(cfg config, col *collector) *http.Client {
	transport := &http.Transport{
		MaxConnsPerHost:     1,
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     0, // never expire idle connections locally
		DisableCompression:  true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}

			return &tracedConn{Conn: conn, col: col}, nil
		},
	}

	if cfg.insecure {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, // test/benchmark tool: endpoint identity is not under test
			ServerName:         cfg.host,
		}
	}

	return &http.Client{Transport: transport, Timeout: cfg.timeout}
}

// connAddrs remembers the transport's local address per held connection so
// a transparent reconnect can name the flow that died: the previous local
// port is the join key into the node-side packet capture.
type connAddrs struct {
	prev string
	cur  string
}

// doRequest issues one GET and reports whether the transport had to open a
// new TCP connection to serve it.
func doRequest(ctx context.Context, client *http.Client, cfg config, col *collector, addrs *connAddrs) (newConn bool, err error) {
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			local := ""
			if info.Conn != nil {
				local = info.Conn.LocalAddr().String()
			}

			if !info.Reused {
				newConn = true
				addrs.prev = addrs.cur
			}
			addrs.cur = local
		},
		PutIdleConn: func(err error) {
			// A pool rejection closes the connection now and forces a
			// fresh dial on the next request: exactly the shape of the
			// silent reconnects under investigation.
			if err != nil {
				fmt.Fprintf(
					os.Stderr,
					"loadgen: pool rejected conn %s at t=%.1fs: %v\n",
					addrs.cur,
					time.Since(col.start).Seconds(),
					err,
				)
			}
		},
	}

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, cfg.url, nil)
	if err != nil {
		return newConn, err
	}

	if cfg.host != "" {
		req.Host = cfg.host
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		// The end-of-run cancellation aborts whatever requests are in
		// flight; they say nothing about the proxy and are not counted.
		if ctx.Err() == nil {
			col.requests.Add(1)
			col.requestErrors.Add(1)
			col.record(0, true)
		}
		return newConn, err
	}

	// A response can lawfully force the connection closed: an explicit
	// Connection: close, or an EOF-framed body (neither Content-Length nor
	// chunked encoding), which HTTP/1.1 can only delimit by teardown. The
	// transport reopens on the next request; telling this apart from a
	// proxy-initiated drop is what attributes the disconnect.
	if resp.Close || (resp.ContentLength < 0 && len(resp.TransferEncoding) == 0) {
		col.closeDemanded.Add(1)
		fmt.Fprintf(
			os.Stderr,
			"loadgen: close-demanding response at t=%.1fs: status=%d close=%v content_length=%d transfer_encoding=%v\n",
			time.Since(col.start).Seconds(),
			resp.StatusCode,
			resp.Close,
			resp.ContentLength,
			resp.TransferEncoding,
		)
	}

	n, readErr := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// A failed body read is a failed request: swallowing it records a
	// phantom success while Body.Close tears the connection down (the
	// client-first FIN in the packet captures) and the next request
	// silently reopens. Surface it, with the transport's own reason.
	if readErr != nil {
		if ctx.Err() == nil {
			col.requests.Add(1)
			col.requestErrors.Add(1)
			col.record(time.Since(start), true)
			fmt.Fprintf(
				os.Stderr,
				"loadgen: body read failed at t=%.1fs after %s: %v\n",
				time.Since(col.start).Seconds(),
				time.Since(start),
				readErr,
			)
		}
		return newConn, fmt.Errorf("reading response body: %w", readErr)
	}

	col.bytesIn.Add(n)
	col.requests.Add(1)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		col.non2xx.Add(1)
		col.record(time.Since(start), true)
		return newConn, fmt.Errorf("status %d", resp.StatusCode)
	}

	col.record(time.Since(start), false)
	return newConn, nil
}

func runHold(ctx context.Context, cfg config, col *collector) {
	holdActive.Store(true)
	stackBudget.Store(20)
	context.AfterFunc(ctx, func() { holdActive.Store(false) })

	var wg sync.WaitGroup
	// Ramp connections in batches to avoid a SYN stampede.
	sem := make(chan struct{}, cfg.rampWorkers)

	for i := 0; i < cfg.connections; i++ {
		wg.Go(func() {
			client := newClient(cfg, col)
			defer client.CloseIdleConnections()

			var addrs connAddrs

			sem <- struct{}{}
			_, err := doRequest(ctx, client, cfg, col, &addrs)
			<-sem
			if err != nil {
				col.connectErrors.Add(1)
				return
			}
			col.established.Add(1)

			ticker := time.NewTicker(cfg.interval)
			defer ticker.Stop()

			var tracker disconnectTracker

			for {
				select {
				case <-ctx.Done():
					return

				case <-ticker.C:
					wasDead := tracker.dead
					newConn, err := doRequest(ctx, client, cfg, col, &addrs)
					if ctx.Err() != nil {
						return
					}
					// A reconnect or a failed request on an established
					// connection means the proxy dropped us: exactly what
					// docs/spec/performance.md forbids during reloads.
					tracker.observe(col, newConn, err)

					if newConn && err == nil && !wasDead {
						col.recordReconnect(addrs.prev, addrs.cur)
						fmt.Fprintf(
							os.Stderr,
							"loadgen: transparent reconnect at t=%.1fs: %s -> %s\n",
							time.Since(col.start).Seconds(),
							addrs.prev,
							addrs.cur,
						)
					}
				}
			}
		})
	}

	wg.Wait()
}

func runLoad(ctx context.Context, cfg config, col *collector) {
	holdActive.Store(true)
	stackBudget.Store(20)
	context.AfterFunc(ctx, func() { holdActive.Store(false) })

	var wg sync.WaitGroup
	for i := 0; i < cfg.connections; i++ {
		wg.Go(func() {
			client := newClient(cfg, col)
			defer client.CloseIdleConnections()

			var addrs connAddrs

			first := true
			var tracker disconnectTracker

			for ctx.Err() == nil {
				newConn, err := doRequest(ctx, client, cfg, col, &addrs)
				if ctx.Err() != nil {
					return
				}

				if first {
					if err != nil {
						col.connectErrors.Add(1)
						// Never established: the retry that follows is not a
						// proxy-generated disconnect.
						tracker.dead = true
					} else {
						col.established.Add(1)
					}

					first = false
					continue
				}

				tracker.observe(col, newConn, err)
			}
		})
	}

	wg.Wait()
}

func main() {
	var cfg config
	flag.StringVar(&cfg.mode, "mode", "hold", "hold or load")
	flag.StringVar(&cfg.url, "url", "", "target URL, e.g. http://10.89.0.5:30089/")
	flag.StringVar(&cfg.host, "host", "", "Host header / TLS SNI override")
	flag.IntVar(&cfg.connections, "connections", 100, "number of concurrent downstream connections")
	flag.DurationVar(&cfg.duration, "duration", 60*time.Second, "measurement duration after ramp-up")
	flag.DurationVar(&cfg.interval, "interval", 5*time.Second, "hold mode: per-connection request interval")
	flag.DurationVar(&cfg.timeout, "timeout", 30*time.Second, "per-request timeout")
	flag.BoolVar(&cfg.insecure, "insecure", false, "skip TLS verification")
	flag.IntVar(&cfg.rampWorkers, "ramp", 500, "hold mode: max concurrent connection attempts during ramp-up")
	flag.Parse()

	if cfg.url == "" {
		fmt.Fprintln(os.Stderr, "loadgen: -url is required")
		os.Exit(2)
	}

	col := newCollector()
	col.start = time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.duration)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		switch cfg.mode {
		case "hold":
			runHold(ctx, cfg, col)

		case "load":
			runLoad(ctx, cfg, col)

		default:
			fmt.Fprintf(os.Stderr, "loadgen: unknown mode %q\n", cfg.mode)
			os.Exit(2)
		}
	}()

	// Progress heartbeat on stderr so long runs are observable.
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			out := col.report(cfg, time.Since(col.start))
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")

			if err := enc.Encode(out); err != nil {
				fmt.Fprintf(os.Stderr, "loadgen: %v\n", err)
				os.Exit(1)
			}
			return

		case <-ticker.C:
			fmt.Fprintf(
				os.Stderr,
				"loadgen: established=%d requests=%d errors=%d disconnects=%d\n",
				col.established.Load(),
				col.requests.Load(),
				col.requestErrors.Load(),
				col.disconnects.Load(),
			)
		}
	}
}
