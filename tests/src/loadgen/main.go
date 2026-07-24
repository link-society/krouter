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
	"net/http"
	"net/http/httptrace"

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
	Second   int   `json:"second"`
	Requests int64 `json:"requests"`
	Errors   int64 `json:"errors"`
}

type latency struct {
	MeanMs float64 `json:"mean_ms"`
	P50Ms  float64 `json:"p50_ms"`
	P95Ms  float64 `json:"p95_ms"`
	P99Ms  float64 `json:"p99_ms"`
	MaxMs  float64 `json:"max_ms"`
}

type report struct {
	Mode            string   `json:"mode"`
	URL             string   `json:"url"`
	Connections     int      `json:"connections"`
	DurationSeconds float64  `json:"duration_seconds"`
	Established     int64    `json:"established"`
	ConnectErrors   int64    `json:"connect_errors"`
	Requests        int64    `json:"requests"`
	RequestErrors   int64    `json:"request_errors"`
	Non2xx          int64    `json:"non_2xx"`
	Disconnects     int64    `json:"disconnects"`
	BytesIn         int64    `json:"bytes_in"`
	RequestsPerSec  float64  `json:"requests_per_sec"`
	Latency         latency  `json:"latency"`
	Timeline        []second `json:"timeline"`
}

type collector struct {
	established   atomic.Int64
	connectErrors atomic.Int64
	requests      atomic.Int64
	requestErrors atomic.Int64
	non2xx        atomic.Int64
	disconnects   atomic.Int64
	bytesIn       atomic.Int64

	start time.Time

	mu        sync.Mutex
	latencies []time.Duration
	timeline  map[int]*second
}

func newCollector() *collector {
	return &collector{timeline: map[int]*second{}}
}

func (c *collector) record(d time.Duration, err bool) {
	sec := int(time.Since(c.start).Seconds())
	c.mu.Lock()
	defer c.mu.Unlock()

	cell, ok := c.timeline[sec]
	if !ok {
		cell = &second{Second: sec}
		c.timeline[sec] = cell
	}

	cell.Requests++

	if err {
		cell.Errors++
	} else {
		c.latencies = append(c.latencies, d)
	}
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
		BytesIn:         c.bytesIn.Load(),
		RequestsPerSec:  float64(c.requests.Load()) / elapsed.Seconds(),
		Latency: latency{
			MeanMs: mean,
			P50Ms:  pct(0.50),
			P95Ms:  pct(0.95),
			P99Ms:  pct(0.99),
			MaxMs:  pct(1.0),
		},
		Timeline: timeline,
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
		}
		t.dead = true

		return
	}

	if newConn && !t.dead {
		col.disconnects.Add(1)
	}
	t.dead = false
}

// newClient builds an HTTP client owning exactly one TCP connection, so that
// N clients == N downstream connections and transparent reconnects are
// observable per connection.
func newClient(cfg config) *http.Client {
	transport := &http.Transport{
		MaxConnsPerHost:     1,
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     0, // never expire idle connections locally
		DisableCompression:  true,
	}

	if cfg.insecure {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, // test/benchmark tool: endpoint identity is not under test
			ServerName:         cfg.host,
		}
	}

	return &http.Client{Transport: transport, Timeout: cfg.timeout}
}

// doRequest issues one GET and reports whether the transport had to open a
// new TCP connection to serve it.
func doRequest(ctx context.Context, client *http.Client, cfg config, col *collector) (newConn bool, err error) {
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if !info.Reused {
				newConn = true
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
	n, _ := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

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
	var wg sync.WaitGroup
	// Ramp connections in batches to avoid a SYN stampede.
	sem := make(chan struct{}, cfg.rampWorkers)

	for i := 0; i < cfg.connections; i++ {
		wg.Go(func() {
			client := newClient(cfg)
			defer client.CloseIdleConnections()

			sem <- struct{}{}
			_, err := doRequest(ctx, client, cfg, col)
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
					newConn, err := doRequest(ctx, client, cfg, col)
					if ctx.Err() != nil {
						return
					}
					// A reconnect or a failed request on an established
					// connection means the proxy dropped us: exactly what
					// docs/spec/performance.md forbids during reloads.
					tracker.observe(col, newConn, err)
				}
			}
		})
	}

	wg.Wait()
}

func runLoad(ctx context.Context, cfg config, col *collector) {
	var wg sync.WaitGroup
	for i := 0; i < cfg.connections; i++ {
		wg.Go(func() {
			client := newClient(cfg)
			defer client.CloseIdleConnections()

			first := true
			var tracker disconnectTracker

			for ctx.Err() == nil {
				newConn, err := doRequest(ctx, client, cfg, col)
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
