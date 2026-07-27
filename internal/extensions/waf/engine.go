package waf

import (
	"fmt"

	"bytes"
	"io"
	"io/fs"

	"os"
	"path/filepath"
	"strings"

	"net"
	"net/http"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// Engine wraps one compiled Coraza ruleset enforcing a rule's
// concatenated directives (docs/spec/extensions.md Web application
// firewall). Transactions are per request; the engine itself is
// immutable and safe for concurrent use.
type Engine struct {
	waf coraza.WAF
}

// NewEngine builds the Coraza engine from a concatenated SecLang program.
// `@`-includes resolve against the embedded Core Rule Set; any other
// `Include` path resolves against the pod filesystem, so operators can
// bring rule files through image extension or volume mounts
// (docs/spec/extensions.md Web application firewall).
func NewEngine(directives string) (*Engine, error) {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithRootFS(rulesFS{}).
			WithDirectives(directives),
	)
	if err != nil {
		return nil, err
	}

	return &Engine{waf: waf}, nil
}

// rulesFS resolves `Include` paths: the `@`-prefixed names come from the
// embedded Core Rule Set, everything else from the pod filesystem. Like
// Coraza's own OS-backed root, it deliberately deviates from strict io/fs
// path semantics to accept absolute paths.
type rulesFS struct{}

func (rulesFS) Open(name string) (fs.File, error) {
	if strings.HasPrefix(name, "@") {
		return coreruleset.FS.Open(name)
	}

	return os.Open(name)
}

func (rulesFS) ReadFile(name string) ([]byte, error) {
	if strings.HasPrefix(name, "@") {
		return fs.ReadFile(coreruleset.FS, name)
	}

	return os.ReadFile(name)
}

func (rulesFS) Glob(pattern string) ([]string, error) {
	if strings.HasPrefix(pattern, "@") {
		return fs.Glob(coreruleset.FS, pattern)
	}

	return filepath.Glob(pattern)
}

// Denial is one interruption produced by the request phases: the client
// receives Status and the backend never sees the request.
type Denial struct {
	Status int
	RuleID int
}

// Evaluate runs the request phases (docs/spec/extensions.md): the header
// phase always, the body phase only when headersOnly is false (upgrade
// handshakes forward the tunnel without inspection). The inspected body
// bytes are replayed onto r.Body so the backend receives the request
// unchanged.
//
// clientIP is the resolved client address (docs/spec/traffic.md
// Forwarding headers): rules keyed on the remote address inspect the
// client, not the proxy that carried the request.
func (e *Engine) Evaluate(r *http.Request, clientIP string, headersOnly bool) (*Denial, error) {
	tx := e.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	_, clientPort := hostPort(r.RemoteAddr)
	tx.ProcessConnection(clientIP, clientPort, "", 0)

	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
	tx.SetServerName(hostOnly(r.Host))

	tx.AddRequestHeader("Host", r.Host)
	for name, values := range r.Header {
		for _, value := range values {
			tx.AddRequestHeader(name, value)
		}
	}

	if interruption := tx.ProcessRequestHeaders(); interruption != nil {
		return denialFrom(interruption), nil
	}

	bodyBuffered := false

	if !headersOnly && r.Body != nil && tx.IsRequestBodyAccessible() {
		// The engine buffers the body up to its configured limits
		// (SecRequestBodyLimit and related directives) so the request
		// body phase can inspect it.
		interruption, _, err := tx.ReadRequestBodyFrom(r.Body)
		if err != nil {
			return nil, fmt.Errorf("reading request body: %w", err)
		}

		if interruption != nil {
			return denialFrom(interruption), nil
		}

		bodyBuffered = true
	}

	interruption, err := tx.ProcessRequestBody()
	if err != nil {
		return nil, fmt.Errorf("processing request body: %w", err)
	}

	if interruption != nil {
		return denialFrom(interruption), nil
	}

	if bodyBuffered {
		// Replay the inspected bytes onto r.Body so the backend receives
		// the request unchanged. The bytes are copied out of the engine
		// buffer before the deferred tx.Close frees it; anything past the
		// engine's body limit stays on the original body.
		buffered, err := tx.RequestBodyReader()
		if err != nil {
			return nil, fmt.Errorf("replaying request body: %w", err)
		}

		body, err := io.ReadAll(buffered)
		if err != nil {
			return nil, fmt.Errorf("buffering request body: %w", err)
		}

		r.Body = replayBody{
			Reader: io.MultiReader(bytes.NewReader(body), r.Body),
			closer: r.Body,
		}
	}

	return nil, nil
}

// replayBody streams the buffered body bytes then whatever the engine
// did not consume, closing the original body.
type replayBody struct {
	io.Reader
	closer io.Closer
}

func (b replayBody) Close() error { return b.closer.Close() }

func denialFrom(interruption *types.Interruption) *Denial {
	status := interruption.Status
	if status == 0 {
		// SecLang deny without an explicit status (docs/spec/extensions.md).
		status = http.StatusForbidden
	}

	return &Denial{Status: status, RuleID: interruption.RuleID}
}

func hostPort(remoteAddr string) (string, int) {
	host, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr, 0
	}

	var portNum int
	fmt.Sscanf(port, "%d", &portNum)

	return host, portNum
}

func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}

	return host
}
