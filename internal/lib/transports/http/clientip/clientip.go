// Package clientip resolves the client IP of a request from the
// downstream connection and, for peers the Gateway trusts, the
// X-Forwarded-For chain they present (docs/spec/traffic.md Forwarding
// headers). Trusting nothing is the default: an unconfigured Gateway
// always reports the peer (docs/spec/security.md Client IP trust).
package clientip

import (
	"fmt"

	"strings"

	"net"
	"net/http"
	"net/netip"
)

// MaxHops bounds the chain walk. A client controls the left of the chain
// and can pad it, so the work one request can buy is bounded; the spec
// requires at least 16 (docs/spec/traffic.md Forwarding headers).
const MaxHops = 32

const forwardedForHeader = "X-Forwarded-For"

// Trust is the set of networks whose forwarded headers are honored. A nil
// Trust trusts no peer.
type Trust struct {
	prefixes []netip.Prefix
}

// New parses the Gateway's trusted_proxies parameter
// (docs/spec/parameters.md). An empty list yields a nil Trust: every peer
// is then treated as the client itself.
func New(cidrs []string) (*Trust, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}

	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy %q: %w", cidr, err)
		}

		// Host bits carry no meaning here; comparing masked prefixes keeps
		// 10.1.2.3/8 behaving like the 10.0.0.0/8 the operator meant.
		prefixes = append(prefixes, prefix.Masked())
	}

	return &Trust{prefixes: prefixes}, nil
}

// Resolve reports the client IP of a request and whether the peer that
// carried it is a trusted proxy (docs/spec/traffic.md Forwarding
// headers). The caller uses the second value to decide whether the
// forwarded headers it received may reach the backend unchanged.
//
// The chain is walked from right to left and stops at the first address
// no trusted hop vouched for, so a spoofed prefix can never choose the
// reported address.
func (t *Trust) Resolve(remoteAddr string, header http.Header) (string, bool) {
	host := hostOf(remoteAddr)

	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host, false
	}

	peer = peer.Unmap().WithZone("")

	if !t.contains(peer) {
		return peer.String(), false
	}

	resolved := peer

	for i, entry := range chain(header) {
		if i == MaxHops {
			break
		}

		addr, err := netip.ParseAddr(entry)
		if err != nil {
			// A malformed entry ends the walk: everything further left was
			// vouched for by nobody.
			break
		}

		addr = addr.Unmap().WithZone("")

		if !t.contains(addr) {
			return addr.String(), true
		}

		resolved = addr
	}

	// Either no chain, or every address in it is trusted: the leftmost
	// trusted address is the closest thing to a client this Gateway has.
	return resolved.String(), true
}

func (t *Trust) contains(addr netip.Addr) bool {
	if t == nil {
		return false
	}

	for _, prefix := range t.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}

// chain returns the X-Forwarded-For entries from right to left. Repeated
// header lines form one chain, in the order they were received.
func chain(header http.Header) []string {
	values := header.Values(forwardedForHeader)
	if len(values) == 0 {
		return nil
	}

	var entries []string
	for _, value := range values {
		for _, entry := range strings.Split(value, ",") {
			entries = append(entries, strings.TrimSpace(entry))
		}
	}

	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}

	return entries
}

// hostOf strips the port from a "host:port" peer address, leaving an
// address without one untouched.
func hostOf(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}

	return remoteAddr
}
