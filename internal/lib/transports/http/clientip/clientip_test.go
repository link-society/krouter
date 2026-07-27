package clientip

import (
	"strings"

	"net/http"

	"testing"
)

// forwarded builds a request header carrying one X-Forwarded-For entry per
// argument, as separate header lines: repeated headers form one chain.
func forwarded(values ...string) http.Header {
	header := http.Header{}
	for _, value := range values {
		header.Add("X-Forwarded-For", value)
	}

	return header
}

func mustNew(t *testing.T, cidrs ...string) *Trust {
	t.Helper()

	trust, err := New(cidrs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return trust
}

// --------------------------------------------------------------- parsing --

func TestNewWithoutPrefixesTrustsNobody(t *testing.T) {
	trust, err := New(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if trust != nil {
		t.Fatalf("expected no trust, got %+v", trust)
	}
}

func TestNewRejectsInvalidPrefixes(t *testing.T) {
	// docs/spec/parameters.md: every entry is a valid IPv4 or IPv6 prefix.
	cases := map[string]string{
		"bare address": "10.0.0.1",
		"empty":        "",
		"garbage":      "not-a-cidr",
		"bad mask":     "10.0.0.0/33",
	}

	for name, cidr := range cases {
		if _, err := New([]string{cidr}); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestNewIgnoresHostBits(t *testing.T) {
	trust := mustNew(t, "10.1.2.3/8")

	if ip, _ := trust.Resolve("10.9.9.9:1234", forwarded("203.0.113.7")); ip != "203.0.113.7" {
		t.Errorf("expected the prefix to cover 10.9.9.9, got %q", ip)
	}
}

// ------------------------------------------------------------ resolution --

func TestResolveWithoutTrustReturnsPeer(t *testing.T) {
	var trust *Trust

	ip, trusted := trust.Resolve("10.0.0.9:5555", forwarded("203.0.113.7"))
	if ip != "10.0.0.9" || trusted {
		t.Errorf("expected the peer address, got %q (trusted=%v)", ip, trusted)
	}
}

func TestResolveUntrustedPeerIgnoresChain(t *testing.T) {
	// docs/spec/traffic.md: a peer outside trusted_proxies chooses nothing.
	trust := mustNew(t, "192.168.0.0/16")

	ip, trusted := trust.Resolve("10.0.0.9:5555", forwarded("203.0.113.7"))
	if ip != "10.0.0.9" || trusted {
		t.Errorf("expected the peer address, got %q (trusted=%v)", ip, trusted)
	}
}

func TestResolveTrustedPeerReadsChain(t *testing.T) {
	trust := mustNew(t, "10.0.0.0/8")

	ip, trusted := trust.Resolve("10.0.0.9:5555", forwarded("203.0.113.7"))
	if ip != "203.0.113.7" || !trusted {
		t.Errorf("expected the forwarded client, got %q (trusted=%v)", ip, trusted)
	}
}

func TestResolveTrustedPeerWithoutChainReturnsPeer(t *testing.T) {
	trust := mustNew(t, "10.0.0.0/8")

	ip, trusted := trust.Resolve("10.0.0.9:5555", http.Header{})
	if ip != "10.0.0.9" || !trusted {
		t.Errorf("expected the peer address, got %q (trusted=%v)", ip, trusted)
	}
}

func TestResolveStopsAtFirstUntrustedAddress(t *testing.T) {
	// Two proxies in front: the rightmost entries are their own addresses,
	// the first untrusted one going left is the client.
	trust := mustNew(t, "10.0.0.0/8")

	ip, _ := trust.Resolve("10.0.0.9:5555", forwarded("203.0.113.7, 10.0.0.8"))
	if ip != "203.0.113.7" {
		t.Errorf("expected the first untrusted address, got %q", ip)
	}
}

func TestResolveSpoofedChainCannotReachPastTrustedHops(t *testing.T) {
	// docs/spec/security.md: the client controls the left of the chain, so
	// entries beyond the first untrusted one are never consulted.
	trust := mustNew(t, "10.0.0.0/8")

	ip, _ := trust.Resolve("10.0.0.9:5555", forwarded("10.0.0.1, 203.0.113.7, 10.0.0.8"))
	if ip != "203.0.113.7" {
		t.Errorf("expected the first untrusted address, got %q", ip)
	}
}

func TestResolveFullyTrustedChainUsesLeftmost(t *testing.T) {
	trust := mustNew(t, "10.0.0.0/8")

	ip, _ := trust.Resolve("10.0.0.9:5555", forwarded("10.0.0.1, 10.0.0.2"))
	if ip != "10.0.0.1" {
		t.Errorf("expected the leftmost address, got %q", ip)
	}
}

func TestResolveMalformedEntryKeepsNearestTrusted(t *testing.T) {
	// The walk never reports a value no trusted hop vouched for
	// (docs/spec/traffic.md Forwarding headers).
	trust := mustNew(t, "10.0.0.0/8")

	ip, _ := trust.Resolve("10.0.0.9:5555", forwarded("203.0.113.7, unknown, 10.0.0.8"))
	if ip != "10.0.0.8" {
		t.Errorf("expected the nearest trusted address, got %q", ip)
	}
}

func TestResolveJoinsRepeatedHeaders(t *testing.T) {
	// Repeated header lines are one chain, in order.
	trust := mustNew(t, "10.0.0.0/8")

	ip, _ := trust.Resolve("10.0.0.9:5555", forwarded("203.0.113.7", "10.0.0.8"))
	if ip != "203.0.113.7" {
		t.Errorf("expected the forwarded client, got %q", ip)
	}
}

func TestResolveBoundsTheChainWalk(t *testing.T) {
	// A client can pad the chain with trusted-looking entries; the walk is
	// bounded, so the padding costs a bounded amount of work and never
	// reaches the attacker-chosen address (docs/spec/traffic.md).
	trust := mustNew(t, "10.0.0.0/8")

	entries := []string{"203.0.113.7"}
	for range MaxHops + 8 {
		entries = append(entries, "10.0.0.1")
	}

	ip, _ := trust.Resolve("10.0.0.9:5555", forwarded(strings.Join(entries, ", ")))
	if ip != "10.0.0.1" {
		t.Errorf("expected the walk to stop inside the padding, got %q", ip)
	}
}

func TestResolveIPv6(t *testing.T) {
	trust := mustNew(t, "2001:db8::/32")

	ip, trusted := trust.Resolve("[2001:db8::1]:5555", forwarded("2001:db8:ffff::9, 2001:db8::2"))
	if ip != "2001:db8:ffff::9" || !trusted {
		t.Errorf("expected the forwarded client, got %q (trusted=%v)", ip, trusted)
	}
}

func TestResolveUnmapsIPv4MappedAddresses(t *testing.T) {
	// A dual-stack listener reports IPv4 peers in their mapped form; the
	// configured IPv4 prefix must still cover them.
	trust := mustNew(t, "10.0.0.0/8")

	ip, trusted := trust.Resolve("[::ffff:10.0.0.9]:5555", forwarded("203.0.113.7"))
	if ip != "203.0.113.7" || !trusted {
		t.Errorf("expected the forwarded client, got %q (trusted=%v)", ip, trusted)
	}
}

func TestResolveUnparseablePeerIsUntrusted(t *testing.T) {
	trust := mustNew(t, "0.0.0.0/0")

	ip, trusted := trust.Resolve("@", forwarded("203.0.113.7"))
	if ip != "@" || trusted {
		t.Errorf("expected the raw peer, got %q (trusted=%v)", ip, trusted)
	}
}
