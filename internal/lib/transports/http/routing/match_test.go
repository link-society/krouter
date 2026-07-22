package routing

import "testing"

func TestHostnameMatches(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		want    bool
	}{
		{"", "anything.example.com", true},
		{"hello.example.com", "hello.example.com", true},
		{"hello.example.com", "other.example.com", false},
		{"*.example.com", "hello.example.com", true},
		{"*.example.com", "example.com", false},
		// A wildcard matches one or more labels (Gateway API Hostname
		// semantics, docs/spec/traffic.md).
		{"*.example.com", "a.b.example.com", true},
	}

	for _, tc := range cases {
		if got := hostnameMatches(tc.pattern, tc.host); got != tc.want {
			t.Errorf("hostnameMatches(%q, %q) = %v, want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}

func TestPickBucketWeightedDistribution(t *testing.T) {
	// docs/spec/traffic.md: Gateway API backend weights shape selection (9:1 here).
	heavy := &BackendTable{name: "heavy", weight: 9, valid: true}
	light := &BackendTable{name: "light", weight: 1, valid: true}
	backends := []*BackendTable{heavy, light}

	counts := map[string]int{}
	for counter := int64(0); counter < 50; counter++ {
		picked := pickBucket(counter, backends, 10)
		counts[picked.name]++
	}

	if counts["heavy"] != 45 || counts["light"] != 5 {
		t.Fatalf("expected 45/5 split, got %v", counts)
	}
}

func TestPickBucketIncludesInvalidBackends(t *testing.T) {
	// Invalid refs keep their traffic share and answer 500 (Gateway API).
	valid := &BackendTable{name: "ok", weight: 1, valid: true}
	invalid := &BackendTable{name: "broken", weight: 1, valid: false}

	seen := map[string]bool{}
	for counter := int64(0); counter < 4; counter++ {
		seen[pickBucket(counter, []*BackendTable{valid, invalid}, 2).name] = true
	}

	if !seen["ok"] || !seen["broken"] {
		t.Fatalf("both backends must receive their share, got %v", seen)
	}
}

func TestPickBucketEmpty(t *testing.T) {
	if pickBucket(0, nil, 0) != nil {
		t.Fatal("no backends must yield nil")
	}
}

func TestPathPrefixMatches(t *testing.T) {
	cases := []struct {
		prefix string
		path   string
		want   bool
	}{
		{"/", "/anything", true},
		{"/api", "/api", true},
		{"/api", "/api/v1", true},
		{"/api", "/apiary", false},
	}

	for _, tc := range cases {
		if got := pathPrefixMatches(tc.prefix, tc.path); got != tc.want {
			t.Errorf("pathPrefixMatches(%q, %q) = %v, want %v", tc.prefix, tc.path, got, tc.want)
		}
	}
}
