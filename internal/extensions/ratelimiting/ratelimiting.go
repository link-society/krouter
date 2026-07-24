// Package ratelimiting implements the `ratelimit.hcl` extension documents
// and the per-rule token buckets enforcing them (docs/spec/extensions.md
// Rate limiting). Documents are partial by design: they merge in filter
// list order, a later document overriding the attributes it sets.
package ratelimiting

import (
	"fmt"

	"strings"

	"time"

	"github.com/hashicorp/hcl/v2/hclsimple"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// Document is one parsed ratelimit.hcl. Every attribute is optional so
// documents compose; validation of the merged result happens in Merge.
type Document struct {
	Requests *int64
	Window   *time.Duration
	Burst    *int64
	Key      *string
	Status   *int32
}

type hclDocument struct {
	Version   int           `hcl:"version"`
	RateLimit *hclRateLimit `hcl:"rate_limit,block"`
}

type hclRateLimit struct {
	Requests *int64  `hcl:"requests,optional"`
	Window   *string `hcl:"window,optional"`
	Burst    *int64  `hcl:"burst,optional"`
	Key      *string `hcl:"key,optional"`
	Status   *int32  `hcl:"status,optional"`
}

// Parse decodes one ratelimit.hcl document (HCL native syntax, unknown or
// invalid fields rejected, docs/spec/parameters.md conventions). Attribute
// values are validated here; completeness is only checked after Merge.
func Parse(src string) (*Document, error) {
	raw := &hclDocument{}
	if err := hclsimple.Decode("ratelimit.hcl", []byte(src), nil, raw); err != nil {
		return nil, err
	}

	if raw.Version != 1 {
		return nil, fmt.Errorf("unsupported version %d", raw.Version)
	}

	if raw.RateLimit == nil {
		return nil, fmt.Errorf("missing rate_limit block")
	}

	doc := &Document{
		Requests: raw.RateLimit.Requests,
		Burst:    raw.RateLimit.Burst,
		Key:      raw.RateLimit.Key,
		Status:   raw.RateLimit.Status,
	}

	if doc.Requests != nil && *doc.Requests <= 0 {
		return nil, fmt.Errorf("requests must be > 0")
	}

	if raw.RateLimit.Window != nil {
		window, err := time.ParseDuration(*raw.RateLimit.Window)
		if err != nil || window <= 0 {
			return nil, fmt.Errorf("invalid window %q", *raw.RateLimit.Window)
		}

		doc.Window = &window
	}

	if doc.Burst != nil && *doc.Burst <= 0 {
		return nil, fmt.Errorf("burst must be > 0")
	}

	if doc.Key != nil {
		if *doc.Key != "client_ip" &&
			(!strings.HasPrefix(*doc.Key, "header:") || len(*doc.Key) <= len("header:")) {
			return nil, fmt.Errorf("invalid key %q", *doc.Key)
		}
	}

	if doc.Status != nil && (*doc.Status < 400 || *doc.Status > 599) {
		return nil, fmt.Errorf("status must be in 400-599")
	}

	return doc, nil
}

// Merge folds documents in filter list order into the compiled
// configuration (docs/spec/extensions.md Resolution and status): a later
// document overrides the attributes it sets and inherits the rest. The
// merged result MUST define at least requests and window.
func Merge(docs []*Document) (*compiled.RateLimit, error) {
	merged := Document{}

	for _, doc := range docs {
		if doc.Requests != nil {
			merged.Requests = doc.Requests
		}

		if doc.Window != nil {
			merged.Window = doc.Window
		}

		if doc.Burst != nil {
			merged.Burst = doc.Burst
		}

		if doc.Key != nil {
			merged.Key = doc.Key
		}

		if doc.Status != nil {
			merged.Status = doc.Status
		}
	}

	if merged.Requests == nil || merged.Window == nil {
		return nil, fmt.Errorf("merged configuration must define requests and window")
	}

	config := &compiled.RateLimit{
		Requests:     *merged.Requests,
		WindowMillis: merged.Window.Milliseconds(),
		Burst:        *merged.Requests,
		Key:          "client_ip",
		Status:       429,
	}

	if merged.Burst != nil {
		config.Burst = *merged.Burst
	}

	if merged.Key != nil {
		config.Key = *merged.Key
	}

	if merged.Status != nil {
		config.Status = *merged.Status
	}

	return config, nil
}
