// Package waf implements the `waf.hcl` extension documents and the Coraza
// engine enforcing them (docs/spec/extensions.md Web application
// firewall). Documents concatenate in filter list order into one SecLang
// program; the OWASP Core Rule Set and the Coraza recommended
// configuration are embedded and reachable through `@`-includes, while
// other `Include` paths read rule files from the pod filesystem.
package waf

import (
	"fmt"

	"strings"

	"github.com/hashicorp/hcl/v2/hclsimple"
)

// Document is one parsed waf.hcl: a SecLang directives fragment.
type Document struct {
	Directives string
}

type hclDocument struct {
	Version int       `hcl:"version"`
	WAF     *hclBlock `hcl:"waf,block"`
}

type hclBlock struct {
	Directives string `hcl:"directives"`
}

// Parse decodes one waf.hcl document (HCL native syntax, unknown or
// invalid fields rejected, docs/spec/parameters.md conventions).
// `Include` targets are not resolved here: the engine build validates
// them, embedded `@`-includes and pod-filesystem paths alike
// (docs/spec/extensions.md).
func Parse(src string) (*Document, error) {
	raw := &hclDocument{}
	if err := hclsimple.Decode("waf.hcl", []byte(src), nil, raw); err != nil {
		return nil, err
	}

	if raw.Version != 1 {
		return nil, fmt.Errorf("unsupported version %d", raw.Version)
	}

	if raw.WAF == nil {
		return nil, fmt.Errorf("missing waf block")
	}

	if strings.TrimSpace(raw.WAF.Directives) == "" {
		return nil, fmt.Errorf("empty directives")
	}

	return &Document{Directives: raw.WAF.Directives}, nil
}

// Concat folds the documents reaching a rule, in filter list order, into
// one SecLang program (docs/spec/extensions.md): later fragments MAY add
// rules and exclusions or override engine settings, per SecLang
// semantics.
func Concat(docs []*Document) string {
	fragments := make([]string, 0, len(docs))
	for _, doc := range docs {
		fragments = append(fragments, doc.Directives)
	}

	return strings.Join(fragments, "\n")
}
