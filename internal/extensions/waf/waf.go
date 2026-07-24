// Package waf implements the `waf.hcl` extension documents and the Coraza
// engine enforcing them (docs/spec/extensions.md Web application
// firewall). Documents concatenate in filter list order into one SecLang
// program; the OWASP Core Rule Set and the Coraza recommended
// configuration are embedded and reachable only through `@`-includes.
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
// `Include` of filesystem paths is rejected here: extension ConfigMaps
// MUST NOT read the pod filesystem (docs/spec/extensions.md).
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

	for line := range strings.Lines(raw.WAF.Directives) {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "Include") {
			continue
		}

		target := strings.Trim(fields[1], `"'`)
		if !strings.HasPrefix(target, "@") {
			return nil, fmt.Errorf(
				"Include %q: only embedded @-includes are allowed", target)
		}
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
