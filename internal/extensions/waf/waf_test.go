package waf

import (
	"testing"

	"io"

	"strings"

	"net/http"
	"net/http/httptest"
)

// ------------------------------------------------------------- parsing --

func TestParseValidDocument(t *testing.T) {
	doc, err := Parse(`
version = 1

waf {
  directives = <<-EOT
    SecRuleEngine On
    Include @owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf
  EOT
}
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(doc.Directives, "SecRuleEngine On") {
		t.Errorf("unexpected directives: %q", doc.Directives)
	}
}

func TestParseRejectsInvalidDocuments(t *testing.T) {
	cases := map[string]string{
		"unsupported version": "version = 2\n\nwaf {\n  directives = \"SecRuleEngine On\"\n}\n",
		"missing block":       "version = 1\n",
		"empty directives":    "version = 1\n\nwaf {\n  directives = \"  \"\n}\n",
		"unknown field":       "version = 1\n\nwaf {\n  directives = \"x\"\n  bogus = 1\n}\n",
		// Extension ConfigMaps MUST NOT read the pod filesystem
		// (docs/spec/extensions.md).
		"filesystem include": "version = 1\n\nwaf {\n  directives = \"Include /etc/rules.conf\"\n}\n",
	}

	for name, src := range cases {
		if _, err := Parse(src); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestConcatKeepsFilterOrder(t *testing.T) {
	program := Concat([]*Document{
		{Directives: "SecRuleEngine On"},
		{Directives: `SecRule REQUEST_HEADERS:X-Attack "@streq yes" "id:911001,phase:1,deny"`},
	})

	if !strings.HasPrefix(program, "SecRuleEngine On\n") {
		t.Errorf("fragments must concatenate in order, got %q", program)
	}
}

// -------------------------------------------------------------- engine --

const headerRule = `
SecRuleEngine On
SecRule REQUEST_HEADERS:X-Attack "@streq yes" "id:911001,phase:1,deny,status:406"
SecRule ARGS_GET:q "@contains <script" "id:911002,phase:1,deny,status:403"
`

func TestEngineDeniesAndAllows(t *testing.T) {
	engine, err := NewEngine(headerRule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hostile := httptest.NewRequest(http.MethodGet, "/?q=<script>alert(1)</script>", nil)
	denial, err := engine.Evaluate(hostile, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if denial == nil || denial.Status != 403 || denial.RuleID != 911002 {
		t.Errorf("expected the query rule to deny with 403, got %+v", denial)
	}

	header := httptest.NewRequest(http.MethodGet, "/", nil)
	header.Header.Set("X-Attack", "yes")

	denial, err = engine.Evaluate(header, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The interruption status is honored (docs/spec/extensions.md).
	if denial == nil || denial.Status != 406 || denial.RuleID != 911001 {
		t.Errorf("expected the header rule to deny with 406, got %+v", denial)
	}

	clean := httptest.NewRequest(http.MethodGet, "/", nil)
	denial, err = engine.Evaluate(clean, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if denial != nil {
		t.Errorf("clean request must pass, got %+v", denial)
	}
}

func TestEngineHeadersOnlySkipsBodyPhase(t *testing.T) {
	engine, err := NewEngine(`
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_BODY "@contains attack" "id:911003,phase:2,deny,status:403"
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body := strings.NewReader("attack payload")
	r := httptest.NewRequest(http.MethodPost, "/", body)

	// gRPC rules and upgrade requests forward payloads without
	// inspection (docs/spec/extensions.md).
	denial, err := engine.Evaluate(r, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if denial != nil {
		t.Errorf("headers-only evaluation must skip the body phase, got %+v", denial)
	}
}

func TestEngineInspectsAndReplaysBody(t *testing.T) {
	engine, err := NewEngine(`
SecRuleEngine On
SecRequestBodyAccess On
SecAction "id:911000,phase:1,pass,nolog,ctl:forceRequestBodyVariable=On"
SecRule REQUEST_BODY "@contains attack" "id:911003,phase:2,deny,status:403"
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hostile := httptest.NewRequest(
		http.MethodPost, "/", strings.NewReader("an attack payload"))

	denial, err := engine.Evaluate(hostile, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if denial == nil || denial.RuleID != 911003 {
		t.Errorf("expected the body rule to deny, got %+v", denial)
	}

	clean := httptest.NewRequest(
		http.MethodPost, "/", strings.NewReader("a friendly payload"))

	denial, err = engine.Evaluate(clean, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if denial != nil {
		t.Fatalf("clean body must pass, got %+v", denial)
	}

	// The inspected bytes reach the backend unchanged.
	replayed, err := io.ReadAll(clean.Body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(replayed) != "a friendly payload" {
		t.Errorf("body must be replayed unchanged, got %q", replayed)
	}
}

func TestEngineBuildsTheEmbeddedCRS(t *testing.T) {
	// The full Core Rule Set builds from the embedded filesystem
	// (docs/spec/extensions.md Web application firewall).
	engine, err := NewEngine(`
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleEngine On
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hostile := httptest.NewRequest(
		http.MethodGet, "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil)

	denial, err := engine.Evaluate(hostile, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if denial == nil || denial.Status != 403 {
		t.Errorf("the CRS must block a canonical XSS probe, got %+v", denial)
	}

	clean := httptest.NewRequest(http.MethodGet, "/", nil)
	clean.Header.Set("User-Agent", "krouter-tests/1.0")
	clean.Header.Set("Accept", "application/json")

	denial, err = engine.Evaluate(clean, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if denial != nil {
		t.Errorf("a clean request must pass the CRS, got %+v", denial)
	}
}

func TestNewEngineRejectsInvalidDirectives(t *testing.T) {
	if _, err := NewEngine("SecBogusDirective definitely-not-seclang"); err == nil {
		t.Error("invalid directives must fail the engine build")
	}
}
