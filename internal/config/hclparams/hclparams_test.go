package hclparams

import (
	"testing"

	"strings"
)

func TestParseInfraDefaults(t *testing.T) {
	params, err := ParseInfra("version = 1\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if params.Service.Type != "NodePort" {
		t.Errorf("expected default type NodePort, got %q", params.Service.Type)
	}

	if params.Service.ExternalTrafficPolicy != "Local" {
		t.Errorf("expected default policy Local, got %q", params.Service.ExternalTrafficPolicy)
	}
}

func TestParseInfraFull(t *testing.T) {
	src := `
version = 1

service {
  type                    = "NodePort"
  external_traffic_policy = "Local"

  annotations = {
    "example.com/setting" = "value"
  }

  node_ports = {
    "http" = 30080
  }
}
`

	params, err := ParseInfra(src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if params.Service.NodePorts["http"] != 30080 {
		t.Errorf("expected node port 30080, got %d", params.Service.NodePorts["http"])
	}

	if params.Service.Annotations["example.com/setting"] != "value" {
		t.Errorf("annotations not parsed: %v", params.Service.Annotations)
	}
}

func TestParseInfraRejectsUnknownFields(t *testing.T) {
	// docs/spec/parameters.md: unknown or invalid fields are rejected.
	_, err := ParseInfra("version = 1\nbogus_field = \"boom\"\n")
	if err == nil {
		t.Fatal("expected an error for unknown field")
	}
}

func TestParseInfraRejectsUnknownVersion(t *testing.T) {
	_, err := ParseInfra("version = 2\n")
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("expected a version error, got %v", err)
	}
}

func TestParseInfraRejectsInvalidType(t *testing.T) {
	_, err := ParseInfra("version = 1\nservice {\n  type = \"ExternalName\"\n}\n")
	if err == nil {
		t.Fatal("expected an error for invalid service type")
	}
}

func TestParseInfraTrustsNobodyByDefault(t *testing.T) {
	// docs/spec/security.md Client IP trust: no peer is trusted unless the
	// operator says so.
	params, err := ParseInfra("version = 1\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(params.ClientIP.TrustedProxies) != 0 {
		t.Errorf("expected no trusted proxies, got %v", params.ClientIP.TrustedProxies)
	}
}

func TestParseInfraTrustedProxies(t *testing.T) {
	src := `
version = 1

client_ip {
  trusted_proxies = ["10.0.0.0/8", "2001:db8::/32"]
}
`

	params, err := ParseInfra(src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(params.ClientIP.TrustedProxies) != 2 ||
		params.ClientIP.TrustedProxies[0] != "10.0.0.0/8" ||
		params.ClientIP.TrustedProxies[1] != "2001:db8::/32" {
		t.Errorf("unexpected trusted proxies: %v", params.ClientIP.TrustedProxies)
	}
}

func TestParseInfraRejectsInvalidTrustedProxies(t *testing.T) {
	// docs/spec/parameters.md: a malformed prefix is an invalid parameter,
	// never a silently ignored entry.
	cases := map[string]string{
		"bare address": "10.0.0.1",
		"garbage":      "trust-me",
		"bad mask":     "10.0.0.0/33",
	}

	for name, cidr := range cases {
		src := "version = 1\nclient_ip {\n  trusted_proxies = [\"" + cidr + "\"]\n}\n"
		if _, err := ParseInfra(src); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestParseInfraProxyProtocol(t *testing.T) {
	src := `
version = 1

client_ip {
  trusted_proxies = ["10.0.0.0/8"]

  proxy_protocol {
    listeners = ["http", "https"]
  }
}
`

	params, err := ParseInfra(src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(params.ClientIP.ProxyProtocol.Listeners) != 2 ||
		params.ClientIP.ProxyProtocol.Listeners[0] != "http" {
		t.Errorf("unexpected listeners: %v", params.ClientIP.ProxyProtocol.Listeners)
	}
}

func TestParseInfraExpectsNoPreambleByDefault(t *testing.T) {
	params, err := ParseInfra("version = 1\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(params.ClientIP.ProxyProtocol.Listeners) != 0 {
		t.Errorf("expected no listener, got %v", params.ClientIP.ProxyProtocol.Listeners)
	}
}

func TestParseInfraRejectsProxyProtocolWithoutTrust(t *testing.T) {
	// docs/spec/parameters.md: no peer would be allowed to send the
	// preamble those listeners require.
	src := "version = 1\nclient_ip {\n  proxy_protocol {\n    listeners = [\"http\"]\n  }\n}\n"
	if _, err := ParseInfra(src); err == nil {
		t.Fatal("expected an error")
	}
}

func TestParseInfraRejectsEmptyProxyProtocolListener(t *testing.T) {
	src := "version = 1\nclient_ip {\n  trusted_proxies = [\"10.0.0.0/8\"]\n" +
		"  proxy_protocol {\n    listeners = [\"\"]\n  }\n}\n"
	if _, err := ParseInfra(src); err == nil {
		t.Fatal("expected an error")
	}
}

func TestParseClassDefaults(t *testing.T) {
	params, err := ParseClass("version = 1\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if params.LoadBalancing.Algorithm != "round_robin" {
		t.Errorf("expected round_robin default, got %q", params.LoadBalancing.Algorithm)
	}
}

func TestParseClassRejectsUnknownAlgorithm(t *testing.T) {
	_, err := ParseClass("version = 1\nload_balancing {\n  algorithm = \"random\"\n}\n")
	if err == nil {
		t.Fatal("expected an error for unsupported algorithm")
	}
}
