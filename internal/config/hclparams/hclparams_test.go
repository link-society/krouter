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
