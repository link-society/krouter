package compiled

import "testing"

func TestGenerationIDIsDeterministic(t *testing.T) {
	attachments := map[string][]byte{
		"uid-a": []byte(`{"a":1}`),
		"uid-b": []byte(`{"b":2}`),
	}

	first := GenerationID([]byte(`{"gw":1}`), attachments, "sum")
	second := GenerationID([]byte(`{"gw":1}`), attachments, "sum")

	if first != second {
		t.Fatalf("generation must be a pure function: %s != %s", first, second)
	}

	if len(first) != 12 {
		t.Fatalf("unexpected generation id length: %q", first)
	}
}

func TestGenerationIDChangesWithContent(t *testing.T) {
	base := GenerationID([]byte(`{"gw":1}`), nil, "")

	changedGateway := GenerationID([]byte(`{"gw":2}`), nil, "")
	if changedGateway == base {
		t.Error("gateway payload change must change the generation")
	}

	changedRoutes := GenerationID([]byte(`{"gw":1}`), map[string][]byte{"r": []byte(`{}`)}, "")
	if changedRoutes == base {
		t.Error("attachment change must change the generation")
	}

	changedSecret := GenerationID([]byte(`{"gw":1}`), nil, "other")
	if changedSecret == base {
		t.Error("TLS material change must change the generation (docs/spec/security.md)")
	}
}

func TestChecksumSecretIsOrderIndependent(t *testing.T) {
	first := ChecksumSecret(map[string][]byte{"a": []byte("1"), "b": []byte("2")})
	second := ChecksumSecret(map[string][]byte{"b": []byte("2"), "a": []byte("1")})

	if first != second {
		t.Fatal("secret checksum must not depend on map iteration order")
	}
}
