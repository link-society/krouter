package auth

import (
	"testing"

	"strings"

	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"net/http"
	"net/http/httptest"

	"time"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

func b64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func mintRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()

	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	payload, _ := json.Marshal(claims)
	signingInput := b64url(header) + "." + b64url(payload)

	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return signingInput + "." + b64url(signature)
}

func jwksServer(t *testing.T, key *rsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()

	public := key.Public().(*rsa.PublicKey)
	document := map[string]any{
		"keys": []map[string]string{
			{
				"kty": "RSA",
				"kid": kid,
				"use": "sig",
				"alg": "RS256",
				"n":   b64url(public.N.Bytes()),
				"e":   b64url([]byte{1, 0, 1}),
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks" {
			http.NotFound(w, r)
			return
		}

		json.NewEncoder(w).Encode(document)
	}))
	t.Cleanup(server.Close)

	return server
}

func testClaims(issuer string) map[string]any {
	return map[string]any{
		"iss":    issuer,
		"aud":    "my-api",
		"sub":    "alice",
		"email":  "alice@example.com",
		"groups": []string{"platform-team"},
		"iat":    time.Now().Unix(),
		"exp":    time.Now().Add(5 * time.Minute).Unix(),
	}
}

func TestJWTValidateAcceptsAndCanonicalizes(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	server := jwksServer(t, key, "k1")

	validator := NewJWTValidator(&compiled.AuthJWT{
		Issuer:    "https://idp.example.com",
		Audiences: []string{"my-api"},
		JWKSURL:   server.URL + "/jwks",
	})

	claims := testClaims("https://idp.example.com")
	claims["admin"] = true
	claims["level"] = 42

	got, err := validator.Validate(mintRS256(t, key, "k1", claims))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got["sub"][0] != "alice" || got["groups"][0] != "platform-team" {
		t.Errorf("unexpected claims: %+v", got)
	}

	// Scalars compare in canonical string form
	// (docs/spec/authentication.md Authorization).
	if got["admin"][0] != "true" || got["level"][0] != "42" {
		t.Errorf("unexpected canonical scalars: %+v", got)
	}
}

func TestJWTValidateRejections(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	server := jwksServer(t, key, "k1")

	validator := NewJWTValidator(&compiled.AuthJWT{
		Issuer:    "https://idp.example.com",
		Audiences: []string{"my-api"},
		JWKSURL:   server.URL + "/jwks",
	})

	mint := func(mutate func(map[string]any)) string {
		claims := testClaims("https://idp.example.com")
		mutate(claims)

		return mintRS256(t, key, "k1", claims)
	}

	cases := map[string]string{
		"expired": mint(func(c map[string]any) {
			c["exp"] = time.Now().Add(-time.Hour).Unix()
		}),
		"not yet valid": mint(func(c map[string]any) {
			c["nbf"] = time.Now().Add(time.Hour).Unix()
		}),
		"wrong audience": mint(func(c map[string]any) { c["aud"] = "other" }),
		"wrong issuer":   mint(func(c map[string]any) { c["iss"] = "https://evil" }),
		"garbage":        "not.a.token",
	}

	// Wrong signing key.
	imposter, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases["wrong key"] = mintRS256(t, imposter, "k1", testClaims("https://idp.example.com"))

	// `none` algorithm.
	header, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	payload, _ := json.Marshal(testClaims("https://idp.example.com"))
	cases["none algorithm"] = b64url(header) + "." + b64url(payload) + "."

	// Symmetric algorithm.
	hsHeader, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	hsInput := b64url(hsHeader) + "." + b64url(payload)
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(hsInput))
	cases["symmetric algorithm"] = hsInput + "." + b64url(mac.Sum(nil))

	for name, token := range cases {
		_, err := validator.Validate(token)
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}

		if !strings.Contains(err.Error(), ErrUnauthenticated.Error()) {
			t.Errorf("%s: expected an unauthenticated error, got %v", name, err)
		}
	}
}

func TestJWTUnreachableJWKSFailsClosed(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	server.Close()

	validator := NewJWTValidator(&compiled.AuthJWT{
		Issuer:    "https://idp.example.com",
		Audiences: []string{"my-api"},
		JWKSURL:   server.URL + "/jwks",
	})

	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	_, err := validator.Validate(mintRS256(t, key, "k1", testClaims("https://idp.example.com")))
	if err == nil || !strings.Contains(err.Error(), ErrUnavailable.Error()) {
		t.Errorf("expected an unavailable error, got %v", err)
	}
}
