package auth

import (
	"testing"

	"strings"

	"net/http"
	"net/http/httptest"

	"time"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

func testCodec(t *testing.T, identity string) *Codec {
	t.Helper()

	codec, err := NewCodec(identity, &compiled.AuthSession{
		Secret:         testSecret,
		LifetimeMillis: time.Hour.Milliseconds(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return codec
}

func withCookies(recorder *httptest.ResponseRecorder) *http.Request {
	r := httptest.NewRequest("GET", "/app", nil)
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.MaxAge >= 0 {
			r.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
		}
	}

	return r
}

func TestSessionRoundTrip(t *testing.T) {
	codec := testCodec(t, "0123456789ab")

	session := &Session{
		Provider:  "oidc",
		User:      "alice",
		Email:     "alice@example.com",
		Groups:    []string{"platform-team"},
		Claims:    map[string][]string{"dept": {"eng"}},
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}

	w := httptest.NewRecorder()
	if err := codec.SealSession(w, httptest.NewRequest("GET", "/", nil), session); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one cookie, got %d", len(cookies))
	}

	// docs/spec/authentication.md: HttpOnly, SameSite=Lax.
	if !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Errorf("unexpected cookie flags: %+v", cookies[0])
	}

	opened := codec.OpenSession(withCookies(w))
	if opened == nil {
		t.Fatal("expected a session")
	}

	if opened.User != "alice" || opened.Provider != "oidc" ||
		len(opened.Groups) != 1 || opened.Claims["dept"][0] != "eng" {
		t.Errorf("unexpected session: %+v", opened)
	}
}

func TestTamperedAndForeignSessionsAreNoSession(t *testing.T) {
	codec := testCodec(t, "0123456789ab")

	session := &Session{
		User:      "alice",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}

	w := httptest.NewRecorder()
	if err := codec.SealSession(w, httptest.NewRequest("GET", "/", nil), session); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Tampered value.
	r := withCookies(w)
	cookie, _ := r.Cookie(codec.SessionCookie())
	tampered := httptest.NewRequest("GET", "/app", nil)
	tampered.AddCookie(&http.Cookie{
		Name:  codec.SessionCookie(),
		Value: cookie.Value[:len(cookie.Value)-2] + "xx",
	})

	if codec.OpenSession(tampered) != nil {
		t.Error("a tampered cookie must be treated as no session")
	}

	// A session minted by another extension (different key) is rejected:
	// sessions are scoped to the extension that minted them.
	other, err := NewCodec("0123456789ab", &compiled.AuthSession{
		Secret:         strings.Repeat("x", 32),
		LifetimeMillis: time.Hour.Milliseconds(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if other.OpenSession(withCookies(w)) != nil {
		t.Error("a foreign session must be treated as no session")
	}
}

func TestExpiredSessionIsNoSession(t *testing.T) {
	codec := testCodec(t, "0123456789ab")

	w := httptest.NewRecorder()
	err := codec.SealSession(w, httptest.NewRequest("GET", "/", nil), &Session{
		User:      "alice",
		ExpiresAt: time.Now().Add(-time.Second).Unix(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if codec.OpenSession(withCookies(w)) != nil {
		t.Error("an expired session must be treated as no session")
	}
}

func TestSessionChunking(t *testing.T) {
	codec := testCodec(t, "0123456789ab")

	session := &Session{
		User:      "alice",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Claims: map[string][]string{
			"blob": {strings.Repeat("x", 2*cookieChunkSize)},
		},
	}

	w := httptest.NewRecorder()
	if err := codec.SealSession(w, httptest.NewRequest("GET", "/", nil), session); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(w.Result().Cookies()) < 2 {
		t.Fatalf("expected chunked cookies, got %d", len(w.Result().Cookies()))
	}

	opened := codec.OpenSession(withCookies(w))
	if opened == nil || opened.Claims["blob"][0] != session.Claims["blob"][0] {
		t.Error("chunked session must round-trip")
	}
}

func TestOversizedSessionFailsInsteadOfTruncating(t *testing.T) {
	codec := testCodec(t, "0123456789ab")

	session := &Session{
		User:      "alice",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Claims: map[string][]string{
			"blob": {strings.Repeat("x", (maxCookieChunks+1)*cookieChunkSize)},
		},
	}

	w := httptest.NewRecorder()
	if err := codec.SealSession(w, httptest.NewRequest("GET", "/", nil), session); err == nil {
		t.Error("an identity exceeding the cookie budget must fail")
	}
}

func TestStateRoundTripAndConsumption(t *testing.T) {
	codec := testCodec(t, "0123456789ab")

	w := httptest.NewRecorder()
	err := codec.SealState(w, httptest.NewRequest("GET", "/", nil), &State{
		Extension: "0123456789ab",
		ReturnURL: "/app?tab=1",
		OIDCState: "s1",
	}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	opened := codec.OpenState(withCookies(w))
	if opened == nil || opened.ReturnURL != "/app?tab=1" || opened.OIDCState != "s1" {
		t.Fatalf("unexpected state: %+v", opened)
	}

	if opened.ExpiresAt > time.Now().Add(StateLifetime+time.Minute).Unix() {
		t.Error("state lifetime must be bounded")
	}
}

func TestCrossSiteStateCookie(t *testing.T) {
	// The SAML POST callback arrives cross-site
	// (docs/spec/authentication.md In-flight login state).
	codec := testCodec(t, "0123456789ab")

	w := httptest.NewRecorder()
	err := codec.SealState(w, httptest.NewRequest("GET", "/", nil), &State{
		Extension:     "0123456789ab",
		SAMLRequestID: "_r1",
	}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cookie := w.Result().Cookies()[0]
	if cookie.SameSite != http.SameSiteNoneMode || !cookie.Secure {
		t.Errorf("cross-site state must be SameSite=None; Secure: %+v", cookie)
	}
}
