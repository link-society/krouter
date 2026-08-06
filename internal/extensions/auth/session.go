package auth

import (
	"fmt"

	"strings"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"net/http"

	"time"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// Session is the decrypted content of one session cookie: everything
// later requests need, and nothing else (docs/spec/authentication.md
// Stateless sessions). Claims are pruned to what authorization rules
// and identity headers consume.
type Session struct {
	Provider string              `json:"p"`
	User     string              `json:"u,omitempty"`
	Email    string              `json:"e,omitempty"`
	Groups   []string            `json:"g,omitempty"`
	Claims   map[string][]string `json:"c,omitempty"`

	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`

	// TokenExpiresAt bounds the OIDC tokens inside the session: past it,
	// a refresh (or a new login) is required even though the session
	// itself is still within its lifetime.
	TokenExpiresAt int64 `json:"texp,omitempty"`
	// RefreshToken is carried encrypted for transparent OIDC refresh.
	RefreshToken string `json:"rt,omitempty"`

	// SAML logout references (docs/spec/authentication.md Logout).
	NameID       string `json:"nid,omitempty"`
	SessionIndex string `json:"sidx,omitempty"`
}

// State is the in-flight login state cookie: extension identity, return
// URL, the login form's anti-forgery token, and the flow's anti-forgery
// material (docs/spec/authentication.md In-flight login state).
type State struct {
	Extension string `json:"ext"`
	ReturnURL string `json:"rd,omitempty"`
	FormToken string `json:"tok,omitempty"`

	OIDCState    string `json:"os,omitempty"`
	OIDCNonce    string `json:"on,omitempty"`
	OIDCVerifier string `json:"ov,omitempty"`

	SAMLRequestID string `json:"sid,omitempty"`

	ExpiresAt int64 `json:"exp"`
}

// StateLifetime bounds in-flight login flows
// (docs/spec/authentication.md In-flight login state).
const StateLifetime = 10 * time.Minute

// cookieChunkSize keeps each chunk under common per-cookie limits;
// maxCookieChunks bounds the total session budget.
const (
	cookieChunkSize = 3500
	maxCookieChunks = 4
)

// Codec seals and opens the session and state cookies of one extension
// with authenticated encryption keyed from `session.secret`. Cookie
// names derive from the extension identity: stable across Secret edits,
// distinct between extensions.
type Codec struct {
	aead     cipher.AEAD
	identity string
	lifetime time.Duration
}

// NewCodec derives the AEAD key from the session secret
// (docs/spec/authentication.md Stateless sessions).
func NewCodec(identity string, session *compiled.AuthSession) (*Codec, error) {
	key := sha256.Sum256([]byte(session.Secret))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &Codec{
		aead:     aead,
		identity: identity,
		lifetime: time.Duration(session.LifetimeMillis) * time.Millisecond,
	}, nil
}

func (c *Codec) Lifetime() time.Duration { return c.lifetime }

// SessionCookie is the base name of the extension's session cookie;
// chunks append `-<n>`.
func (c *Codec) SessionCookie() string {
	return "krouter_auth_" + cookieSuffix(c.identity)
}

// StateCookie is the name of the extension's in-flight state cookie.
func (c *Codec) StateCookie() string {
	return "krouter_state_" + cookieSuffix(c.identity)
}

func cookieSuffix(identity string) string {
	if len(identity) > 8 {
		return identity[:8]
	}

	return identity
}

// --------------------------------------------------------------- sealing --

func (c *Codec) seal(context string, payload any) (string, error) {
	plain, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	sealed := c.aead.Seal(nonce, nonce, plain, []byte(context))

	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (c *Codec) open(context, value string, target any) error {
	sealed, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return err
	}

	if len(sealed) < c.aead.NonceSize() {
		return fmt.Errorf("sealed value too short")
	}

	nonce, box := sealed[:c.aead.NonceSize()], sealed[c.aead.NonceSize():]

	plain, err := c.aead.Open(nil, nonce, box, []byte(context))
	if err != nil {
		return err
	}

	return json.Unmarshal(plain, target)
}

// --------------------------------------------------------------- session --

// SealSession writes the session cookie chunks onto the response. An
// identity exceeding the bounded cookie budget fails: a truncated
// session MUST NOT be produced (docs/spec/authentication.md).
func (c *Codec) SealSession(w http.ResponseWriter, r *http.Request, session *Session) error {
	value, err := c.seal("session", session)
	if err != nil {
		return err
	}

	if len(value) > cookieChunkSize*maxCookieChunks {
		return fmt.Errorf(
			"session exceeds the cookie budget (%d bytes sealed)", len(value))
	}

	chunks := chunk(value, cookieChunkSize)
	for index, part := range chunks {
		http.SetCookie(w, c.cookie(r, c.chunkName(index), part, c.lifetime))
	}

	// Drop stale higher-numbered chunks from a previous, larger session.
	for index := len(chunks); index < maxCookieChunks; index++ {
		if _, err := r.Cookie(c.chunkName(index)); err == nil {
			http.SetCookie(w, c.expiredCookie(r, c.chunkName(index)))
		}
	}

	return nil
}

// OpenSession returns the request's session, or nil when there is none:
// a missing, tampered, undecryptable, or expired cookie is treated as
// no session, never as an error (docs/spec/authentication.md).
func (c *Codec) OpenSession(r *http.Request) *Session {
	var parts []string
	for index := 0; index < maxCookieChunks; index++ {
		cookie, err := r.Cookie(c.chunkName(index))
		if err != nil {
			break
		}

		parts = append(parts, cookie.Value)
	}

	if len(parts) == 0 {
		return nil
	}

	session := &Session{}
	if err := c.open("session", strings.Join(parts, ""), session); err != nil {
		return nil
	}

	if time.Now().Unix() >= session.ExpiresAt {
		return nil
	}

	return session
}

// ClearSession expires every session cookie chunk on the browser
// performing the request (docs/spec/authentication.md Logout).
func (c *Codec) ClearSession(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, c.expiredCookie(r, c.chunkName(0)))

	for index := 1; index < maxCookieChunks; index++ {
		if _, err := r.Cookie(c.chunkName(index)); err == nil {
			http.SetCookie(w, c.expiredCookie(r, c.chunkName(index)))
		}
	}
}

func (c *Codec) chunkName(index int) string {
	if index == 0 {
		return c.SessionCookie()
	}

	return fmt.Sprintf("%s-%d", c.SessionCookie(), index)
}

// ----------------------------------------------------------------- state --

// SealState writes the in-flight state cookie. The SAML POST callback
// arrives cross-site, so its state cookie needs SameSite=None
// (docs/spec/authentication.md In-flight login state).
func (c *Codec) SealState(
	w http.ResponseWriter,
	r *http.Request,
	state *State,
	crossSite bool,
) error {
	state.ExpiresAt = time.Now().Add(StateLifetime).Unix()

	value, err := c.seal("state", state)
	if err != nil {
		return err
	}

	cookie := c.cookie(r, c.StateCookie(), value, StateLifetime)
	if crossSite && r.TLS != nil {
		// SameSite=None requires Secure: on plain HTTP listeners the
		// cookie stays Lax (docs/spec/authentication.md Stateless
		// sessions), matching the Secure-on-HTTPS rule.
		cookie.SameSite = http.SameSiteNoneMode
		cookie.Secure = true
	}

	http.SetCookie(w, cookie)

	return nil
}

// OpenState returns the in-flight state, or nil when there is none;
// flows older than the validity window are rejected.
func (c *Codec) OpenState(r *http.Request) *State {
	cookie, err := r.Cookie(c.StateCookie())
	if err != nil {
		return nil
	}

	state := &State{}
	if err := c.open("state", cookie.Value, state); err != nil {
		return nil
	}

	if time.Now().Unix() >= state.ExpiresAt {
		return nil
	}

	return state
}

// ClearState consumes the state cookie: callbacks verify it exactly
// once (docs/spec/authentication.md).
func (c *Codec) ClearState(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, c.expiredCookie(r, c.StateCookie()))
}

// --------------------------------------------------------------- cookies --

func (c *Codec) cookie(
	r *http.Request,
	name string,
	value string,
	maxAge time.Duration,
) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	}
}

func (c *Codec) expiredCookie(r *http.Request, name string) *http.Cookie {
	cookie := c.cookie(r, name, "", 0)
	cookie.MaxAge = -1

	return cookie
}

func chunk(value string, size int) []string {
	var parts []string
	for len(value) > size {
		parts = append(parts, value[:size])
		value = value[size:]
	}

	return append(parts, value)
}
