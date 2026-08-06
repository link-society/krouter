package auth

import (
	"context"
	"fmt"

	"strings"

	"sync"

	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"io"

	"net/http"
	"net/url"

	"time"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// OIDCProvider drives the authorization code flow with PKCE, state and
// nonce against one OpenID Connect provider
// (docs/spec/authentication.md OpenID Connect). Endpoints and signing
// keys come from the issuer's discovery document, cached per data-plane
// pod.
type OIDCProvider struct {
	cfg    *compiled.AuthOIDC
	client *http.Client
	tokens *JWTValidator

	mu        sync.Mutex
	discovery *oidcDiscovery
	fetchedAt time.Time
}

type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

func NewOIDCProvider(cfg *compiled.AuthOIDC) *OIDCProvider {
	return &OIDCProvider{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		// ID token validation reuses the bearer machinery: signature via
		// the issuer's JWKS, issuer and audience (the client identity),
		// expiry with bounded skew (docs/spec/authentication.md).
		tokens: NewJWTValidator(&compiled.AuthJWT{
			Issuer:    cfg.Issuer,
			Audiences: []string{cfg.ClientID},
		}),
	}
}

func (p *OIDCProvider) discover() (*oidcDiscovery, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.discovery != nil && time.Since(p.fetchedAt) < jwksTTL {
		return p.discovery, nil
	}

	resp, err := p.client.Get(p.cfg.Issuer + "/.well-known/openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"%w: discovery answered %d", ErrUnavailable, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	discovery := &oidcDiscovery{}
	if err := json.Unmarshal(body, discovery); err != nil {
		return nil, fmt.Errorf("%w: invalid discovery document: %v", ErrUnavailable, err)
	}

	if discovery.AuthorizationEndpoint == "" || discovery.TokenEndpoint == "" {
		return nil, fmt.Errorf(
			"%w: discovery document misses endpoints", ErrUnavailable)
	}

	p.discovery = discovery
	p.fetchedAt = time.Now()

	return discovery, nil
}

// ------------------------------------------------------------- endpoints --

// serveOIDCStart begins the authorization redirect: the in-flight state
// cookie gains the flow's anti-forgery material
// (docs/spec/authentication.md In-flight login state).
func (e *Enforcer) serveOIDCStart(w http.ResponseWriter, r *http.Request) int {
	if e.oidc == nil {
		http.NotFound(w, r)

		return http.StatusNotFound
	}

	discovery, err := e.oidc.discover()
	if err != nil {
		http.Error(w, "authentication provider unavailable", http.StatusServiceUnavailable)

		return http.StatusServiceUnavailable
	}

	state := e.codec.OpenState(r)
	if state == nil || state.Extension != e.cfg.Identity {
		// No in-flight login: restart through the login page.
		return e.redirect(w, r, e.LoginURL(""))
	}

	state.OIDCState = randomToken()
	state.OIDCNonce = randomToken()
	state.OIDCVerifier = randomToken()

	if err := e.codec.SealState(w, r, state, false); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)

		return http.StatusInternalServerError
	}

	challenge := b64urlBytes(sha256Sum(state.OIDCVerifier))

	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.cfg.OIDC.ClientID},
		"redirect_uri":          {e.oidcRedirectURI(r)},
		"scope":                 {strings.Join(e.oidcScopes(), " ")},
		"state":                 {state.OIDCState},
		"nonce":                 {state.OIDCNonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	return e.redirect(w, r, discovery.AuthorizationEndpoint+"?"+query.Encode())
}

// serveOIDCCallback verifies the state, exchanges the code, validates
// the ID token (signature, issuer, audience, expiry, nonce), and mints
// the session (docs/spec/authentication.md OpenID Connect).
func (e *Enforcer) serveOIDCCallback(w http.ResponseWriter, r *http.Request) int {
	if e.oidc == nil {
		http.NotFound(w, r)

		return http.StatusNotFound
	}

	state := e.codec.OpenState(r)
	if state == nil || state.Extension != e.cfg.Identity ||
		state.OIDCState == "" || r.URL.Query().Get("state") != state.OIDCState {
		http.Error(w, "invalid login state", http.StatusBadRequest)

		return http.StatusBadRequest
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)

		return http.StatusBadRequest
	}

	tokens, err := e.oidc.exchange(r.Context(), url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {e.oidcRedirectURI(r)},
		"code_verifier": {state.OIDCVerifier},
	})
	if err != nil {
		http.Error(w, "authentication provider unavailable", http.StatusServiceUnavailable)

		return http.StatusServiceUnavailable
	}

	session, err := e.oidc.sessionFromTokens(tokens, state.OIDCNonce, e)
	if err != nil {
		http.Error(w, "login failed", http.StatusBadRequest)

		return http.StatusBadRequest
	}

	e.codec.ClearState(w, r)

	if err := e.codec.SealSession(w, r, session); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)

		return http.StatusInternalServerError
	}

	return e.redirect(w, r, sanitizeReturnURL(state.ReturnURL))
}

// ----------------------------------------------------------------- flows --

type oidcTokens struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

func (p *OIDCProvider) exchange(ctx context.Context, form url.Values) (*oidcTokens, error) {
	discovery, err := p.discover()
	if err != nil {
		return nil, err
	}

	form.Set("client_id", p.cfg.ClientID)
	if p.cfg.ClientSecret != "" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		discovery.TokenEndpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"%w: token endpoint answered %d", ErrUnavailable, resp.StatusCode)
	}

	tokens := &oidcTokens{}
	if err := json.Unmarshal(body, tokens); err != nil || tokens.IDToken == "" {
		return nil, fmt.Errorf("%w: invalid token response", ErrUnavailable)
	}

	return tokens, nil
}

// sessionFromTokens validates the ID token and mints the session:
// claims come from the ID token, `sub` is the user claim
// (docs/spec/authentication.md OpenID Connect).
func (p *OIDCProvider) sessionFromTokens(
	tokens *oidcTokens,
	expectedNonce string,
	enforcer *Enforcer,
) (*Session, error) {
	claims, err := p.tokens.Validate(tokens.IDToken)
	if err != nil {
		return nil, err
	}

	if expectedNonce != "" {
		if got := claims["nonce"]; len(got) != 1 || got[0] != expectedNonce {
			return nil, fmt.Errorf("%w: nonce mismatch", ErrUnauthenticated)
		}
	}

	extra := &Session{RefreshToken: tokens.RefreshToken}
	if tokens.ExpiresIn > 0 {
		extra.TokenExpiresAt = time.Now().Unix() + tokens.ExpiresIn
	}

	identity := &Identity{
		Groups: claims["groups"],
		Claims: claims,
	}

	if values := claims["sub"]; len(values) > 0 {
		identity.User = values[0]
	}

	if values := claims["email"]; len(values) > 0 {
		identity.Email = values[0]
	}

	return enforcer.mintSession("oidc", identity, extra), nil
}

// Refresh transparently renews an in-session expired token; the session
// lifetime still caps absolutely, so expiry is preserved
// (docs/spec/authentication.md).
func (p *OIDCProvider) Refresh(
	ctx context.Context,
	session *Session,
	cfg *compiled.Auth,
) (*Session, error) {
	tokens, err := p.exchange(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {session.RefreshToken},
	})
	if err != nil {
		return nil, err
	}

	if tokens.RefreshToken == "" {
		// Providers MAY rotate or withhold the refresh token; keep the
		// previous one until told otherwise.
		tokens.RefreshToken = session.RefreshToken
	}

	claims, err := p.tokens.Validate(tokens.IDToken)
	if err != nil {
		return nil, err
	}

	refreshed := &Session{
		Provider:  "oidc",
		Groups:    claims["groups"],
		Claims:    claims,
		IssuedAt:  session.IssuedAt,
		ExpiresAt: session.ExpiresAt,

		RefreshToken: tokens.RefreshToken,
	}

	if values := claims["sub"]; len(values) > 0 {
		refreshed.User = values[0]
	}

	if values := claims["email"]; len(values) > 0 {
		refreshed.Email = values[0]
	}

	if tokens.ExpiresIn > 0 {
		refreshed.TokenExpiresAt = time.Now().Unix() + tokens.ExpiresIn
	}

	return refreshed, nil
}

// LogoutURL redirects through the provider's end-session endpoint when
// the discovery document advertises one; `id_token_hint` is not sent
// (docs/spec/authentication.md Logout and single logout).
func (p *OIDCProvider) LogoutURL(r *http.Request, session *Session) string {
	discovery, err := p.discover()
	if err != nil || discovery.EndSessionEndpoint == "" {
		return ""
	}

	query := url.Values{
		"client_id":                {p.cfg.ClientID},
		"post_logout_redirect_uri": {requestOrigin(r) + "/"},
	}

	return discovery.EndSessionEndpoint + "?" + query.Encode()
}

// ---------------------------------------------------------------- helpers --

func (e *Enforcer) oidcRedirectURI(r *http.Request) string {
	return requestOrigin(r) + e.cfg.PathPrefix + "/oidc/callback"
}

func (e *Enforcer) oidcScopes() []string {
	if len(e.cfg.OIDC.Scopes) > 0 {
		return e.cfg.OIDC.Scopes
	}

	return []string{"openid"}
}

// requestOrigin rebuilds the request's own authority: redirect URIs and
// post-logout returns never leave it (docs/spec/authentication.md).
func requestOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	return scheme + "://" + r.Host
}

func randomToken() string {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}

	return base64.RawURLEncoding.EncodeToString(raw)
}

func sha256Sum(value string) []byte {
	sum := sha256.Sum256([]byte(value))

	return sum[:]
}

func b64urlBytes(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
