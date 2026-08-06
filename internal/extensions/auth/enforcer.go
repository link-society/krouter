package auth

import (
	"context"
	"errors"
	"fmt"

	"strings"

	"net/http"
	"net/url"

	"time"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
	"github.com/link-society/krouter/internal/lib/transports/grpc"
)

// Identity headers injected for authenticated and authorized requests;
// client-supplied copies are stripped on every auth-enabled rule,
// whatever the outcome (docs/spec/authentication.md Identity headers).
const (
	HeaderUser   = "X-Auth-Request-User"
	HeaderEmail  = "X-Auth-Request-Email"
	HeaderGroups = "X-Auth-Request-Groups"
)

// Identity is the authenticated principal applied to proxied requests.
type Identity struct {
	User   string
	Email  string
	Groups []string
	Claims map[string][]string
}

// Decision is the outcome of enforcing one rule's auth extension
// (docs/spec/authentication.md Request path integration). When Allowed
// is false, the transport-appropriate rejection is described by Status,
// RedirectTo, Challenges and GRPCCode.
type Decision struct {
	Allowed  bool
	Identity *Identity

	// Provider that decided, for metrics and logs: oidc|saml|ldap|jwt,
	// or empty when no provider was engaged.
	Provider string
	// Result classifies the decision for metrics:
	// allowed|unauthenticated|forbidden|error.
	Result string

	Status     int
	RedirectTo string
	Challenges []string
	GRPCCode   string
	Message    string
}

// Enforcer evaluates one extension's providers on the request path.
// Session and token validation are local cryptography on most requests
// (docs/spec/authentication.md).
type Enforcer struct {
	cfg   *compiled.Auth
	codec *Codec

	jwt  *JWTValidator
	oidc *OIDCProvider
	ldap *LDAPProvider
	saml *SAMLProvider
}

// Providers not implemented yet are constructed by their own commits;
// until then a configured provider without an implementation fails
// closed through the nil checks in Evaluate.
type (
	LDAPProvider struct{}
	SAMLProvider struct{}
)

func NewLDAPProvider(cfg *compiled.AuthLDAP) (*LDAPProvider, error) { return nil, nil }

func NewSAMLProvider(cfg *compiled.AuthSAML) (*SAMLProvider, error) { return nil, nil }

func (p *SAMLProvider) LogoutURL(r *http.Request, session *Session) string { return "" }

func (p *LDAPProvider) Authenticate(ctx context.Context, username, password string) (*Identity, error) {
	return nil, fmt.Errorf("%w: ldap not implemented", ErrUnavailable)
}

func (e *Enforcer) serveSAMLStart(w http.ResponseWriter, r *http.Request) int {
	http.NotFound(w, r)

	return http.StatusNotFound
}

func (e *Enforcer) serveSAMLACS(w http.ResponseWriter, r *http.Request) int {
	http.NotFound(w, r)

	return http.StatusNotFound
}

func (e *Enforcer) serveSAMLMetadata(w http.ResponseWriter, r *http.Request) int {
	http.NotFound(w, r)

	return http.StatusNotFound
}

func (e *Enforcer) serveSAMLSLO(w http.ResponseWriter, r *http.Request) int {
	http.NotFound(w, r)

	return http.StatusNotFound
}

func (e *Enforcer) serveLDAPLogin(w http.ResponseWriter, r *http.Request) int {
	http.NotFound(w, r)

	return http.StatusNotFound
}

// NewEnforcer hydrates the providers of one compiled extension.
func NewEnforcer(cfg *compiled.Auth) (*Enforcer, error) {
	enforcer := &Enforcer{cfg: cfg}

	if cfg.Session != nil {
		codec, err := NewCodec(cfg.Identity, cfg.Session)
		if err != nil {
			return nil, fmt.Errorf("session codec: %w", err)
		}

		enforcer.codec = codec
	}

	if cfg.JWT != nil {
		enforcer.jwt = NewJWTValidator(cfg.JWT)
	}

	if cfg.OIDC != nil {
		enforcer.oidc = NewOIDCProvider(cfg.OIDC)
	}

	if cfg.LDAP != nil {
		provider, err := NewLDAPProvider(cfg.LDAP)
		if err != nil {
			return nil, fmt.Errorf("ldap provider: %w", err)
		}

		enforcer.ldap = provider
	}

	if cfg.SAML != nil {
		provider, err := NewSAMLProvider(cfg.SAML)
		if err != nil {
			return nil, fmt.Errorf("saml provider: %w", err)
		}

		enforcer.saml = provider
	}

	return enforcer, nil
}

func (e *Enforcer) Identity() string   { return e.cfg.Identity }
func (e *Enforcer) PathPrefix() string { return e.cfg.PathPrefix }

// HasCookieProvider reports whether the extension mints sessions: only
// then are the reserved endpoints intercepted for its hostnames
// (docs/spec/authentication.md Reserved path prefix).
func (e *Enforcer) HasCookieProvider() bool {
	return e.cfg.OIDC != nil || e.cfg.SAML != nil || e.cfg.LDAP != nil
}

// Evaluate enforces authentication and authorization for one request
// (docs/spec/authentication.md Provider selection). It may set cookies
// on the response (an LDAP bind mints the session) but never writes the
// status or body: the caller renders the Decision.
func (e *Enforcer) Evaluate(w http.ResponseWriter, r *http.Request, grpcRule bool) Decision {
	// Stripped whatever the outcome: a client can never smuggle identity
	// past the gateway (docs/spec/authentication.md Identity headers).
	r.Header.Del(HeaderUser)
	r.Header.Del(HeaderEmail)
	r.Header.Del(HeaderGroups)

	// 1. A valid session authenticates the request, whichever cookie
	// provider minted it.
	if e.codec != nil {
		if session := e.codec.OpenSession(r); session != nil {
			if refreshed, ok := e.refreshIfNeeded(w, r, session); ok {
				return e.authorize(refreshed, refreshed.Provider, grpcRule)
			}
		}
	}

	scheme, credentials := authorizationHeader(r)

	// 2. Bearer tokens are validated by the jwt provider.
	if scheme == "bearer" && e.jwt != nil {
		claims, err := e.jwt.Validate(credentials)
		if err != nil {
			return e.credentialFailure("jwt", err, grpcRule)
		}

		return e.authorize(sessionFromClaims("jwt", claims, e.cfg), "jwt", grpcRule)
	}

	// 3. Basic credentials are validated by the ldap provider.
	if scheme == "basic" && e.ldap != nil {
		username, password, ok := r.BasicAuth()
		if !ok {
			return e.unauthenticated(grpcRule, false, "")
		}

		identity, err := e.ldap.Authenticate(r.Context(), username, password)
		if err != nil {
			return e.credentialFailure("ldap", err, grpcRule)
		}

		session := e.mintSession("ldap", identity, nil)
		if e.codec != nil {
			// A successful bind mints the session cookie so cookie-keeping
			// clients do not re-bind (docs/spec/authentication.md LDAP).
			if err := e.codec.SealSession(w, r, session); err != nil {
				return e.failure("ldap", err, grpcRule)
			}
		}

		return e.authorize(session, "ldap", grpcRule)
	}

	// 4. Anything else is unauthenticated.
	return e.unauthenticated(grpcRule, isNavigation(r), r.URL.RequestURI())
}

// refreshIfNeeded hands an in-session expired OIDC token to the
// provider for a transparent refresh; failures degrade to a new login,
// never to an error (docs/spec/authentication.md OpenID Connect).
func (e *Enforcer) refreshIfNeeded(
	w http.ResponseWriter,
	r *http.Request,
	session *Session,
) (*Session, bool) {
	if session.TokenExpiresAt == 0 || time.Now().Unix() < session.TokenExpiresAt {
		return session, true
	}

	if session.Provider != "oidc" || e.oidc == nil || session.RefreshToken == "" {
		return nil, false
	}

	refreshed, err := e.oidc.Refresh(r.Context(), session, e.cfg)
	if err != nil {
		return nil, false
	}

	if err := e.codec.SealSession(w, r, refreshed); err != nil {
		return nil, false
	}

	return refreshed, true
}

// authorize evaluates the claim rules; failures answer 403 and MUST NOT
// trigger a login redirect (docs/spec/authentication.md Authorization).
func (e *Enforcer) authorize(session *Session, provider string, grpcRule bool) Decision {
	identity := &Identity{
		User:   session.User,
		Email:  session.Email,
		Groups: session.Groups,
		Claims: session.Claims,
	}

	for _, require := range e.cfg.Authorization {
		if !intersects(claimValues(identity, require.Claim), require.Values) {
			return Decision{
				Provider: provider,
				Result:   "forbidden",
				Status:   http.StatusForbidden,
				GRPCCode: grpc.StatusPermissionDenied,
				Message:  "forbidden",
			}
		}
	}

	return Decision{
		Allowed:  true,
		Identity: identity,
		Provider: provider,
		Result:   "allowed",
	}
}

// credentialFailure classifies a failed validation of presented
// credentials: 401, never a redirect; unreachable providers fail closed
// with 503 (docs/spec/authentication.md Provider selection).
func (e *Enforcer) credentialFailure(provider string, err error, grpcRule bool) Decision {
	if errors.Is(err, ErrUnavailable) {
		return e.failure(provider, err, grpcRule)
	}

	decision := e.unauthenticated(grpcRule, false, "")
	decision.Provider = provider

	return decision
}

func (e *Enforcer) failure(provider string, err error, grpcRule bool) Decision {
	return Decision{
		Provider: provider,
		Result:   "error",
		Status:   http.StatusServiceUnavailable,
		GRPCCode: grpc.StatusUnavailable,
		Message:  "authentication provider unavailable",
	}
}

// unauthenticated renders the no-credentials outcome: browser
// navigations are redirected to the login page when a cookie provider
// is configured, everything else is answered 401 with one challenge per
// credential-consuming provider (docs/spec/authentication.md).
func (e *Enforcer) unauthenticated(grpcRule, navigation bool, returnURL string) Decision {
	if navigation && !grpcRule && e.HasCookieProvider() {
		return Decision{
			Result:     "unauthenticated",
			Status:     http.StatusFound,
			RedirectTo: e.LoginURL(returnURL),
		}
	}

	var challenges []string
	if e.cfg.JWT != nil {
		challenges = append(challenges, `Bearer realm="krouter"`)
	}

	if e.cfg.LDAP != nil {
		realm := e.cfg.LDAP.Realm
		if realm == "" {
			realm = "krouter"
		}

		challenges = append(challenges, fmt.Sprintf("Basic realm=%q", realm))
	}

	return Decision{
		Result:     "unauthenticated",
		Status:     http.StatusUnauthorized,
		Challenges: challenges,
		GRPCCode:   grpc.StatusUnauthenticated,
		Message:    "authentication required",
	}
}

// LoginURL is the login page target for one return URL
// (docs/spec/authentication.md Login page). The extension identity
// bridges the first hop; the state cookie carries it afterwards.
func (e *Enforcer) LoginURL(returnURL string) string {
	target := e.cfg.PathPrefix + "/login?ext=" + url.QueryEscape(e.cfg.Identity)
	if returnURL != "" {
		target += "&rd=" + url.QueryEscape(returnURL)
	}

	return target
}

// mintSession builds a session from one provider identity, pruned to
// the claims that authorization rules and identity headers consume
// (docs/spec/authentication.md Stateless sessions).
func (e *Enforcer) mintSession(provider string, identity *Identity, extra *Session) *Session {
	now := time.Now()

	session := &Session{
		Provider:  provider,
		User:      identity.User,
		Email:     identity.Email,
		Groups:    identity.Groups,
		Claims:    e.pruneClaims(identity.Claims),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(e.codec.Lifetime()).Unix(),
	}

	if extra != nil {
		session.TokenExpiresAt = extra.TokenExpiresAt
		session.RefreshToken = extra.RefreshToken
		session.NameID = extra.NameID
		session.SessionIndex = extra.SessionIndex
	}

	return session
}

// pruneClaims keeps only the claims that authorization rules consume:
// the session budget is bounded (docs/spec/authentication.md).
func (e *Enforcer) pruneClaims(claims map[string][]string) map[string][]string {
	if len(claims) == 0 || len(e.cfg.Authorization) == 0 {
		return nil
	}

	pruned := map[string][]string{}
	for _, require := range e.cfg.Authorization {
		switch require.Claim {
		case "user", "email", "groups":
			continue
		}

		if values, ok := claims[require.Claim]; ok {
			pruned[require.Claim] = values
		}
	}

	if len(pruned) == 0 {
		return nil
	}

	return pruned
}

// ---------------------------------------------------------------- helpers --

func sessionFromClaims(provider string, claims map[string][]string, cfg *compiled.Auth) *Session {
	session := &Session{
		Provider: provider,
		Claims:   claims,
		Groups:   claims["groups"],
	}

	if values := claims["sub"]; len(values) > 0 {
		session.User = values[0]
	}

	if values := claims["email"]; len(values) > 0 {
		session.Email = values[0]
	}

	return session
}

func claimValues(identity *Identity, claim string) []string {
	switch claim {
	case "user":
		return []string{identity.User}
	case "email":
		return []string{identity.Email}
	case "groups":
		return identity.Groups
	}

	return identity.Claims[claim]
}

func authorizationHeader(r *http.Request) (string, string) {
	value := r.Header.Get("Authorization")
	if value == "" {
		return "", ""
	}

	scheme, credentials, found := strings.Cut(value, " ")
	if !found {
		return "", ""
	}

	return strings.ToLower(scheme), strings.TrimSpace(credentials)
}

// isNavigation reports whether the request looks like a top-level
// browser navigation: method GET or HEAD with an Accept header
// including text/html (docs/spec/authentication.md).
func isNavigation(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}

	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// Apply injects the authenticated identity into the proxied request
// (docs/spec/authentication.md Identity headers).
func (identity *Identity) Apply(r *http.Request) {
	if identity.User != "" {
		r.Header.Set(HeaderUser, identity.User)
	}

	if identity.Email != "" {
		r.Header.Set(HeaderEmail, identity.Email)
	}

	if len(identity.Groups) > 0 {
		r.Header.Set(HeaderGroups, strings.Join(identity.Groups, ","))
	}
}
