package auth

import (
	"crypto/rand"
	"encoding/base64"

	"net/http"

	"strings"
)

// ServeEndpoint dispatches one request under a reserved auth prefix
// (docs/spec/authentication.md Reserved path prefix). Candidates are
// the extensions serving this hostname whose prefix matches; flows are
// disambiguated by the `ext` parameter on the first hop and by the
// state and session cookies afterwards. Returns the served status.
func ServeEndpoint(w http.ResponseWriter, r *http.Request, candidates []*Enforcer) int {
	enforcer, endpoint := selectEndpoint(r, candidates)
	if enforcer == nil {
		http.NotFound(w, r)

		return http.StatusNotFound
	}

	switch {
	case endpoint == "/login" && r.Method == http.MethodGet:
		return enforcer.serveLogin(w, r)

	case endpoint == "/logout" && r.Method == http.MethodGet:
		return enforcer.serveLogout(w, r)

	case endpoint == "/oidc/start" && r.Method == http.MethodGet:
		return enforcer.serveOIDCStart(w, r)

	case endpoint == "/oidc/callback" && r.Method == http.MethodGet:
		return enforcer.serveOIDCCallback(w, r)

	case endpoint == "/saml/start" && r.Method == http.MethodGet:
		return enforcer.serveSAMLStart(w, r)

	case endpoint == "/saml/acs" && r.Method == http.MethodPost:
		return enforcer.serveSAMLACS(w, r)

	case endpoint == "/saml/metadata" && r.Method == http.MethodGet:
		return enforcer.serveSAMLMetadata(w, r)

	case endpoint == "/saml/slo":
		return enforcer.serveSAMLSLO(w, r)

	case endpoint == "/ldap/login" && r.Method == http.MethodPost:
		return enforcer.serveLDAPLogin(w, r)
	}

	http.NotFound(w, r)

	return http.StatusNotFound
}

// selectEndpoint picks the extension a reserved-prefix request belongs
// to: the `ext` parameter on first hops, the state or session cookie on
// later ones, or the only candidate.
func selectEndpoint(r *http.Request, candidates []*Enforcer) (*Enforcer, string) {
	pick := func() *Enforcer {
		if ext := r.URL.Query().Get("ext"); ext != "" {
			for _, candidate := range candidates {
				if candidate.Identity() == ext {
					return candidate
				}
			}

			return nil
		}

		for _, candidate := range candidates {
			if candidate.codec == nil {
				continue
			}

			if candidate.codec.OpenState(r) != nil || candidate.codec.OpenSession(r) != nil {
				return candidate
			}
		}

		if len(candidates) == 1 {
			return candidates[0]
		}

		return nil
	}

	enforcer := pick()
	if enforcer == nil {
		return nil, ""
	}

	return enforcer, strings.TrimPrefix(r.URL.Path, enforcer.PathPrefix())
}

// serveLogin serves the login page: a chooser of the extension's
// interactive providers and the LDAP credential form. With exactly one
// interactive provider and no `ldap`, the flow starts directly
// (docs/spec/authentication.md Login page).
func (e *Enforcer) serveLogin(w http.ResponseWriter, r *http.Request) int {
	returnURL := sanitizeReturnURL(r.URL.Query().Get("rd"))

	token, err := newFormToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)

		return http.StatusInternalServerError
	}

	state := &State{
		Extension: e.cfg.Identity,
		ReturnURL: returnURL,
		FormToken: token,
	}

	if err := e.codec.SealState(w, r, state, false); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)

		return http.StatusInternalServerError
	}

	// Single interactive provider, no credential form: skip the chooser
	// (docs/spec/authentication.md Login page).
	if e.cfg.LDAP == nil {
		if e.cfg.OIDC != nil && e.cfg.SAML == nil {
			return e.redirect(w, r, e.startURL("oidc"))
		}

		if e.cfg.SAML != nil && e.cfg.OIDC == nil {
			return e.redirect(w, r, e.startURL("saml"))
		}
	}

	return e.renderLoginPage(w, token)
}

// serveLogout clears the extension's session cookies and dispatches on
// the provider recorded in the session
// (docs/spec/authentication.md Logout and single logout).
func (e *Enforcer) serveLogout(w http.ResponseWriter, r *http.Request) int {
	session := e.codec.OpenSession(r)
	e.codec.ClearSession(w, r)

	if session != nil {
		switch session.Provider {
		case "saml":
			if e.saml != nil {
				if target := e.saml.LogoutURL(r, session, e.cfg.PathPrefix); target != "" {
					return e.redirect(w, r, target)
				}
			}

		case "oidc":
			if e.oidc != nil {
				if target := e.oidc.LogoutURL(r, session); target != "" {
					return e.redirect(w, r, target)
				}
			}
		}
	}

	return e.redirect(w, r, "/")
}

func (e *Enforcer) redirect(w http.ResponseWriter, r *http.Request, target string) int {
	http.Redirect(w, r, target, http.StatusFound)

	return http.StatusFound
}

func (e *Enforcer) startURL(provider string) string {
	return e.cfg.PathPrefix + "/" + provider + "/start"
}

// sanitizeReturnURL keeps path and query only, applied to the request's
// own authority: cross-origin post-login redirects are not expressible
// (docs/spec/authentication.md In-flight login state).
func sanitizeReturnURL(raw string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return "/"
	}

	return raw
}

func newFormToken() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}
