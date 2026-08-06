package auth

import (
	"context"
	"fmt"

	"strings"

	"crypto/tls"
	"crypto/x509"

	"net"
	"net/http"
	"net/url"

	"time"

	ldapv3 "github.com/go-ldap/ldap/v3"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// ldapTimeout bounds every directory operation: an unreachable
// directory fails closed (docs/spec/authentication.md LDAP).
const ldapTimeout = 10 * time.Second

// LDAPProvider authenticates presented credentials against a directory
// with search-then-bind (docs/spec/authentication.md LDAP). Connections
// are per attempt: verified credentials are never cached beyond the
// session cookie.
type LDAPProvider struct {
	cfg   *compiled.AuthLDAP
	roots *x509.CertPool
}

func NewLDAPProvider(cfg *compiled.AuthLDAP) (*LDAPProvider, error) {
	provider := &LDAPProvider{cfg: cfg}

	if cfg.CA != "" {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(cfg.CA)) {
			return nil, fmt.Errorf("ldap ca holds no certificate")
		}

		provider.roots = roots
	}

	return provider, nil
}

func (p *LDAPProvider) connect(ctx context.Context) (*ldapv3.Conn, error) {
	server, err := url.Parse(p.cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	tlsConfig := &tls.Config{
		ServerName: server.Hostname(),
		RootCAs:    p.roots,
	}

	conn, err := ldapv3.DialURL(
		p.cfg.URL,
		ldapv3.DialWithDialer(&net.Dialer{Timeout: ldapTimeout}),
		ldapv3.DialWithTLSConfig(tlsConfig),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	conn.SetTimeout(ldapTimeout)

	// StartTLS upgrades an ldap:// connection before any credential is
	// sent (docs/spec/authentication.md LDAP).
	if p.cfg.StartTLS {
		if err := conn.StartTLS(tlsConfig); err != nil {
			conn.Close()

			return nil, fmt.Errorf("%w: start_tls: %v", ErrUnavailable, err)
		}
	}

	return conn, nil
}

// Authenticate performs search-then-bind: bind as the service account,
// search for exactly one user entry, bind as the found DN with the
// presented password, and resolve the mapped attributes and groups
// (docs/spec/authentication.md LDAP).
func (p *LDAPProvider) Authenticate(
	ctx context.Context,
	username string,
	password string,
) (*Identity, error) {
	if username == "" || password == "" {
		return nil, fmt.Errorf("%w: empty credentials", ErrUnauthenticated)
	}

	conn, err := p.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.Bind(p.cfg.BindDN, p.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("%w: service bind: %v", ErrUnavailable, err)
	}

	// {username} is escaped per RFC 4515 (docs/spec/authentication.md).
	filter := strings.ReplaceAll(
		p.cfg.UserFilter,
		"{username}",
		ldapv3.EscapeFilter(username),
	)

	attributes := []string{"dn"}
	for _, attribute := range p.cfg.Attributes {
		attributes = append(attributes, attribute)
	}

	result, err := conn.Search(ldapv3.NewSearchRequest(
		p.cfg.UserBaseDN,
		ldapv3.ScopeWholeSubtree,
		ldapv3.NeverDerefAliases,
		2, // one entry expected: two is already a failure
		int(ldapTimeout.Seconds()),
		false,
		filter,
		attributes,
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("%w: user search: %v", ErrUnavailable, err)
	}

	// Zero or several matches answer the challenge again
	// (docs/spec/authentication.md LDAP).
	if len(result.Entries) != 1 {
		return nil, fmt.Errorf(
			"%w: user search matched %d entries", ErrUnauthenticated, len(result.Entries))
	}

	entry := result.Entries[0]

	if err := conn.Bind(entry.DN, password); err != nil {
		if ldapv3.IsErrorWithCode(err, ldapv3.LDAPResultInvalidCredentials) {
			return nil, fmt.Errorf("%w: bind failed", ErrUnauthenticated)
		}

		return nil, fmt.Errorf("%w: user bind: %v", ErrUnavailable, err)
	}

	identity := &Identity{User: username}

	if attribute := p.cfg.Attributes["email"]; attribute != "" {
		identity.Email = entry.GetAttributeValue(attribute)
	}

	// Group membership from a group-valued attribute, an optional group
	// search, or both merged (docs/spec/authentication.md LDAP).
	if attribute := p.cfg.Attributes["groups"]; attribute != "" {
		identity.Groups = append(identity.Groups, entry.GetAttributeValues(attribute)...)
	}

	if p.cfg.GroupSearch != nil {
		groups, err := p.searchGroups(conn, entry.DN, username)
		if err != nil {
			return nil, err
		}

		identity.Groups = mergeValues(identity.Groups, groups)
	}

	return identity, nil
}

func (p *LDAPProvider) searchGroups(
	conn *ldapv3.Conn,
	userDN string,
	username string,
) ([]string, error) {
	search := p.cfg.GroupSearch

	// {dn} and {username} substitutions are escaped per RFC 4515
	// (docs/spec/authentication.md LDAP).
	filter := strings.ReplaceAll(search.Filter, "{dn}", ldapv3.EscapeFilter(userDN))
	filter = strings.ReplaceAll(filter, "{username}", ldapv3.EscapeFilter(username))

	result, err := conn.Search(ldapv3.NewSearchRequest(
		search.BaseDN,
		ldapv3.ScopeWholeSubtree,
		ldapv3.NeverDerefAliases,
		0,
		int(ldapTimeout.Seconds()),
		false,
		filter,
		[]string{search.Attribute},
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("%w: group search: %v", ErrUnavailable, err)
	}

	var groups []string
	for _, entry := range result.Entries {
		groups = append(groups, entry.GetAttributeValues(search.Attribute)...)
	}

	return groups, nil
}

func mergeValues(existing, extra []string) []string {
	seen := map[string]bool{}
	for _, value := range existing {
		seen[value] = true
	}

	for _, value := range extra {
		if !seen[value] {
			seen[value] = true
			existing = append(existing, value)
		}
	}

	return existing
}

// ------------------------------------------------------------- endpoints --

// serveLDAPLogin is the login form's target: the POST MUST carry the
// in-flight state cookie and the embedded anti-forgery token
// (docs/spec/authentication.md Login page).
func (e *Enforcer) serveLDAPLogin(w http.ResponseWriter, r *http.Request) int {
	if e.ldap == nil {
		http.NotFound(w, r)

		return http.StatusNotFound
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)

		return http.StatusBadRequest
	}

	state := e.codec.OpenState(r)
	if state == nil || state.Extension != e.cfg.Identity ||
		state.FormToken == "" || r.PostFormValue("token") != state.FormToken {
		// A cross-site POST carries neither the state cookie nor the
		// token: rejected, nothing is minted.
		http.Error(w, "invalid login state", http.StatusForbidden)

		return http.StatusForbidden
	}

	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	identity, err := e.ldap.Authenticate(r.Context(), username, password)
	if err != nil {
		if strings.Contains(err.Error(), ErrUnavailable.Error()) {
			http.Error(w, "authentication provider unavailable", http.StatusServiceUnavailable)

			return http.StatusServiceUnavailable
		}

		// A failed bind re-renders the form with a generic notice naming
		// neither the reason nor the directory
		// (docs/spec/authentication.md Login page).
		return e.renderLoginPageResult(w, state.FormToken, true)
	}

	session := e.mintSession("ldap", identity, nil)

	e.codec.ClearState(w, r)

	if err := e.codec.SealSession(w, r, session); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)

		return http.StatusInternalServerError
	}

	return e.redirect(w, r, sanitizeReturnURL(state.ReturnURL))
}
