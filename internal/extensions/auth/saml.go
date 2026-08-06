package auth

import (
	"context"
	"fmt"

	"sync"

	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"

	"bytes"
	"compress/flate"
	"io"

	"net/http"
	"net/url"

	"time"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// SAMLProvider drives SP-initiated SAML 2.0 login: signed AuthnRequests
// over the HTTP-Redirect binding, assertions over the HTTP-POST binding,
// and front-channel single logout in both directions
// (docs/spec/authentication.md SAML 2.0). IdP metadata is fetched and
// cached per data-plane pod, or provided inline.
type SAMLProvider struct {
	cfg    *compiled.AuthSAML
	key    crypto.Signer
	cert   *x509.Certificate
	client *http.Client

	mu        sync.Mutex
	metadata  *saml.EntityDescriptor
	fetchedAt time.Time
}

func NewSAMLProvider(cfg *compiled.AuthSAML) (*SAMLProvider, error) {
	pair, err := tls.X509KeyPair([]byte(cfg.SPCertPEM), []byte(cfg.SPKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("sp key material: %w", err)
	}

	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("sp certificate: %w", err)
	}

	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("sp key does not sign")
	}

	provider := &SAMLProvider{
		cfg:    cfg,
		key:    signer,
		cert:   cert,
		client: &http.Client{Timeout: 10 * time.Second},
	}

	if cfg.IDPMetadata != "" {
		metadata, err := samlsp.ParseMetadata([]byte(cfg.IDPMetadata))
		if err != nil {
			return nil, fmt.Errorf("inline idp metadata: %w", err)
		}

		provider.metadata = metadata
	}

	return provider, nil
}

// idpMetadata returns the IdP metadata, fetching and caching it when it
// comes from idp_metadata_url (docs/spec/authentication.md SAML 2.0).
func (p *SAMLProvider) idpMetadata(ctx context.Context) (*saml.EntityDescriptor, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.metadata != nil && (p.cfg.IDPMetadataURL == "" || time.Since(p.fetchedAt) < jwksTTL) {
		return p.metadata, nil
	}

	target, err := url.Parse(p.cfg.IDPMetadataURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	metadata, err := samlsp.FetchMetadata(ctx, p.client, *target)
	if err != nil {
		if p.metadata != nil {
			// A previously fetched document keeps flows working through
			// a provider outage (docs/spec/authentication.md).
			return p.metadata, nil
		}

		return nil, fmt.Errorf("%w: idp metadata: %v", ErrUnavailable, err)
	}

	p.metadata = metadata
	p.fetchedAt = time.Now()

	return metadata, nil
}

// serviceProvider builds the request-scoped SP: the metadata, ACS and
// SLO URLs reflect the serving host (docs/spec/authentication.md
// Reserved path prefix).
func (p *SAMLProvider) serviceProvider(
	r *http.Request,
	prefix string,
) (*saml.ServiceProvider, error) {
	metadata, err := p.idpMetadata(r.Context())
	if err != nil {
		return nil, err
	}

	origin := requestOrigin(r)

	metadataURL, _ := url.Parse(origin + prefix + "/saml/metadata")
	acsURL, _ := url.Parse(origin + prefix + "/saml/acs")
	sloURL, _ := url.Parse(origin + prefix + "/saml/slo")

	return &saml.ServiceProvider{
		EntityID:    p.cfg.EntityID,
		Key:         p.key,
		Certificate: p.cert,
		HTTPClient:  p.client,
		MetadataURL: *metadataURL,
		AcsURL:      *acsURL,
		SloURL:      *sloURL,
		IDPMetadata: metadata,
		// AuthnRequests use the HTTP-Redirect binding and are signed
		// with sp_key (docs/spec/authentication.md SAML 2.0).
		SignatureMethod: dsig.RSASHA256SignatureMethod,
		// Unsolicited (IdP-initiated) responses MUST be rejected:
		// InResponseTo MUST match the in-flight request ID.
		AllowIDPInitiated: false,
	}, nil
}

// ------------------------------------------------------------- endpoints --

// serveSAMLStart begins the SP-initiated flow: the in-flight state
// cookie records the request ID, the stateless replay defense
// (docs/spec/authentication.md SAML 2.0). The POST callback arrives
// cross-site, so the state cookie is SameSite=None.
func (e *Enforcer) serveSAMLStart(w http.ResponseWriter, r *http.Request) int {
	if e.saml == nil {
		http.NotFound(w, r)

		return http.StatusNotFound
	}

	sp, err := e.saml.serviceProvider(r, e.cfg.PathPrefix)
	if err != nil {
		http.Error(w, "authentication provider unavailable", http.StatusServiceUnavailable)

		return http.StatusServiceUnavailable
	}

	state := e.codec.OpenState(r)
	if state == nil || state.Extension != e.cfg.Identity {
		return e.redirect(w, r, e.LoginURL(""))
	}

	request, err := sp.MakeAuthenticationRequest(
		sp.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		http.Error(w, "authentication provider unavailable", http.StatusServiceUnavailable)

		return http.StatusServiceUnavailable
	}

	state.SAMLRequestID = request.ID

	if err := e.codec.SealState(w, r, state, true); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)

		return http.StatusInternalServerError
	}

	target, err := request.Redirect("", sp)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)

		return http.StatusInternalServerError
	}

	return e.redirect(w, r, target.String())
}

// serveSAMLACS validates the posted assertion (signature against the
// IdP metadata, audience, destination, validity window, InResponseTo)
// and mints the session (docs/spec/authentication.md SAML 2.0).
func (e *Enforcer) serveSAMLACS(w http.ResponseWriter, r *http.Request) int {
	if e.saml == nil {
		http.NotFound(w, r)

		return http.StatusNotFound
	}

	sp, err := e.saml.serviceProvider(r, e.cfg.PathPrefix)
	if err != nil {
		http.Error(w, "authentication provider unavailable", http.StatusServiceUnavailable)

		return http.StatusServiceUnavailable
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)

		return http.StatusBadRequest
	}

	// The callback requires the in-flight state: an unsolicited
	// assertion has no matching request ID and is rejected.
	state := e.codec.OpenState(r)
	if state == nil || state.Extension != e.cfg.Identity || state.SAMLRequestID == "" {
		http.Error(w, "unsolicited saml response", http.StatusForbidden)

		return http.StatusForbidden
	}

	assertion, err := sp.ParseResponse(r, []string{state.SAMLRequestID})
	if err != nil {
		http.Error(w, "invalid saml response", http.StatusForbidden)

		return http.StatusForbidden
	}

	identity, extra := e.saml.identityFromAssertion(assertion, e.cfg.SAML.Attributes)

	session := e.mintSession("saml", identity, extra)

	e.codec.ClearState(w, r)

	if err := e.codec.SealSession(w, r, session); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)

		return http.StatusInternalServerError
	}

	return e.redirect(w, r, sanitizeReturnURL(state.ReturnURL))
}

// serveSAMLMetadata serves the SP metadata document, reflecting the ACS
// and SLO URLs of the host it is fetched from
// (docs/spec/authentication.md Reserved path prefix).
func (e *Enforcer) serveSAMLMetadata(w http.ResponseWriter, r *http.Request) int {
	if e.saml == nil {
		http.NotFound(w, r)

		return http.StatusNotFound
	}

	sp, err := e.saml.serviceProvider(r, e.cfg.PathPrefix)
	if err != nil {
		http.Error(w, "authentication provider unavailable", http.StatusServiceUnavailable)

		return http.StatusServiceUnavailable
	}

	document, err := xml.MarshalIndent(sp.Metadata(), "", "  ")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)

		return http.StatusInternalServerError
	}

	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(document)

	return http.StatusOK
}

// serveSAMLSLO is the single logout endpoint: LogoutResponses conclude
// RP-initiated logout, and IdP-initiated front-channel LogoutRequests
// clear the session and are answered with a signed LogoutResponse over
// the requested binding (docs/spec/authentication.md Logout and single
// logout).
func (e *Enforcer) serveSAMLSLO(w http.ResponseWriter, r *http.Request) int {
	if e.saml == nil {
		http.NotFound(w, r)

		return http.StatusNotFound
	}

	sp, err := e.saml.serviceProvider(r, e.cfg.PathPrefix)
	if err != nil {
		http.Error(w, "authentication provider unavailable", http.StatusServiceUnavailable)

		return http.StatusServiceUnavailable
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)

		return http.StatusBadRequest
	}

	// RP-initiated flow concluding: the IdP returns a LogoutResponse.
	if r.Form.Get("SAMLResponse") != "" {
		return e.redirect(w, r, "/")
	}

	encoded := r.Form.Get("SAMLRequest")
	if encoded == "" {
		http.Error(w, "missing saml message", http.StatusBadRequest)

		return http.StatusBadRequest
	}

	request, err := parseLogoutRequest(encoded, r.Method == http.MethodGet)
	if err != nil {
		http.Error(w, "invalid logout request", http.StatusBadRequest)

		return http.StatusBadRequest
	}

	// The request arrives through the user's browser: krouter can clear
	// the session cookie it could never reach server-side.
	e.codec.ClearSession(w, r)

	destination := sp.GetSLOBindingLocation(saml.HTTPRedirectBinding)
	if destination == "" {
		// No IdP SLO endpoint to answer to: the session is cleared, done.
		return e.redirect(w, r, "/")
	}

	response, err := sp.MakeLogoutResponse(destination, request.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)

		return http.StatusInternalServerError
	}

	target, err := signedRedirect(
		sp,
		destination,
		"SAMLResponse",
		response.Element(),
		r.Form.Get("RelayState"),
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)

		return http.StatusInternalServerError
	}

	return e.redirect(w, r, target)
}

// LogoutURL builds the RP-initiated single logout redirect from the
// session's NameID, when the IdP metadata advertises an SLO endpoint
// (docs/spec/authentication.md Logout and single logout).
func (p *SAMLProvider) LogoutURL(r *http.Request, session *Session, prefix string) string {
	if session.NameID == "" {
		return ""
	}

	sp, err := p.serviceProvider(r, prefix)
	if err != nil {
		return ""
	}

	destination := sp.GetSLOBindingLocation(saml.HTTPRedirectBinding)
	if destination == "" {
		return ""
	}

	request, err := sp.MakeLogoutRequest(destination, session.NameID)
	if err != nil {
		return ""
	}

	if session.SessionIndex != "" {
		request.SessionIndex = &saml.SessionIndex{Value: session.SessionIndex}
	}

	target, err := signedRedirect(sp, destination, "SAMLRequest", request.Element(), "")
	if err != nil {
		return ""
	}

	return target
}

// ---------------------------------------------------------------- helpers --

// identityFromAssertion maps the NameID and the configured assertion
// attributes onto the identity (docs/spec/authentication.md SAML 2.0).
func (p *SAMLProvider) identityFromAssertion(
	assertion *saml.Assertion,
	attributes map[string]string,
) (*Identity, *Session) {
	identity := &Identity{Claims: map[string][]string{}}

	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		identity.User = assertion.Subject.NameID.Value
	}

	values := map[string][]string{}
	for _, statement := range assertion.AttributeStatements {
		for _, attribute := range statement.Attributes {
			name := attribute.Name
			if name == "" {
				name = attribute.FriendlyName
			}

			for _, value := range attribute.Values {
				values[name] = append(values[name], value.Value)
			}
		}
	}

	identity.Claims = values

	if attribute := attributes["email"]; attribute != "" {
		if mapped := values[attribute]; len(mapped) > 0 {
			identity.Email = mapped[0]
		}
	}

	if attribute := attributes["groups"]; attribute != "" {
		identity.Groups = values[attribute]
	}

	extra := &Session{NameID: identity.User}
	for _, statement := range assertion.AuthnStatements {
		if statement.SessionIndex != "" {
			extra.SessionIndex = statement.SessionIndex
			break
		}
	}

	return identity, extra
}

// signedRedirect builds a redirect-binding URL for one SAML message,
// signing the query string with sp_key (SAML bindings §3.4.4.1; the
// XML signature does not survive the DEFLATE encoding, the query
// signature replaces it).
func signedRedirect(
	sp *saml.ServiceProvider,
	destination string,
	param string,
	element *etree.Element,
	relayState string,
) (string, error) {
	// The embedded XML signature MUST be removed on this binding.
	for _, child := range element.ChildElements() {
		if child.Tag == "Signature" {
			element.RemoveChild(child)
		}
	}

	var encoded bytes.Buffer
	b64 := base64.NewEncoder(base64.StdEncoding, &encoded)
	deflated, _ := flate.NewWriter(b64, flate.BestCompression)

	document := etree.NewDocument()
	document.SetRoot(element)
	if _, err := document.WriteTo(deflated); err != nil {
		return "", err
	}

	if err := deflated.Close(); err != nil {
		return "", err
	}

	if err := b64.Close(); err != nil {
		return "", err
	}

	target, err := url.Parse(destination)
	if err != nil {
		return "", err
	}

	// Order matters for the signature: the signed string is the query
	// as transmitted.
	query := target.RawQuery
	if query != "" {
		query += "&"
	}

	query += param + "=" + url.QueryEscape(encoded.String())
	if relayState != "" {
		query += "&RelayState=" + url.QueryEscape(relayState)
	}

	query += "&SigAlg=" + url.QueryEscape(sp.SignatureMethod)

	signingContext, err := saml.GetSigningContext(sp)
	if err != nil {
		return "", err
	}

	signature, err := signingContext.SignString(query)
	if err != nil {
		return "", err
	}

	query += "&Signature=" + url.QueryEscape(
		base64.StdEncoding.EncodeToString(signature))

	target.RawQuery = query

	return target.String(), nil
}

// parseLogoutRequest decodes an incoming front-channel LogoutRequest:
// base64 on the POST binding, base64 plus DEFLATE on the redirect
// binding.
func parseLogoutRequest(encoded string, deflated bool) (*saml.LogoutRequest, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	if deflated {
		raw, err = io.ReadAll(
			io.LimitReader(flate.NewReader(bytes.NewReader(raw)), 1<<20))
		if err != nil {
			return nil, err
		}
	}

	request := &saml.LogoutRequest{}
	if err := xml.Unmarshal(raw, request); err != nil {
		return nil, err
	}

	if request.ID == "" {
		return nil, fmt.Errorf("logout request has no ID")
	}

	return request, nil
}
