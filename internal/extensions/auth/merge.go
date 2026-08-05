package auth

import (
	"fmt"

	"strings"

	"net/url"

	"crypto/tls"
	"crypto/x509"
	"encoding/pem"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// Merge folds documents in filter list order into the compiled
// configuration (docs/spec/authentication.md Resolution and status):
// `session` and same-type provider blocks merge attribute by attribute,
// nested blocks replace as a unit, `require` blocks concatenate, and
// `path_prefix` is overridden wholesale. The merged result MUST
// configure at least one provider; the caller sets the extension
// identity.
func Merge(docs []*Document) (*compiled.Auth, error) {
	merged := &Document{}

	for _, doc := range docs {
		mergeSession(merged, doc)
		mergeOIDC(merged, doc)
		mergeSAML(merged, doc)
		mergeLDAP(merged, doc)
		mergeJWT(merged, doc)

		merged.Requires = append(merged.Requires, doc.Requires...)

		if doc.PathPrefix != nil {
			merged.PathPrefix = doc.PathPrefix
		}
	}

	return validate(merged)
}

func mergeSession(merged, doc *Document) {
	if doc.Session == nil {
		return
	}

	if merged.Session == nil {
		merged.Session = &SessionDoc{}
	}

	if doc.Session.Secret != nil {
		merged.Session.Secret = doc.Session.Secret
	}

	if doc.Session.Lifetime != nil {
		merged.Session.Lifetime = doc.Session.Lifetime
	}
}

func mergeOIDC(merged, doc *Document) {
	if doc.OIDC == nil {
		return
	}

	if merged.OIDC == nil {
		merged.OIDC = &OIDCDoc{}
	}

	if doc.OIDC.Issuer != nil {
		merged.OIDC.Issuer = doc.OIDC.Issuer
	}

	if doc.OIDC.ClientID != nil {
		merged.OIDC.ClientID = doc.OIDC.ClientID
	}

	if doc.OIDC.ClientSecret != nil {
		merged.OIDC.ClientSecret = doc.OIDC.ClientSecret
	}

	if doc.OIDC.Scopes != nil {
		merged.OIDC.Scopes = doc.OIDC.Scopes
	}

	if doc.OIDC.DisplayName != nil {
		merged.OIDC.DisplayName = doc.OIDC.DisplayName
	}
}

func mergeSAML(merged, doc *Document) {
	if doc.SAML == nil {
		return
	}

	if merged.SAML == nil {
		merged.SAML = &SAMLDoc{}
	}

	if doc.SAML.EntityID != nil {
		merged.SAML.EntityID = doc.SAML.EntityID
	}

	if doc.SAML.IDPMetadataURL != nil {
		merged.SAML.IDPMetadataURL = doc.SAML.IDPMetadataURL
	}

	if doc.SAML.IDPMetadata != nil {
		merged.SAML.IDPMetadata = doc.SAML.IDPMetadata
	}

	if doc.SAML.SPKey != nil {
		merged.SAML.SPKey = doc.SAML.SPKey
	}

	if doc.SAML.SPCertificate != nil {
		merged.SAML.SPCertificate = doc.SAML.SPCertificate
	}

	// Nested blocks replace as a unit (docs/spec/authentication.md).
	if doc.SAML.Attributes != nil {
		merged.SAML.Attributes = doc.SAML.Attributes
	}

	if doc.SAML.DisplayName != nil {
		merged.SAML.DisplayName = doc.SAML.DisplayName
	}
}

func mergeLDAP(merged, doc *Document) {
	if doc.LDAP == nil {
		return
	}

	if merged.LDAP == nil {
		merged.LDAP = &LDAPDoc{}
	}

	if doc.LDAP.URL != nil {
		merged.LDAP.URL = doc.LDAP.URL
	}

	if doc.LDAP.StartTLS != nil {
		merged.LDAP.StartTLS = doc.LDAP.StartTLS
	}

	if doc.LDAP.CA != nil {
		merged.LDAP.CA = doc.LDAP.CA
	}

	if doc.LDAP.BindDN != nil {
		merged.LDAP.BindDN = doc.LDAP.BindDN
	}

	if doc.LDAP.BindPassword != nil {
		merged.LDAP.BindPassword = doc.LDAP.BindPassword
	}

	if doc.LDAP.UserBaseDN != nil {
		merged.LDAP.UserBaseDN = doc.LDAP.UserBaseDN
	}

	if doc.LDAP.UserFilter != nil {
		merged.LDAP.UserFilter = doc.LDAP.UserFilter
	}

	if doc.LDAP.Realm != nil {
		merged.LDAP.Realm = doc.LDAP.Realm
	}

	// Nested blocks replace as a unit (docs/spec/authentication.md).
	if doc.LDAP.Attributes != nil {
		merged.LDAP.Attributes = doc.LDAP.Attributes
	}

	if doc.LDAP.GroupSearch != nil {
		merged.LDAP.GroupSearch = doc.LDAP.GroupSearch
	}

	if doc.LDAP.DisplayName != nil {
		merged.LDAP.DisplayName = doc.LDAP.DisplayName
	}
}

func mergeJWT(merged, doc *Document) {
	if doc.JWT == nil {
		return
	}

	if merged.JWT == nil {
		merged.JWT = &JWTDoc{}
	}

	if doc.JWT.Issuer != nil {
		merged.JWT.Issuer = doc.JWT.Issuer
	}

	if doc.JWT.Audiences != nil {
		merged.JWT.Audiences = doc.JWT.Audiences
	}

	if doc.JWT.JWKSURL != nil {
		merged.JWT.JWKSURL = doc.JWT.JWKSURL
	}
}

// validate checks the merged configuration statically: schema
// completeness, well-formed URLs, parseable key material, session
// secret length (docs/spec/authentication.md Configuration lifecycle).
// It never contacts providers.
func validate(merged *Document) (*compiled.Auth, error) {
	config := &compiled.Auth{PathPrefix: DefaultPathPrefix}
	if merged.PathPrefix != nil {
		config.PathPrefix = *merged.PathPrefix
	}

	config.Authorization = merged.Requires

	providers := 0
	cookieProviders := 0

	if merged.OIDC != nil {
		providers++
		cookieProviders++

		oidc, err := validateOIDC(merged.OIDC)
		if err != nil {
			return nil, err
		}

		config.OIDC = oidc
	}

	if merged.SAML != nil {
		providers++
		cookieProviders++

		saml, err := validateSAML(merged.SAML)
		if err != nil {
			return nil, err
		}

		config.SAML = saml
	}

	if merged.LDAP != nil {
		providers++
		cookieProviders++

		ldap, err := validateLDAP(merged.LDAP)
		if err != nil {
			return nil, err
		}

		config.LDAP = ldap
	}

	if merged.JWT != nil {
		providers++

		jwt, err := validateJWT(merged.JWT)
		if err != nil {
			return nil, err
		}

		config.JWT = jwt
	}

	if providers == 0 {
		return nil, fmt.Errorf("merged configuration must configure at least one provider")
	}

	session, err := validateSession(merged.Session, cookieProviders > 0)
	if err != nil {
		return nil, err
	}

	config.Session = session

	return config, nil
}

func validateSession(session *SessionDoc, required bool) (*compiled.AuthSession, error) {
	if session == nil {
		if required {
			return nil, fmt.Errorf("session block is required with cookie providers")
		}

		return nil, nil
	}

	if !required {
		// docs/spec/authentication.md: bearer validation keeps no session.
		return nil, fmt.Errorf("session block is invalid when jwt is the only provider")
	}

	if session.Secret == nil || len(*session.Secret) < MinSessionSecretBytes {
		return nil, fmt.Errorf(
			"session secret must hold at least %d bytes", MinSessionSecretBytes)
	}

	lifetime := DefaultSessionLifetime
	if session.Lifetime != nil {
		lifetime = *session.Lifetime
	}

	return &compiled.AuthSession{
		Secret:         *session.Secret,
		LifetimeMillis: lifetime.Milliseconds(),
	}, nil
}

func validateOIDC(doc *OIDCDoc) (*compiled.AuthOIDC, error) {
	if doc.Issuer == nil || doc.ClientID == nil {
		return nil, fmt.Errorf("oidc provider must define issuer and client_id")
	}

	if err := validateHTTPURL("oidc issuer", *doc.Issuer); err != nil {
		return nil, err
	}

	config := &compiled.AuthOIDC{
		Issuer:   strings.TrimSuffix(*doc.Issuer, "/"),
		ClientID: *doc.ClientID,
		Scopes:   doc.Scopes,
	}

	if doc.ClientSecret != nil {
		config.ClientSecret = *doc.ClientSecret
	}

	if doc.DisplayName != nil {
		config.DisplayName = *doc.DisplayName
	}

	return config, nil
}

func validateSAML(doc *SAMLDoc) (*compiled.AuthSAML, error) {
	if doc.EntityID == nil {
		return nil, fmt.Errorf("saml provider must define entity_id")
	}

	hasURL := doc.IDPMetadataURL != nil
	hasInline := doc.IDPMetadata != nil
	if hasURL == hasInline {
		return nil, fmt.Errorf(
			"saml provider must define exactly one of idp_metadata_url and idp_metadata")
	}

	if hasURL {
		if err := validateHTTPURL("saml idp_metadata_url", *doc.IDPMetadataURL); err != nil {
			return nil, err
		}
	}

	if doc.SPKey == nil || doc.SPCertificate == nil {
		return nil, fmt.Errorf("saml provider must define sp_key and sp_certificate")
	}

	if _, err := tls.X509KeyPair([]byte(*doc.SPCertificate), []byte(*doc.SPKey)); err != nil {
		return nil, fmt.Errorf("saml sp key material: %v", err)
	}

	config := &compiled.AuthSAML{
		EntityID:   *doc.EntityID,
		SPKeyPEM:   *doc.SPKey,
		SPCertPEM:  *doc.SPCertificate,
		Attributes: doc.Attributes,
	}

	if hasURL {
		config.IDPMetadataURL = *doc.IDPMetadataURL
	} else {
		config.IDPMetadata = *doc.IDPMetadata
	}

	if doc.DisplayName != nil {
		config.DisplayName = *doc.DisplayName
	}

	return config, nil
}

func validateLDAP(doc *LDAPDoc) (*compiled.AuthLDAP, error) {
	if doc.URL == nil || doc.BindDN == nil || doc.BindPassword == nil ||
		doc.UserBaseDN == nil || doc.UserFilter == nil {
		return nil, fmt.Errorf(
			"ldap provider must define url, bind_dn, bind_password, " +
				"user_base_dn and user_filter")
	}

	parsed, err := url.Parse(*doc.URL)
	if err != nil || (parsed.Scheme != "ldap" && parsed.Scheme != "ldaps") || parsed.Host == "" {
		return nil, fmt.Errorf("invalid ldap url %q", *doc.URL)
	}

	if !strings.Contains(*doc.UserFilter, "{username}") {
		return nil, fmt.Errorf("ldap user_filter must reference {username}")
	}

	config := &compiled.AuthLDAP{
		URL:          *doc.URL,
		BindDN:       *doc.BindDN,
		BindPassword: *doc.BindPassword,
		UserBaseDN:   *doc.UserBaseDN,
		UserFilter:   *doc.UserFilter,
		Attributes:   doc.Attributes,
		GroupSearch:  doc.GroupSearch,
	}

	if doc.StartTLS != nil {
		config.StartTLS = *doc.StartTLS

		if parsed.Scheme == "ldaps" && config.StartTLS {
			return nil, fmt.Errorf("start_tls does not apply to ldaps urls")
		}
	}

	if doc.CA != nil {
		if !validCAPEM(*doc.CA) {
			return nil, fmt.Errorf("ldap ca does not hold a certificate")
		}

		config.CA = *doc.CA
	}

	if doc.Realm != nil {
		config.Realm = *doc.Realm
	}

	if doc.DisplayName != nil {
		config.DisplayName = *doc.DisplayName
	}

	if doc.GroupSearch != nil {
		gs := doc.GroupSearch
		if gs.BaseDN == "" || gs.Filter == "" || gs.Attribute == "" {
			return nil, fmt.Errorf(
				"ldap group_search must define base_dn, filter and attribute")
		}

		if !strings.Contains(gs.Filter, "{dn}") && !strings.Contains(gs.Filter, "{username}") {
			return nil, fmt.Errorf(
				"ldap group_search filter must reference {dn} or {username}")
		}
	}

	return config, nil
}

func validateJWT(doc *JWTDoc) (*compiled.AuthJWT, error) {
	if doc.Issuer == nil || len(doc.Audiences) == 0 {
		return nil, fmt.Errorf("jwt provider must define issuer and audiences")
	}

	config := &compiled.AuthJWT{
		Issuer:    *doc.Issuer,
		Audiences: doc.Audiences,
	}

	if doc.JWKSURL != nil {
		if err := validateHTTPURL("jwt jwks_url", *doc.JWKSURL); err != nil {
			return nil, err
		}

		config.JWKSURL = *doc.JWKSURL
	} else if err := validateHTTPURL("jwt issuer", *doc.Issuer); err != nil {
		// Without jwks_url the issuer must be resolvable for discovery.
		return nil, err
	}

	return config, nil
}

func validateHTTPURL(what, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("invalid %s %q", what, raw)
	}

	return nil
}

func validCAPEM(bundle string) bool {
	rest := []byte(bundle)

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return false
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		if _, err := x509.ParseCertificate(block.Bytes); err == nil {
			return true
		}
	}
}
