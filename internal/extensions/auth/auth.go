// Package auth implements the `auth.hcl` extension documents, their
// merge semantics, and the per-rule enforcement they configure
// (docs/spec/authentication.md). Documents are partial by design: they
// merge in filter list order, a later document overriding the
// attributes it sets, nested blocks replacing as a unit, and `require`
// blocks concatenating. The merged result MUST configure at least one
// provider, at most one of each type.
package auth

import (
	"fmt"

	"strings"

	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclsimple"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// DefaultPathPrefix hosts the reserved endpoints when `path_prefix` is
// not set (docs/spec/authentication.md Reserved path prefix).
const DefaultPathPrefix = "/.krouter/auth"

// DefaultSessionLifetime caps sessions absolutely when `lifetime` is
// not set (docs/spec/authentication.md).
const DefaultSessionLifetime = 12 * time.Hour

// MinSessionSecretBytes is the entropy floor of `session.secret`
// (docs/spec/authentication.md).
const MinSessionSecretBytes = 32

// Document is one parsed auth.hcl. Every attribute is optional so
// documents compose; validation of the merged result happens in Merge.
type Document struct {
	Session    *SessionDoc
	OIDC       *OIDCDoc
	SAML       *SAMLDoc
	LDAP       *LDAPDoc
	JWT        *JWTDoc
	Requires   []compiled.AuthRequire
	PathPrefix *string
}

type SessionDoc struct {
	Secret   *string
	Lifetime *time.Duration
}

type OIDCDoc struct {
	Issuer       *string
	ClientID     *string
	ClientSecret *string
	Scopes       []string
	DisplayName  *string
}

type SAMLDoc struct {
	EntityID       *string
	IDPMetadataURL *string
	IDPMetadata    *string
	SPKey          *string
	SPCertificate  *string
	Attributes     map[string]string
	DisplayName    *string
}

type LDAPDoc struct {
	URL          *string
	StartTLS     *bool
	CA           *string
	BindDN       *string
	BindPassword *string
	UserBaseDN   *string
	UserFilter   *string
	Realm        *string
	Attributes   map[string]string
	GroupSearch  *compiled.AuthGroupSearch
	DisplayName  *string
}

type JWTDoc struct {
	Issuer    *string
	Audiences []string
	JWKSURL   *string
}

// ------------------------------------------------------------ hcl schema --

type hclDocument struct {
	Version int      `hcl:"version"`
	Auth    *hclAuth `hcl:"auth,block"`
}

type hclAuth struct {
	Session       *hclSession       `hcl:"session,block"`
	Providers     []hclProvider     `hcl:"provider,block"`
	Authorization *hclAuthorization `hcl:"authorization,block"`
	PathPrefix    *string           `hcl:"path_prefix,optional"`
}

type hclSession struct {
	Secret   *string `hcl:"secret,optional"`
	Lifetime *string `hcl:"lifetime,optional"`
}

// hclProvider is a labeled block: `provider "oidc" { ... }`. The body
// is decoded against the schema its label selects.
type hclProvider struct {
	Type string   `hcl:"type,label"`
	Body hcl.Body `hcl:",remain"`
}

type hclOIDC struct {
	Issuer       *string  `hcl:"issuer,optional"`
	ClientID     *string  `hcl:"client_id,optional"`
	ClientSecret *string  `hcl:"client_secret,optional"`
	Scopes       []string `hcl:"scopes,optional"`
	DisplayName  *string  `hcl:"display_name,optional"`
}

type hclSAML struct {
	EntityID       *string        `hcl:"entity_id,optional"`
	IDPMetadataURL *string        `hcl:"idp_metadata_url,optional"`
	IDPMetadata    *string        `hcl:"idp_metadata,optional"`
	SPKey          *string        `hcl:"sp_key,optional"`
	SPCertificate  *string        `hcl:"sp_certificate,optional"`
	Attributes     *hclAttributes `hcl:"attributes,block"`
	DisplayName    *string        `hcl:"display_name,optional"`
}

type hclLDAP struct {
	URL          *string         `hcl:"url,optional"`
	StartTLS     *bool           `hcl:"start_tls,optional"`
	CA           *string         `hcl:"ca,optional"`
	BindDN       *string         `hcl:"bind_dn,optional"`
	BindPassword *string         `hcl:"bind_password,optional"`
	UserBaseDN   *string         `hcl:"user_base_dn,optional"`
	UserFilter   *string         `hcl:"user_filter,optional"`
	Realm        *string         `hcl:"realm,optional"`
	Attributes   *hclAttributes  `hcl:"attributes,block"`
	GroupSearch  *hclGroupSearch `hcl:"group_search,block"`
	DisplayName  *string         `hcl:"display_name,optional"`
}

type hclAttributes struct {
	Email  *string `hcl:"email,optional"`
	Groups *string `hcl:"groups,optional"`
}

type hclGroupSearch struct {
	BaseDN    string `hcl:"base_dn"`
	Filter    string `hcl:"filter"`
	Attribute string `hcl:"attribute"`
}

type hclJWT struct {
	Issuer    *string  `hcl:"issuer,optional"`
	Audiences []string `hcl:"audiences,optional"`
	JWKSURL   *string  `hcl:"jwks_url,optional"`
}

type hclAuthorization struct {
	Requires []hclRequire `hcl:"require,block"`
}

type hclRequire struct {
	Claim  string   `hcl:"claim"`
	Values []string `hcl:"values"`
}

// Parse decodes one auth.hcl document (HCL native syntax, unknown or
// invalid fields rejected). Attribute values are validated here;
// completeness is only checked after Merge.
func Parse(src string) (*Document, error) {
	raw := &hclDocument{}
	if err := hclsimple.Decode("auth.hcl", []byte(src), nil, raw); err != nil {
		return nil, err
	}

	if raw.Version != 1 {
		return nil, fmt.Errorf("unsupported version %d", raw.Version)
	}

	if raw.Auth == nil {
		return nil, fmt.Errorf("missing auth block")
	}

	doc := &Document{PathPrefix: raw.Auth.PathPrefix}

	if raw.Auth.Session != nil {
		doc.Session = &SessionDoc{Secret: raw.Auth.Session.Secret}

		if raw.Auth.Session.Lifetime != nil {
			lifetime, err := time.ParseDuration(*raw.Auth.Session.Lifetime)
			if err != nil || lifetime <= 0 {
				return nil, fmt.Errorf("invalid session lifetime %q", *raw.Auth.Session.Lifetime)
			}

			doc.Session.Lifetime = &lifetime
		}
	}

	for _, provider := range raw.Auth.Providers {
		if err := doc.decodeProvider(provider); err != nil {
			return nil, err
		}
	}

	if raw.Auth.Authorization != nil {
		for _, require := range raw.Auth.Authorization.Requires {
			if require.Claim == "" || len(require.Values) == 0 {
				return nil, fmt.Errorf("require blocks need a claim and values")
			}

			doc.Requires = append(doc.Requires, compiled.AuthRequire{
				Claim:  require.Claim,
				Values: require.Values,
			})
		}
	}

	if doc.PathPrefix != nil {
		prefix := *doc.PathPrefix
		if !strings.HasPrefix(prefix, "/") || prefix == "/" || strings.HasSuffix(prefix, "/") {
			return nil, fmt.Errorf("invalid path_prefix %q", prefix)
		}
	}

	return doc, nil
}

// decodeProvider decodes one labeled provider block against the schema
// its label selects; a document MUST NOT repeat a label.
func (d *Document) decodeProvider(provider hclProvider) error {
	decode := func(target any) error {
		if diags := gohcl.DecodeBody(provider.Body, nil, target); diags.HasErrors() {
			return fmt.Errorf("provider %q: %s", provider.Type, diags.Error())
		}

		return nil
	}

	switch provider.Type {
	case "oidc":
		if d.OIDC != nil {
			return fmt.Errorf("duplicate provider %q", provider.Type)
		}

		raw := &hclOIDC{}
		if err := decode(raw); err != nil {
			return err
		}

		d.OIDC = &OIDCDoc{
			Issuer:       raw.Issuer,
			ClientID:     raw.ClientID,
			ClientSecret: raw.ClientSecret,
			Scopes:       raw.Scopes,
			DisplayName:  raw.DisplayName,
		}

	case "saml":
		if d.SAML != nil {
			return fmt.Errorf("duplicate provider %q", provider.Type)
		}

		raw := &hclSAML{}
		if err := decode(raw); err != nil {
			return err
		}

		d.SAML = &SAMLDoc{
			EntityID:       raw.EntityID,
			IDPMetadataURL: raw.IDPMetadataURL,
			IDPMetadata:    raw.IDPMetadata,
			SPKey:          raw.SPKey,
			SPCertificate:  raw.SPCertificate,
			Attributes:     raw.Attributes.toMap(),
			DisplayName:    raw.DisplayName,
		}

	case "ldap":
		if d.LDAP != nil {
			return fmt.Errorf("duplicate provider %q", provider.Type)
		}

		raw := &hclLDAP{}
		if err := decode(raw); err != nil {
			return err
		}

		d.LDAP = &LDAPDoc{
			URL:          raw.URL,
			StartTLS:     raw.StartTLS,
			CA:           raw.CA,
			BindDN:       raw.BindDN,
			BindPassword: raw.BindPassword,
			UserBaseDN:   raw.UserBaseDN,
			UserFilter:   raw.UserFilter,
			Realm:        raw.Realm,
			Attributes:   raw.Attributes.toMap(),
			DisplayName:  raw.DisplayName,
		}

		if raw.GroupSearch != nil {
			d.LDAP.GroupSearch = &compiled.AuthGroupSearch{
				BaseDN:    raw.GroupSearch.BaseDN,
				Filter:    raw.GroupSearch.Filter,
				Attribute: raw.GroupSearch.Attribute,
			}
		}

	case "jwt":
		if d.JWT != nil {
			return fmt.Errorf("duplicate provider %q", provider.Type)
		}

		raw := &hclJWT{}
		if err := decode(raw); err != nil {
			return err
		}

		d.JWT = &JWTDoc{
			Issuer:    raw.Issuer,
			Audiences: raw.Audiences,
			JWKSURL:   raw.JWKSURL,
		}

	default:
		return fmt.Errorf("unknown provider type %q", provider.Type)
	}

	return nil
}

func (a *hclAttributes) toMap() map[string]string {
	if a == nil {
		return nil
	}

	attributes := map[string]string{}
	if a.Email != nil {
		attributes["email"] = *a.Email
	}

	if a.Groups != nil {
		attributes["groups"] = *a.Groups
	}

	return attributes
}
