package auth

import (
	"testing"

	"strings"

	"time"
)

// Reusable fixtures: a 32+ byte session secret and a valid SP key pair
// (generated once for the package tests).
const testSecret = "0123456789abcdef0123456789abcdef"

const oidcHCL = `
version = 1

auth {
  session {
    secret = "0123456789abcdef0123456789abcdef"
  }

  provider "oidc" {
    issuer    = "https://idp.example.com/realms/main"
    client_id = "krouter"
  }
}
`

// ------------------------------------------------------------- parsing --

func TestParseFullDocument(t *testing.T) {
	doc, err := Parse(`
version = 1

auth {
  session {
    secret   = "0123456789abcdef0123456789abcdef"
    lifetime = "1h"
  }

  provider "oidc" {
    issuer        = "https://idp.example.com/realms/main"
    client_id     = "krouter"
    client_secret = "hunter2"
    scopes        = ["openid", "email"]
    display_name  = "Corporate SSO"
  }

  provider "jwt" {
    issuer    = "https://idp.example.com/realms/main"
    audiences = ["my-api"]
    jwks_url  = "https://idp.example.com/jwks"
  }

  authorization {
    require {
      claim  = "groups"
      values = ["platform-team"]
    }
  }

  path_prefix = "/.custom/auth"
}
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if *doc.Session.Secret != testSecret || *doc.Session.Lifetime != time.Hour {
		t.Errorf("unexpected session: %+v", doc.Session)
	}

	if *doc.OIDC.Issuer != "https://idp.example.com/realms/main" ||
		*doc.OIDC.ClientID != "krouter" || *doc.OIDC.ClientSecret != "hunter2" ||
		len(doc.OIDC.Scopes) != 2 || *doc.OIDC.DisplayName != "Corporate SSO" {
		t.Errorf("unexpected oidc: %+v", doc.OIDC)
	}

	if *doc.JWT.Issuer == "" || len(doc.JWT.Audiences) != 1 || *doc.JWT.JWKSURL == "" {
		t.Errorf("unexpected jwt: %+v", doc.JWT)
	}

	if len(doc.Requires) != 1 || doc.Requires[0].Claim != "groups" {
		t.Errorf("unexpected requires: %+v", doc.Requires)
	}

	if *doc.PathPrefix != "/.custom/auth" {
		t.Errorf("unexpected path prefix: %v", *doc.PathPrefix)
	}
}

func TestParsePartialDocument(t *testing.T) {
	// A document MAY be partial (docs/spec/authentication.md):
	// completeness is only checked on the merged result.
	doc, err := Parse(`
version = 1

auth {
  authorization {
    require {
      claim  = "groups"
      values = ["sre"]
    }
  }
}
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if doc.Session != nil || doc.OIDC != nil || doc.JWT != nil {
		t.Errorf("unexpected document: %+v", doc)
	}

	if len(doc.Requires) != 1 {
		t.Errorf("unexpected requires: %+v", doc.Requires)
	}
}

func TestParseRejectsInvalidDocuments(t *testing.T) {
	cases := map[string]string{
		"unsupported version": "version = 2\n\nauth {}\n",
		"missing auth block":  "version = 1\n",
		"unknown field":       "version = 1\n\nauth {\n  bogus = 1\n}\n",
		"unknown provider":    "version = 1\n\nauth {\n  provider \"basic\" {}\n}\n",
		"unknown provider field": `
version = 1

auth {
  provider "jwt" {
    bogus = true
  }
}
`,
		"duplicate provider": `
version = 1

auth {
  provider "jwt" {
    issuer = "https://a"
  }

  provider "jwt" {
    issuer = "https://b"
  }
}
`,
		"bad lifetime": `
version = 1

auth {
  session {
    lifetime = "soon"
  }
}
`,
		"require without values": `
version = 1

auth {
  authorization {
    require {
      claim  = "groups"
      values = []
    }
  }
}
`,
		"root path prefix":     "version = 1\n\nauth {\n  path_prefix = \"/\"\n}\n",
		"relative path prefix": "version = 1\n\nauth {\n  path_prefix = \"auth\"\n}\n",
		"trailing slash":       "version = 1\n\nauth {\n  path_prefix = \"/auth/\"\n}\n",
	}

	for name, src := range cases {
		if _, err := Parse(src); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// ------------------------------------------------------------- merging --

func mustParse(t *testing.T, src string) *Document {
	t.Helper()

	doc, err := Parse(src)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	return doc
}

func TestMergeSingleProvider(t *testing.T) {
	config, err := Merge([]*Document{mustParse(t, oidcHCL)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config.OIDC == nil || config.OIDC.Issuer != "https://idp.example.com/realms/main" {
		t.Errorf("unexpected oidc: %+v", config.OIDC)
	}

	if config.PathPrefix != DefaultPathPrefix {
		t.Errorf("unexpected path prefix: %v", config.PathPrefix)
	}

	if config.Session == nil ||
		config.Session.LifetimeMillis != DefaultSessionLifetime.Milliseconds() {
		t.Errorf("unexpected session: %+v", config.Session)
	}
}

func TestMergeComposesProvidersAndTightens(t *testing.T) {
	// A platform document carries the provider and session key, a route
	// document adds jwt and tightens authorization
	// (docs/spec/authentication.md Resolution and status).
	base := mustParse(t, oidcHCL)
	refinement := mustParse(t, `
version = 1

auth {
  provider "jwt" {
    issuer    = "https://idp.example.com/realms/main"
    audiences = ["my-api"]
    jwks_url  = "https://idp.example.com/jwks"
  }

  authorization {
    require {
      claim  = "groups"
      values = ["platform-team"]
    }
  }
}
`)

	config, err := Merge([]*Document{base, refinement})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config.OIDC == nil || config.JWT == nil {
		t.Errorf("providers must compose: %+v", config)
	}

	if len(config.Authorization) != 1 {
		t.Errorf("unexpected authorization: %+v", config.Authorization)
	}
}

func TestMergeSameTypeAttributeWise(t *testing.T) {
	base := mustParse(t, oidcHCL)
	override := mustParse(t, `
version = 1

auth {
  provider "oidc" {
    client_secret = "rotated"
  }
}
`)

	config, err := Merge([]*Document{base, override})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config.OIDC.ClientSecret != "rotated" {
		t.Errorf("later documents must override: %+v", config.OIDC)
	}

	if config.OIDC.Issuer != "https://idp.example.com/realms/main" {
		t.Errorf("unset attributes must be inherited: %+v", config.OIDC)
	}
}

func TestMergeRequiresConcatenate(t *testing.T) {
	doc := `
version = 1

auth {
  authorization {
    require {
      claim  = "groups"
      values = ["%s"]
    }
  }
}
`
	base := mustParse(t, oidcHCL)
	first := mustParse(t, strings.Replace(doc, "%s", "one", 1))
	second := mustParse(t, strings.Replace(doc, "%s", "two", 1))

	config, err := Merge([]*Document{base, first, second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(config.Authorization) != 2 {
		t.Errorf("require blocks must concatenate: %+v", config.Authorization)
	}
}

func TestMergeRejectsIncompleteResults(t *testing.T) {
	cases := map[string]string{
		"no provider": `
version = 1

auth {
  session {
    secret = "0123456789abcdef0123456789abcdef"
  }
}
`,
		"cookie provider without session": `
version = 1

auth {
  provider "ldap" {
    url           = "ldaps://ldap.example.com:636"
    bind_dn       = "cn=krouter,dc=example,dc=com"
    bind_password = "hunter2"
    user_base_dn  = "dc=example,dc=com"
    user_filter   = "(uid={username})"
  }
}
`,
		"session with jwt only": `
version = 1

auth {
  session {
    secret = "0123456789abcdef0123456789abcdef"
  }

  provider "jwt" {
    issuer    = "https://idp.example.com"
    audiences = ["api"]
  }
}
`,
		"short session secret": `
version = 1

auth {
  session {
    secret = "short"
  }

  provider "oidc" {
    issuer    = "https://idp.example.com"
    client_id = "krouter"
  }
}
`,
		"oidc without client id": `
version = 1

auth {
  session {
    secret = "0123456789abcdef0123456789abcdef"
  }

  provider "oidc" {
    issuer = "https://idp.example.com"
  }
}
`,
		"bad issuer url": `
version = 1

auth {
  session {
    secret = "0123456789abcdef0123456789abcdef"
  }

  provider "oidc" {
    issuer    = "ldap://idp.example.com"
    client_id = "krouter"
  }
}
`,
		"jwt without audiences": `
version = 1

auth {
  provider "jwt" {
    issuer = "https://idp.example.com"
  }
}
`,
		"ldap filter without username": `
version = 1

auth {
  session {
    secret = "0123456789abcdef0123456789abcdef"
  }

  provider "ldap" {
    url           = "ldap://ldap.example.com:389"
    bind_dn       = "cn=krouter,dc=example,dc=com"
    bind_password = "hunter2"
    user_base_dn  = "dc=example,dc=com"
    user_filter   = "(uid=someone)"
  }
}
`,
		"saml without metadata": `
version = 1

auth {
  session {
    secret = "0123456789abcdef0123456789abcdef"
  }

  provider "saml" {
    entity_id = "krouter"
  }
}
`,
	}

	for name, src := range cases {
		if _, err := Merge([]*Document{mustParse(t, src)}); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
