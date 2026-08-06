---
title: "Authentication"
description: "Per-rule authentication and authorization from a plain Secret: OIDC, SAML, LDAP and JWT providers with stateless sessions."
weight: 5
---

krouter authenticates requests per route rule, through the same
[ExtensionRef filter](/docs/extensions/) mechanism as rate limiting and
the WAF. Because the configuration carries credentials (client secrets,
bind passwords, signing keys), it lives in a
[Secret](https://kubernetes.io/docs/concepts/configuration/secret/)
rather than a ConfigMap, under the single key `auth.hcl`. The Secret
lives in the route's own namespace, and the filter and the Secret it
points to always travel together:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: app
  namespace: shop
spec:
  parentRefs:
    - name: public
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /app
      filters:
        - type: ExtensionRef
          extensionRef:
            group: ""
            kind: Secret
            name: app-auth
      backendRefs:
        - name: app
          port: 8080
---
apiVersion: v1
kind: Secret
metadata:
  name: app-auth
  namespace: shop
stringData:
  auth.hcl: |
    version = 1

    auth {
      session {
        secret   = "a-random-string-of-at-least-32-bytes"
        lifetime = "12h"
      }

      provider "oidc" {
        issuer        = "https://idp.example.com"
        client_id     = "shop-app"
        client_secret = "..."
        scopes        = ["openid", "profile", "email"]
      }
    }
```

An `auth.hcl` key in a ConfigMap, or a `ratelimit.hcl`/`waf.hcl` key in a
Secret, is invalid: each key belongs to exactly one kind, and a misplaced
key rejects the reference.

## Providers

An `auth` block configures one or more `provider` blocks, at most one per
type. A request is authenticated by the first applicable source: a valid
session cookie, then a
[Bearer token](https://datatracker.ietf.org/doc/html/rfc6750) (`jwt`),
then [Basic credentials](https://datatracker.ietf.org/doc/html/rfc7617)
(`ldap`). Unauthenticated browser navigations are redirected to the login
page; everything else receives `401` with one challenge per credential
provider.

### `provider "oidc"`

[OpenID Connect](https://openid.net/developers/how-connect-works/)
authorization code flow with PKCE, for browser users:

- `issuer`: discovery base URL; the endpoints and JWKS are read from
  `<issuer>/.well-known/openid-configuration`.
- `client_id` and `client_secret`: the client registered at the provider.
- `scopes`: requested scopes (include `openid`).
- Refresh tokens, when granted, ride the session cookie and renew the
  session transparently; a refresh rejected by the provider sends the
  user back through login.

### `provider "saml"`

SAML 2.0 service provider, SP-initiated only:

- `entity_id`: this service provider's entity ID.
- `idp_metadata_url` or inline `idp_metadata`: the identity provider's
  metadata document.
- `sp_key` and `sp_certificate`: PEM material used to sign
  authentication and logout requests. The SP metadata is published on
  the reserved `saml/metadata` endpoint for registration at the IdP.
- `attributes`: maps assertion attribute names onto `email` and `groups`.
- Unsolicited (IdP-initiated) responses are rejected; front-channel
  single logout is supported in both directions.

### `provider "ldap"`

Directory-backed credentials, serving browsers through the login form and
API clients through HTTP Basic:

- `url` (`ldap://` or `ldaps://`), with optional `start_tls` and a `ca`
  PEM bundle for the directory's certificate.
- `bind_dn` and `bind_password`: the service account used to search.
- `user_base_dn` and `user_filter`: search-then-bind resolution, with
  `{username}` substituted (and escaped) in the filter.
- `realm`: the Basic challenge realm.
- `attributes` maps directory attributes onto `email` and `groups`;
  an optional `group_search` block (`base_dn`, `filter` with `{dn}`,
  `attribute`) collects groups from group entries instead.
- A valid session always outranks resent Basic credentials, so API
  clients do not trigger a directory bind on every request.

### `provider "jwt"`

Pre-issued bearer tokens, for machine-to-machine calls:

- `issuer` and `audiences`: required claim values.
- `jwks_url`: the key set used to verify signatures; only asymmetric
  algorithms are accepted.
- `jwt` needs no session and no cookies. It is also the only provider
  usable on GRPCRoute rules: gRPC clients cannot follow interactive
  logins.

Interactive providers (`oidc`, `saml`, `ldap`) accept an optional
`display_name` shown on the login page.

## Sessions and the login page

Any interactive provider requires a `session` block:

- `secret` (at least 32 bytes) keys the cookie encryption; `lifetime`
  defaults to `12h`.
- Sessions are stateless: an encrypted, authenticated cookie holds the
  identity, so any data-plane pod can validate it without shared storage
  and sessions survive configuration reloads. Changing the secret
  invalidates every session at once.

Each extension reserves a path prefix (`path_prefix`, defaulting to
`/.krouter/auth`) on the hostnames its rules serve. It shadows user
routes and hosts the login page (`login`, a chooser when several
interactive providers are configured), the provider endpoints
(`oidc/start`, `oidc/callback`, `saml/start`, `saml/acs`,
`saml/metadata`, `saml/slo`, `ldap/login`) and `logout`, which clears
the session and, for SAML, initiates single logout at the IdP.

## Authorization

An optional `authorization` block restricts authenticated identities:

```hcl
authorization {
  require {
    claim  = "groups"
    values = ["admins", "operators"]
  }
}
```

Every `require` block must be satisfied (the claim holds at least one of
the listed values). An authenticated identity failing authorization
receives `403`, never a login redirect.

## Composition and status

Several auth Secrets on one rule merge in filter list order, like
rate-limit documents: `session` and same-type `provider` blocks merge
attribute by attribute, `require` blocks concatenate (a later Secret can
only tighten authorization), and `path_prefix` is overridden. The ordered
list of referenced Secrets identifies the extension, and the session
cookie name derives from it: rules referencing the same Secrets in the
same order share sessions.

The control plane validates the merged configuration statically (at least
one provider, at most one per type, session material present when an
interactive provider is, key material well-formed) without ever calling
the identity provider. A broken reference follows the same fail-closed
contract as other extensions: the route stays accepted, `ResolvedRefs`
turns `False` with reason `InvalidExtensionRef`, and matching requests
are answered `500`.

## Enforcement order and outcomes

Authentication runs after rate limiting and before the WAF, so
unauthenticated traffic never consumes WAF CPU. CORS preflights are
exempt from authentication only (browsers send them without
credentials); every other request on the rule is enforced:

| Outcome | Response |
|---|---|
| Authenticated and authorized | Forwarded, with identity headers |
| No credentials, browser navigation, interactive provider | `302` to the login page |
| No credentials, anything else | `401` with a challenge per credential provider |
| Presented but invalid credentials | `401`, never a redirect |
| Authenticated but not authorized | `403` |
| Broken extension reference | `500` |
| Identity provider unreachable | `503`, fail closed (established sessions keep working) |

Forwarded requests carry the identity in `X-Auth-Request-User`,
`X-Auth-Request-Email` and `X-Auth-Request-Groups`; inbound values of
these headers are stripped on authenticated rules, so backends can trust
them.

See [Observability](/docs/observability/) for the decision metric and
the access-log fields recording authentication outcomes.
