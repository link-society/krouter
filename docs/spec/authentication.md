# Authentication

krouter authenticates and authorizes requests per route rule through the
`ExtensionRef` filter mechanism (docs/spec/extensions.md), supporting
four provider types: OpenID Connect, SAML 2.0, LDAP, and bearer JWT
validation. A rule MAY combine several providers, at most one of each
type: browser clients pick theirs on a gateway-served login page, API
clients are matched by the credentials they present.

The feature is stateless by construction: after a successful login,
krouter mints a self-contained encrypted session cookie, and every
subsequent request carries it. No session state is shared between
data-plane pods and none is stored server-side, so any pod can serve any
request of any session, pods can be replaced without logging users out,
and the data plane keeps design principle 5 of docs/spec/overview.md.
The costs of statelessness are documented where they apply: session size
is bounded by the cookie budget, a session cannot be revoked server-side
before it expires, and single logout is limited to front-channel flows.

## The auth extension

Authentication configuration carries credentials (client secrets, bind
passwords, private keys, the session key), so it lives in a core Secret,
not a ConfigMap. A rule opts in by referencing the Secret with an
`ExtensionRef` filter:

```yaml
filters:
  - type: ExtensionRef
    extensionRef:
      group: ""
      kind: Secret
      name: my-auth
```

The Secret lives in the route's namespace and carries exactly the key
`auth.hcl` (docs/spec/extensions.md for the kind and key matrix):

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-auth
  namespace: my-app
stringData:
  auth.hcl: |
    version = 1

    auth {
      session {
        secret   = "c545ba9d..."  # at least 32 bytes of entropy
        lifetime = "12h"
      }

      provider "oidc" {
        issuer        = "https://idp.example.com/realms/main"
        client_id     = "krouter"
        client_secret = "..."
        scopes        = ["openid", "profile", "email"]
      }

      authorization {
        require {
          claim  = "groups"
          values = ["platform-team"]
        }
      }
    }
```

`auth.hcl` schema (HCL native syntax, unknown or invalid fields
rejected, like every krouter HCL document): one required `auth` block
containing:

- one or more `provider` blocks, labeled `"oidc"`, `"saml"`, `"ldap"`,
  or `"jwt"` (see their sections below), at most one per label:
  same-label blocks merge (see Resolution and status), so one rule
  cannot serve two providers of the same type;
- `session`: required when a cookie provider (`oidc`, `saml`, or
  `ldap`) is configured; invalid when `jwt` is the only provider,
  since bearer validation keeps no session. `secret` MUST hold at
  least 32 bytes; `lifetime` is a Go duration, default `12h`;
- `authorization`: optional (see Authorization);
- `path_prefix`: optional, default `/.krouter/auth` (see Reserved path
  prefix). MUST start with `/` and MUST NOT be `/`.

These requirements hold on the merged result of the documents reaching
a rule (see Resolution and status), not on each document alone: a
single document MAY be partial, like a `ratelimit.hcl` fragment.

## Resolution and status

The resolution rules of docs/spec/extensions.md apply, with these
additions:

- The `auth.hcl` documents reaching a rule merge in filter list order
  into one effective configuration, called the extension below and
  identified by the ordered list of referenced Secrets: `session` and
  same-label `provider` blocks merge attribute by attribute (a later
  document overrides the attributes it sets and inherits the rest;
  nested blocks such as `attributes` or `group_search` are replaced as
  a unit), `authorization` `require` blocks concatenate (a later
  document can only tighten access), and `path_prefix` is overridden
  wholesale. This is the base-plus-refinement modularity of
  `ratelimit.hcl`: a platform-owned Secret can carry the identity
  provider, its credentials, and the session key, and a route-owned
  one the route's claim requirements.
- The merged configuration MUST configure at least one provider.
  Documents MAY bring different provider types to one rule: the
  providers compose (see Provider selection), so a platform Secret can
  carry the corporate OIDC provider and a route Secret add `jwt` for
  the same rule's API clients. Auth composes freely with
  `ratelimit.hcl` and `waf.hcl` extensions on the same rule.
- On GRPCRoute rules only the `jwt` provider is valid: redirect, form,
  and Basic flows have no meaning for gRPC clients. A merged
  configuration bringing any other provider to a GRPCRoute rule
  follows the `InvalidExtensionRef` handling.
- Status messages MUST name the Secret and describe the error but MUST
  NOT quote Secret contents (docs/spec/security.md).

As for every extension, a broken reference fails closed: requests
matching the affected rule are answered `500 Internal Server Error`
(`INTERNAL` on gRPC rules), never forwarded unauthenticated.

## Configuration lifecycle

Auth Secrets follow the extension lifecycle of docs/spec/extensions.md
(content-addressed generations, atomic activation, last-valid behavior),
with two specifics:

- The control plane validates the documents statically at compile time:
  schema, at least one provider on the merged result, well-formed URLs,
  parseable key material, session secret length. It MUST NOT contact
  identity
  providers, metadata endpoints, JWKS endpoints, or directories during
  reconciliation: reachability is a runtime property, and
  reconciliation MUST NOT depend on the uptime of external systems.
  Discovery documents, SAML metadata, and JWKS are fetched and cached
  by each data-plane pod.
- Compiled authentication configuration is sensitive: it MUST be
  carried by the generation's generated Secret
  (docs/spec/configuration.md), never by compiled ConfigMaps;
  attachment ConfigMaps reference it by checksum like every other
  generation object. The data plane already reads generated Secrets and
  needs no new permission (docs/spec/security.md).

Sessions MUST survive configuration reloads: a cookie is validated
against the current key material and lifetime only, never against a
generation identity, so editing routes or unrelated settings does not
log users out. Changing `session.secret` invalidates every session of
that extension; graceful key rotation (accepting the previous key while
minting with the new one) is deferred work.

## Stateless sessions

A successful `oidc`, `saml`, or `ldap` authentication mints a session
cookie containing everything later requests need: the principal, the
provider that authenticated it (logout dispatches on it), the claims
consumed by authorization rules and identity headers, expiry, and,
when applicable, the OIDC refresh token and the SAML logout references
(NameID and SessionIndex).

- Sessions MUST be protected by authenticated encryption keyed from
  `session.secret`: contents are not readable by the client, and a
  tampered or undecryptable cookie is treated as no session.
- Cookie names MUST be stable for a given extension (the ordered list
  of referenced Secrets: their identities, not their contents, so
  edits do not log users out) and distinct between extensions: several
  auth extensions MAY protect different rules of one hostname without
  interfering. A session is accepted only by rules referencing the
  extension that minted it.
- Cookies MUST be `HttpOnly`, MUST be `Secure` on HTTPS listeners, and
  MUST use `SameSite=Lax`, except where a flow requires cross-site
  delivery (the SAML POST callback, see below).
- The session MUST carry only the claims that the extension's
  authorization rules and the identity headers consume, and MAY be
  split across numbered cookie chunks. An identity that exceeds the
  bounded cookie budget even after this pruning fails authentication
  with a logged error; it MUST NOT produce a truncated session.
- `session.lifetime` caps the session absolutely; on expiry the client
  re-authenticates (silently when the provider still holds a live IdP
  session).
- A stateless session cannot be revoked server-side before it expires.
  Operators SHOULD size `session.lifetime` to their revocation needs.
  Logout (below) clears cookies on the browser performing it.

Session validation is local cookie decryption: requests inside a valid
session require no provider round trip, so a provider outage does not
affect already-authenticated users until refresh or expiry.

## Reserved path prefix

Browser flows need endpoints that krouter itself answers. They live
under `path_prefix` (default `/.krouter/auth`):

| Path | Methods | Role |
|---|---|---|
| `<prefix>/login` | GET | Login page: provider chooser and LDAP credential form |
| `<prefix>/oidc/start` | GET | Begins the OIDC authorization redirect |
| `<prefix>/oidc/callback` | GET | OIDC redirect URI |
| `<prefix>/saml/start` | GET | Begins the SAML AuthnRequest redirect |
| `<prefix>/saml/acs` | POST | SAML assertion consumer service |
| `<prefix>/saml/metadata` | GET | SAML SP metadata document |
| `<prefix>/saml/slo` | GET, POST | SAML single logout endpoint |
| `<prefix>/ldap/login` | POST | LDAP credential form target |
| `<prefix>/logout` | GET | Session termination (all cookie providers) |

Protocol endpoints are namespaced by the provider they serve; `login`
and `logout` are not, since they operate on the extension's session
and provider set rather than on one provider's flow.

- On every hostname under which an accepted rule carrying a cookie
  provider (`oidc`, `saml`, or `ldap`) is served, requests under that
  extension's prefix are answered by the gateway itself and MUST NOT
  reach user routes: the prefix shadows them. Hostnames without such a
  rule, and rules whose only provider is `jwt`, trigger no
  interception.
- Several extensions MAY share a hostname, and even a prefix: flows are
  disambiguated by the extension identity carried in the state and
  session cookies.
- These endpoints match no route rule, so rule extensions (rate
  limiting, WAF) do not apply to them. They MUST bound request sizes,
  enforce the expected content types, and require the in-flight state
  cookie where one is defined.

### Login page

`<prefix>/login` is where unauthenticated browser navigations are sent
(see Request path integration). It serves a minimal, self-contained
page (no external assets), listing the extension's interactive
providers: a link per `oidc` and `saml` provider starting its flow
through the provider's start endpoint, and a username and password
form when `ldap` is configured. `jwt` never appears: bearer clients do
not navigate. Entries are labeled by the provider's optional
`display_name` attribute, defaulting to the provider type name. Login
page branding is deferred work (docs/spec/overview.md).

When the extension configures exactly one interactive provider and it
is `oidc` or `saml`, the login page skips the chooser and starts that
provider's flow directly: single-provider rules keep the
direct-to-provider experience. An `ldap` credential form is never
skipped.

The LDAP form POSTs to `<prefix>/ldap/login`. The POST MUST carry the
in-flight state cookie and the anti-forgery token embedded in the
form, both set when the login page was served: a POST without them is
rejected, so a third-party site cannot submit credentials on a user's
behalf. A failed bind re-renders the form with a generic failure
notice naming neither the reason nor the directory.

### In-flight login state

Serving the login page (or starting a flow directly) sets a
short-lived state cookie holding the extension identity, the return
URL, and the login form's anti-forgery token; starting a provider flow
adds that flow's anti-forgery material (OIDC `state`, `nonce`, and
PKCE verifier; the SAML request ID). The callback endpoints and the
LDAP form target require it, verify it, and consume it; flows older
than a short validity window (10 minutes) are rejected. The return
URL records path and query only and is applied to the request's own
authority: cross-origin post-login redirects are not expressible.

## OpenID Connect

```hcl
provider "oidc" {
  issuer        = "https://idp.example.com/realms/main"
  client_id     = "krouter"
  client_secret = "..."
  scopes        = ["openid", "profile", "email"]
}
```

- Authorization code flow with PKCE (S256), `state`, and `nonce`; all
  three MUST be used and verified.
- Endpoints and signing keys come from the issuer's discovery document;
  each data-plane pod caches them and refreshes periodically and on
  signature key misses, at a bounded rate.
- The redirect URI is `https://<host><prefix>/oidc/callback` for each
  hostname the protected rules serve; operators MUST register every one
  of them with the provider.
- ID token validation covers signature, issuer, audience, expiry (with
  bounded clock skew), and nonce. Claims come from the ID token;
  UserInfo retrieval is deferred work.
- The `user` claim is `sub`; every other ID token claim is available to
  authorization rules and identity headers under its own name.
- When the provider grants a refresh token (for example through the
  `offline_access` scope), it is carried encrypted in the session. A
  request arriving after token expiry but within `session.lifetime`
  triggers a transparent refresh and re-mints the cookie. Refresh
  failures, including refresh token rotation races between pods sharing
  one session, MUST degrade to a new authorization redirect, never to
  an error response.

## SAML 2.0

```hcl
provider "saml" {
  entity_id        = "krouter-apps"
  idp_metadata_url = "https://idp.example.com/saml/metadata"

  sp_key = <<-EOT
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
  EOT

  sp_certificate = <<-EOT
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
  EOT

  attributes {
    email  = "mail"
    groups = "groups"
  }
}
```

- IdP metadata comes from `idp_metadata_url`, fetched and cached by
  each data-plane pod, or inline from `idp_metadata`; exactly one of
  the two MUST be set.
- krouter is the service provider, SP-initiated only: AuthnRequests use
  the HTTP-Redirect binding and are signed with `sp_key`; assertions
  arrive at the ACS over the HTTP-POST binding. The state cookie for
  the POST callback uses `SameSite=None; Secure`, since the IdP posts
  cross-site.
- Unsolicited (IdP-initiated) responses MUST be rejected:
  `InResponseTo` MUST match the in-flight request ID from the state
  cookie. Together with the assertion validity window this is the
  stateless replay defense; a cross-pod replay cache does not exist by
  design.
- Assertion validation covers the signature against the IdP metadata
  certificates, the audience (`entity_id`), destination and recipient
  (the request host's ACS URL), and the validity window with bounded
  clock skew. Encrypted assertions are deferred work; assertions are
  protected by TLS in transit.
- The NameID becomes the `user` claim; the `attributes` block maps
  claim names to assertion attribute names.
- `<prefix>/saml/metadata` serves the SP metadata document, reflecting
  the ACS and SLO URLs of the host it is fetched from. A rule serving
  several hostnames needs a provider that accepts several ACS URLs;
  otherwise operators SHOULD scope the rule to one hostname.

## LDAP

```hcl
provider "ldap" {
  url           = "ldaps://ldap.example.com:636"
  bind_dn       = "cn=krouter,ou=services,dc=example,dc=com"
  bind_password = "..."
  user_base_dn  = "ou=people,dc=example,dc=com"
  user_filter   = "(uid={username})"

  attributes {
    email  = "mail"
    groups = "memberOf"
  }
}
```

- Browser navigations collect credentials through the login form of
  `<prefix>/login` (see Login page). Other requests are answered
  `401 Unauthorized` with a `WWW-Authenticate: Basic` challenge (realm
  from the optional `realm` attribute), and a presented
  `Authorization: Basic` header authenticates the request directly:
  API clients under an `ldap` provider work without cookies.
- Search-then-bind: krouter binds as `bind_dn`, searches `user_base_dn`
  with `user_filter` (`{username}` substituted with the presented name,
  escaped per RFC 4515), and requires exactly one result; it then binds
  as the found DN with the presented password. Zero or several matches,
  or a failed bind, answer the Basic challenge again (or re-render the
  login form, for form logins).
- A successful bind mints the session cookie, and a valid session
  outranks a resent `Authorization` header, so browsers (which cache
  and resend Basic credentials on every request) do not re-bind.
  Clients that ignore cookies bind on every request; verified
  credentials MUST NOT be cached beyond the session cookie.
- The presented username becomes the `user` claim; the `attributes`
  block maps claim names to user entry attributes. Group membership
  comes from a group-valued attribute (such as `memberOf`), or from an
  optional `group_search` block for directories without one:

  ```hcl
  group_search {
    base_dn   = "ou=groups,dc=example,dc=com"
    filter    = "(member={dn})"
    attribute = "cn"
  }
  ```

  `{dn}` and `{username}` substitutions are escaped per RFC 4515; the
  named attribute of every matching entry contributes to the `groups`
  claim. When both sources are configured, their results merge.
- `url` accepts `ldap://` and `ldaps://`; `start_tls = true` upgrades
  an `ldap://` connection before any credential is sent. The optional
  `ca` attribute (PEM) overrides the system roots for the directory
  connection. Plaintext `ldap://` without StartTLS SHOULD NOT be used.
- Directory operations MUST be bounded by timeouts; an unreachable
  directory fails closed (see Request path integration).

## Bearer JWT

```hcl
provider "jwt" {
  issuer    = "https://idp.example.com/realms/main"
  audiences = ["my-api"]
}
```

- `jwt` authenticates requests carrying `Authorization: Bearer
  <token>`. An invalid token, or a missing one when `jwt` is the only
  provider, is answered `401 Unauthorized` with the `WWW-Authenticate:
  Bearer` challenge of RFC 6750 (`UNAUTHENTICATED` on GRPCRoute
  rules). No cookie is read or written and no redirect is ever issued:
  this is the provider for API and gRPC clients.
- Validation covers the signature, `iss` against `issuer`, `exp` and
  `nbf` with bounded clock skew, and `aud` intersecting `audiences`.
  Tokens signed with `none` or with symmetric algorithms MUST be
  rejected.
- Signing keys come from the optional `jwks_url`, or from the issuer's
  discovery document when the attribute is absent; each data-plane pod
  caches them, refreshing periodically and on unknown key identifiers
  at a bounded rate. When no usable key set is available, the rule
  fails closed.
- The `user` claim is `sub`; every token claim is available to
  authorization rules and identity headers.

## Authorization

```hcl
authorization {
  require {
    claim  = "groups"
    values = ["platform-team", "sre"]
  }
}
```

- Zero or more `require` blocks; a request is authorized when every
  block passes. A block passes when the named claim exists and at least
  one of its values equals one of the listed `values`. List-valued
  claims compare per element; scalar claims compare in canonical string
  form (`"true"`, `"42"`).
- Without an `authorization` block, any authenticated principal is
  authorized.
- An authenticated but unauthorized request is answered `403 Forbidden`
  (`PERMISSION_DENIED` on gRPC rules). It MUST NOT trigger a login
  redirect: re-authenticating cannot change the outcome and would loop.

## Identity headers

For an authenticated and authorized request, krouter injects the
identity into the proxied request:

| Header | Contents |
|---|---|
| `X-Auth-Request-User` | The `user` claim |
| `X-Auth-Request-Email` | The `email` claim |
| `X-Auth-Request-Groups` | The `groups` claim, comma-separated |

Headers whose claim is absent are omitted. These three headers MUST be
stripped from every incoming request matching an auth-enabled rule,
whatever the outcome: a client can never smuggle them past the gateway.
Rules without an auth extension do not strip them, so operators MUST
NOT expose one backend through both an authenticated and an
unauthenticated rule unless the backend ignores these headers. Custom
claim-to-header mappings are deferred work.

## Request path integration

Authentication runs inside the extension enforcement chain of
docs/spec/extensions.md: after rate limiting, before the WAF. Session
and token validation are local cryptography on most requests, denied
clients spend no WAF CPU, and on protected rules the WAF only ever
inspects authenticated traffic.

One exemption: CORS preflight requests (docs/spec/traffic.md) on rules
carrying a `CORS` filter MUST skip authentication and continue down the
chain, because browsers never attach credentials to preflights. They
remain subject to rate limiting and WAF inspection.

### Provider selection

With several providers on one rule, the request's own shape selects
one; nothing is ambiguous at request time:

1. A valid session cookie of the extension authenticates the request,
   whichever cookie provider minted it.
2. An `Authorization: Bearer` header is validated by the `jwt`
   provider, when one is configured.
3. An `Authorization: Basic` header is validated by the `ldap`
   provider, when one is configured.
4. Anything else is unauthenticated: browser navigations are
   redirected to the login page, everything else is answered `401`
   with one challenge per credential-consuming provider (`Bearer` for
   `jwt`, `Basic` for `ldap`).

Presented credentials that fail validation are answered `401`, never
redirected: a bad bearer token on a rule that also carries `oidc` MUST
NOT bounce an API client to the identity provider. An invalid or
expired session cookie, on the other hand, is treated as no session:
browsers land on the login page again.

Outcomes:

| Outcome | HTTP | gRPC |
|---|---|---|
| No session, redirect possible | `302` to the login page | never (`jwt` only) |
| No session or failed credentials otherwise | `401` with the provider challenges | `UNAUTHENTICATED` |
| Authenticated, authorization failed | `403` | `PERMISSION_DENIED` |
| Broken extension reference | `500` | `INTERNAL` |
| Provider, metadata, JWKS, or directory unreachable | `503` | `UNAVAILABLE` |

- A redirect is possible when a cookie provider is configured and the
  request looks like a top-level browser navigation: method `GET` or
  `HEAD` with an `Accept` header including `text/html`. Everything
  else receives `401`, so API calls under browser providers fail fast
  instead of bouncing through the login page.
- Authentication failures MUST fail closed, never open. Established
  sessions keep working through a provider outage, since their
  validation is local.
- A request rejected by authentication or authorization MUST NOT be
  mirrored, redirected, answered with CORS headers (preflights
  excepted, above), or forwarded.
- WebSocket upgrades are enforced on the handshake request, which
  carries the session cookie or bearer token like any other request;
  in-tunnel enforcement stays deferred (docs/spec/extensions.md).
- Expiry is evaluated per request; responses and tunnels in flight are
  not interrupted when a session expires under them.

## Logout and single logout

`<prefix>/logout` clears the extension's session cookies for the
request's host; the provider recorded in the session decides what
follows:

- `saml`, when the IdP metadata advertises an SLO endpoint: redirects
  there with a signed LogoutRequest (HTTP-Redirect binding) built from
  the NameID and SessionIndex stored in the session, completing
  RP-initiated single logout. The LogoutResponse returns to
  `<prefix>/saml/slo`.
- `oidc`, when the discovery document advertises an end-session
  endpoint: redirects there with the client identity and a post-logout
  return to the request's host. The session does not carry the raw ID
  token (the cookie budget forbids it), so `id_token_hint` is not sent;
  carrying the hint is deferred work.
- Otherwise: redirects to `/`.

`<prefix>/saml/slo` also accepts IdP-initiated front-channel
LogoutRequests: they arrive through the user's browser, so krouter can
clear the session cookie it could never reach server-side, and answers
with a signed LogoutResponse over the requested binding. Back-channel
logout (SAML SOAP, OIDC back-channel) is deferred work: without shared
session state, a server-to-server message cannot reach a cookie.

For `ldap`, logout clears the session cookie; browsers that cache Basic
credentials will transparently re-authenticate on the next challenge.

## Observability

- `krouter_dataplane_auth_decisions_total{provider,result}` with
  provider `oidc`, `saml`, `ldap`, or `jwt` and result `allowed`,
  `unauthenticated`, `forbidden`, or `error`.
- On auth-enabled rules, the access log carries the authenticated
  `user` claim when one is known; rejected requests name the `auth`
  extension and the result class, like rate limiting and WAF denials.
- Tokens, assertions, credentials, cookies, and session contents MUST
  NOT appear in logs, metrics, or status messages
  (docs/spec/security.md). The label rules of
  docs/spec/observability.md apply: no principals, client keys, or
  paths as metric labels.

## Verification

End-to-end tests MUST cover, against mock providers and directories:

- OIDC: the full redirect round trip (`state`, `nonce`, and PKCE
  verified), session minting, identity headers on the proxied request,
  transparent refresh, logout, and the `401` answer for non-navigation
  requests.
- Sessions: validity across a configuration reload and across
  data-plane pod replacement (the statelessness proof), rejection of
  tampered cookies, and expiry.
- SAML: login through the POST ACS, rejection of unsolicited
  assertions, the SP metadata document, and front-channel single logout
  in both directions.
- LDAP: the Basic challenge, search-then-bind success, wrong-password
  rejection, and group-based authorization.
- Bearer JWT: acceptance and rejection (expired, wrong audience, wrong
  issuer, `none` algorithm) on HTTPRoute and GRPCRoute rules, with RFC
  6750 challenges and gRPC statuses.
- Composition: a base Secret carrying the provider and session key
  refined by a route Secret tightening authorization, merged in filter
  order.
- Multi-provider rules: the login page lists the configured providers
  and each listed flow completes; with a single `oidc` provider the
  login page forwards without a chooser; `jwt` and `oidc` coexist on
  one rule with bearer requests answered `401`, never redirected.
- The login form: a successful POST mints a session, a POST without
  the state cookie and anti-forgery token is rejected, and a failed
  bind re-renders the form.
- Authorization: `403` for authenticated principals failing claim
  rules, with no redirect loop.
- Identity header stripping: client-supplied `X-Auth-Request-*` headers
  never reach backends on auth-enabled rules.
- Fail-closed behavior: broken or missing Secrets, `auth.hcl` in a
  ConfigMap, a merged configuration with no `provider` block, and
  non-`jwt` providers on GRPCRoute rules (all following the
  `InvalidExtensionRef` handling), plus an unreachable provider
  answering `503` while established sessions keep working.
- WebSocket: handshake enforcement with and without a valid session.
