---
title: "Authentication"
description: "Put a login in front of an application: directory-backed credentials, group authorization, identity headers, and bearer tokens for APIs."
weight: 10
params:
  level: "Advanced"
---

**Use case:** you want authentication in front of an application: a login
form for browsers, HTTP Basic for scripts, group-based authorization, and
bearer tokens for machine clients, without touching the application
itself.

This tutorial reuses the `hello` Service and `edge` Gateway from
[Hello, HTTP](/docs/tutorials/hello-http/). The `hello` backend echoes
the request it receives, which is handy for seeing identity headers.

## 1. Deploy a directory

Authentication needs an identity source. To keep the tutorial
self-contained we deploy [GLAuth](https://glauth.github.io), a tiny LDAP
server configured from a file; in production this would be your existing
LDAP or Active Directory:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: directory-config
data:
  config.cfg: |
    [ldap]
      enabled = true
      listen = "0.0.0.0:3893"

    [ldaps]
      enabled = false

    [backend]
      datastore = "config"
      baseDN = "dc=example,dc=com"

    [[users]]
      name = "svc-krouter"
      uidnumber = 5000
      primarygroup = 5500
      passsha256 = "266739a274b3d2030954f1b943135d2116afe09e1a9f9d287d70bbd43ae94515"
        [[users.capabilities]]
        action = "search"
        object = "*"

    [[users]]
      name = "alice"
      mail = "alice@example.com"
      uidnumber = 5001
      primarygroup = 5501
      passsha256 = "17a96502d336e4c18a43182a353d7f0a38414c6fc4daf678acae834a819cecee"

    [[users]]
      name = "bob"
      mail = "bob@example.com"
      uidnumber = 5002
      primarygroup = 5502
      passsha256 = "df53c27a66157885ba143e34f25d6380e12168b0f7da4f0c46efa54cd9a083b7"

    [[groups]]
      name = "svcaccts"
      gidnumber = 5500

    [[groups]]
      name = "platform-team"
      gidnumber = 5501

    [[groups]]
      name = "contractors"
      gidnumber = 5502
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: directory
spec:
  replicas: 1
  selector:
    matchLabels:
      app: directory
  template:
    metadata:
      labels:
        app: directory
    spec:
      containers:
        - name: glauth
          image: glauth/glauth:v2.4.0
          args: ["-c", "/app/config/config.cfg"]
          ports:
            - containerPort: 3893
          volumeMounts:
            - name: config
              mountPath: /app/config
              readOnly: true
      volumes:
        - name: config
          configMap:
            name: directory-config
---
apiVersion: v1
kind: Service
metadata:
  name: directory
spec:
  selector:
    app: directory
  ports:
    - port: 3893
```

Three accounts: `svc-krouter` (the service account krouter binds with,
password `svc-secret`), `alice` (`alice-password`, in `platform-team`)
and `bob` (`bob-password`, in `contractors`).

## 2. Protect the route

Authentication is an [extension](/docs/extensions/) like rate limiting
and the WAF, with one difference: the configuration carries credentials,
so it lives in a [Secret](/docs/authentication/) under the key
`auth.hcl`, and the `ExtensionRef` filter names that Secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: hello-auth
stringData:
  auth.hcl: |
    version = 1

    auth {
      session {
        secret   = "change-me-to-a-random-string-of-32-bytes-or-more"
        lifetime = "12h"
      }

      provider "ldap" {
        url           = "ldap://directory.default.svc.cluster.local:3893"
        bind_dn       = "cn=svc-krouter,ou=svcaccts,dc=example,dc=com"
        bind_password = "svc-secret"
        user_base_dn  = "dc=example,dc=com"
        user_filter   = "(cn={username})"
        realm         = "hello"

        attributes {
          email = "mail"
        }

        group_search {
          base_dn   = "ou=groups,dc=example,dc=com"
          filter    = "(uniqueMember={dn})"
          attribute = "cn"
        }
      }
    }
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: hello
spec:
  parentRefs:
    - name: edge
  hostnames:
    - hello.example.com
  rules:
    - filters:
        - type: ExtensionRef
          extensionRef:
            group: ""
            kind: Secret
            name: hello-auth
      backendRefs:
        - name: hello
          port: 80
```

As with the other extensions, the filter attaches per rule: you can keep
a `/public` rule open and protect only the rest.

## 3. Log in

An API client without credentials is challenged:

```sh
GW_IP=$(kubectl get gateway edge -o jsonpath='{.status.addresses[0].value}')
curl -i -H 'Host: hello.example.com' "http://$GW_IP/"
```

The response is `401 Unauthorized` with a `WWW-Authenticate: Basic`
challenge. Valid credentials pass:

```sh
curl -i -u alice:alice-password -H 'Host: hello.example.com' "http://$GW_IP/"
```

Wrong credentials are challenged again, never redirected:

```sh
curl -i -u alice:wrong -H 'Host: hello.example.com' "http://$GW_IP/"
```

A browser is treated differently: a navigation request (`GET` with
`Accept: text/html`) is redirected to the login form that krouter serves
on the extension's reserved path prefix:

```sh
curl -i -H 'Host: hello.example.com' -H 'Accept: text/html' "http://$GW_IP/"
```

The `302` points to `/.krouter/auth/login`. Open the hostname in a real
browser (map it to the gateway address in `/etc/hosts`), sign in as
`alice`, and you get a session cookie: subsequent requests skip the
directory entirely until the session expires. `/.krouter/auth/logout`
ends it.

## 4. Read the identity downstream

The backend never sees passwords or cookies it has to understand; it
receives the identity as request headers. The `hello` echo shows them:

```sh
curl -s -u alice:alice-password -H 'Host: hello.example.com' "http://$GW_IP/" \
  | grep -i x-auth-request
```

```text
"x-auth-request-user": "alice",
"x-auth-request-email": "alice@example.com",
"x-auth-request-groups": "platform-team"
```

These headers cannot be spoofed: inbound values are stripped on
authenticated rules before the backend sees the request. Try it:

```sh
curl -s -u alice:alice-password -H 'Host: hello.example.com' \
  -H 'X-Auth-Request-User: admin' "http://$GW_IP/" | grep -i x-auth-request
```

The backend still sees `alice`.

## 5. Authorize by group

Authentication says who the user is; an `authorization` block says who
gets in. Restrict the route to `platform-team` by adding it to the same
`auth.hcl`:

```hcl
authorization {
  require {
    claim  = "groups"
    values = ["platform-team"]
  }
}
```

Now `alice` still passes, but `bob`, authenticated yet in the wrong
group, receives `403 Forbidden` (never a login redirect, his credentials
are fine):

```sh
curl -i -u bob:bob-password -H 'Host: hello.example.com' "http://$GW_IP/"
```

Like the other extensions, several auth Secrets compose in filter list
order: a platform-owned base Secret can carry the directory and session
configuration while a route-specific one appends `require` blocks, which
only ever tighten access.

## 6. Swap in single sign-on

The route and the mechanism stay the same for SSO: only the provider
block changes. OpenID Connect against any compliant provider (Keycloak,
Dex, Entra ID, Google, Okta):

```hcl
provider "oidc" {
  issuer        = "https://idp.example.com/realms/main"
  client_id     = "hello"
  client_secret = "..."
  scopes        = ["openid", "profile", "email"]
}
```

Register `https://hello.example.com/.krouter/auth/oidc/callback` as the
redirect URI at the provider. SAML works the same way (the SP metadata to
register at the IdP is served on `/.krouter/auth/saml/metadata`).

Providers can coexist, at most one of each type: with several interactive
providers configured, the login page becomes a chooser offering each of
them (an optional `display_name` labels the buttons). See the
[authentication reference](/docs/authentication/) for every provider
option.

## 7. Bearer tokens for APIs

Machine-to-machine clients should not follow logins. The `jwt` provider
accepts tokens issued out of band and verified against the issuer's
JWKS, with no session and no cookies:

```hcl
provider "jwt" {
  issuer    = "https://idp.example.com/realms/main"
  audiences = ["hello-api"]
  jwks_url  = "https://idp.example.com/realms/main/protocol/openid-connect/certs"
}
```

```sh
curl -i -H 'Host: hello.example.com' \
  -H "Authorization: Bearer $TOKEN" "http://$GW_IP/api"
```

Token claims feed the same `authorization` rules and identity headers as
interactive logins. On GRPCRoute rules, `jwt` is the only provider that
can be configured, since gRPC clients cannot follow interactive logins.

## 8. Operational notes

- Sessions are stateless cookies: any data-plane pod validates them
  without shared storage, and they survive configuration reloads.
- Changing `session.secret` invalidates every session at once; rotate it
  deliberately.
- If the directory or identity provider is unreachable, new logins and
  token verifications fail closed with `503`, but established sessions
  keep working for their lifetime.
- Decisions are observable: the
  `krouter_dataplane_auth_decisions_total` metric counts outcomes by
  provider, and rejected requests are visible in the
  [access log](/docs/observability/).
