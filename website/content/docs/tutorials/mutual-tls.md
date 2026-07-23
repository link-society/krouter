---
title: "Mutual TLS"
description: "Validate client certificates at the gateway and re-encrypt to backends with verified identities."
weight: 6
params:
  level: "Advanced"
---

**Use case:** a zero-trust posture. Clients must present certificates,
and traffic to backends is re-encrypted and verified, both configured with
standard resources only.

## Frontend: validate client certificates

Put your client CA bundle in a
[ConfigMap](https://kubernetes.io/docs/concepts/configuration/configmap/)
under the key `ca.crt`, then enable validation on the Gateway:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
spec:
  gatewayClassName: krouter
  tls:
    frontend:
      default:
        validation:
          caCertificateRefs:
            - kind: ConfigMap
              name: client-ca
      perPort:                    # optional per-port override
        - port: 8443
          tls:
            validation:
              mode: AllowInsecureFallback
              caCertificateRefs:
                - kind: ConfigMap
                  name: partner-ca
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      tls:
        certificateRefs:
          - name: edge-cert
```

- The default mode, `AllowValidOnly`, rejects handshakes without a valid
  client certificate.
- `AllowInsecureFallback` also admits clients with missing or invalid
  certificates (the Gateway then advertises the
  `InsecureFrontendValidationMode` condition so the relaxation is visible).

Test it:

```sh
curl --cert client.crt --key client.key --cacert edge-ca.crt https://hello.example.com/   # 200
curl --cacert edge-ca.crt https://hello.example.com/                                      # handshake fails
```

## Backend: re-encrypt with BackendTLSPolicy

A `BackendTLSPolicy` upgrades gateway→backend connections to verified TLS:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: BackendTLSPolicy
metadata:
  name: hello-tls
spec:
  targetRefs:
    - group: ""
      kind: Service
      name: hello
  validation:
    hostname: hello.internal          # sent as SNI
    caCertificateRefs:
      - group: ""
        kind: ConfigMap
        name: backend-ca
    subjectAltNames:                  # optional: pin exact identities
      - type: Hostname
        hostname: hello.internal
      - type: URI
        uri: spiffe://cluster.local/ns/default/sa/hello
```

With `subjectAltNames`, the backend certificate must match at least one
entry (DNS or [SPIFFE](https://spiffe.io) URI); `hostname` is then only
used for SNI. Verification failures fail **closed**: krouter answers
`502` rather than ever falling back to cleartext.

## Backend: present a client certificate

For backends that themselves require mTLS, give the Gateway a client
keypair from a
[TLS Secret](https://kubernetes.io/docs/concepts/configuration/secret/#tls-secrets):

```yaml
spec:
  tls:
    backend:
      clientCertificateRef:
        kind: Secret
        name: gateway-client-cert
```

The Gateway reports reference problems on its `ResolvedRefs` condition
(`InvalidClientCertificateRef`, or `RefNotPermitted` for cross-namespace
references without a
[ReferenceGrant](https://gateway-api.sigs.k8s.io/api-types/referencegrant/)).

**Next:** [share one gateway across teams](/docs/tutorials/multi-team/).
