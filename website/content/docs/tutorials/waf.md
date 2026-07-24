---
title: "Web application firewall"
description: "Put the embedded OWASP Core Rule Set in front of a route, layer your own SecLang rules from ConfigMaps, and ship full rulesets as files."
weight: 9
params:
  level: "Advanced"
---

**Use case:** you want a WAF in front of an application: the OWASP Core
Rule Set as a baseline, your own ModSecurity-style rules on top, and a
way to ship whole rule files when they outgrow inline configuration.

This tutorial reuses the `hello` Service and `edge` Gateway from
[Hello, HTTP](/docs/tutorials/hello-http/).

## 1. Enable the Core Rule Set

The WAF is an [extension](/docs/extensions/): a ConfigMap holding a
`waf.hcl` document, attached to a route rule with an `ExtensionRef`
filter. The [OWASP Core Rule Set](https://coreruleset.org) and the
[Coraza](https://coraza.io) recommended configuration are embedded in the
krouter binary, so enabling them is three `@`-includes:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: hello-waf
data:
  waf.hcl: |
    version = 1

    waf {
      directives = <<-EOT
        Include @coraza.conf-recommended
        Include @crs-setup.conf.example
        Include @owasp_crs/*.conf
        SecRuleEngine On
      EOT
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
            kind: ConfigMap
            name: hello-waf
      backendRefs:
        - name: hello
          port: 80
```

The filter attaches per rule, not per route: you can keep `/` unprotected
and put the WAF only on the rule matching `/api`, or give different rules
different rulesets.

## 2. Attack yourself

A legitimate request passes untouched:

```sh
GW_IP=$(kubectl get gateway edge -o jsonpath='{.status.addresses[0].value}')
curl -i -H 'Host: hello.example.com' "http://$GW_IP/?q=hello"
```

A cross-site-scripting probe is interrupted before it reaches the
backend:

```sh
curl -i -H 'Host: hello.example.com' \
  "http://$GW_IP/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
```

The client receives `403 Forbidden` and the backend never sees the
request. Request bodies are inspected too, buffered up to the engine's
limits (`SecRequestBodyLimit` and friends), then replayed to the backend
unchanged:

```sh
curl -i -H 'Host: hello.example.com' \
  --data "username=admin' OR 1=1--" "http://$GW_IP/login"
```

## 3. Layer your own rules

This is where rule files would normally come in. In krouter there are no
files: each `waf.hcl` fragment plays the role of one `.conf` file, and
the filter list is the include order. Add a second ConfigMap with your
own directives:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: hello-waf-tuning
data:
  waf.hcl: |
    version = 1

    waf {
      directives = <<-EOT
        SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" \
          "id:1001,phase:1,deny,status:403,log,msg:'Scanner UA blocked'"
      EOT
    }
```

Then reference it after the base one, in the same rule:

```yaml
      filters:
        - type: ExtensionRef
          extensionRef:
            group: ""
            kind: ConfigMap
            name: hello-waf
        - type: ExtensionRef
          extensionRef:
            group: ""
            kind: ConfigMap
            name: hello-waf-tuning
```

The fragments concatenate in filter list order into one SecLang program,
so later fragments see everything the earlier ones defined. That gives
you the usual ModSecurity layering: the base ConfigMap carries the CRS
(shared by many routes), the later one carries route-specific rules and
exclusions. Tuning away a false positive is one directive in the later
fragment:

```text
SecRuleRemoveById 942100
```

Verify your new rule:

```sh
curl -i -A 'sqlmap/1.7' -H 'Host: hello.example.com' "http://$GW_IP/"
```

## 4. Change rules without restarts

Edit either ConfigMap and the control plane compiles a new configuration
generation; data-plane pods swap it atomically. No pods restart, no
volumes are mounted, and in-flight requests finish on the old ruleset.

Validation happens at compile time, before any request reaches the new
program. Break a directive on purpose:

```sh
kubectl patch configmap hello-waf-tuning --type merge -p '
data:
  waf.hcl: |
    version = 1

    waf {
      directives = "SecRule oops"
    }
'
kubectl describe httproute hello
```

The route stays accepted, but `ResolvedRefs` turns `False` with reason
`InvalidExtensionRef`, and requests matching the rule are answered `500`
(fail closed, never silently unprotected). Fix the ConfigMap and the
route recovers on its own.

## 5. Bring your own rule files

ConfigMaps are the day-to-day mechanism, but a large ruleset (a CRS fork,
a fat IP blocklist) can outgrow the
[1 MiB ConfigMap limit](https://kubernetes.io/docs/concepts/configuration/configmap/#motivation)
or already live in files you would rather ship verbatim. `Include` of a
filesystem path reads rule files from the krouter pods themselves:

```hcl
version = 1

waf {
  directives = <<-EOT
    Include /etc/krouter/rules/custom.conf
    Include /etc/krouter/rules/blocklists/*.conf
  EOT
}
```

Getting the files onto the pods means tinkering with the deployment
itself, not with Gateway API resources. Two recipes:

**Extend the image.** The krouter image is built from scratch and
contains only the binary, so adding rules is one COPY layer:

```dockerfile
FROM ghcr.io/link-society/krouter:dev
COPY rules/ /etc/krouter/rules/
```

Point both the control-plane Deployment and the data-plane DaemonSet at
your image and every pod carries the files.

**Mount volumes.** Keep the stock image and patch the manifest with
[Kustomize](https://kubectl.docs.kubernetes.io/references/kustomize/),
mounting your rules (here from a ConfigMap, but any volume works) into
both workloads:

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - https://raw.githubusercontent.com/link-society/krouter/main/k8s/krouter.yaml
configMapGenerator:
  - name: krouter-rules
    namespace: krouter-system
    files:
      - rules/custom.conf
patches:
  - patch: |-
      - op: add
        path: /spec/template/spec/volumes
        value:
          - name: rules
            configMap:
              name: krouter-rules
      - op: add
        path: /spec/template/spec/containers/0/volumeMounts
        value:
          - name: rules
            mountPath: /etc/krouter/rules
            readOnly: true
    target:
      kind: Deployment
      name: krouter-controlplane
  - patch: |-
      - op: add
        path: /spec/template/spec/volumes
        value:
          - name: rules
            configMap:
              name: krouter-rules
      - op: add
        path: /spec/template/spec/containers/0/volumeMounts
        value:
          - name: rules
            mountPath: /etc/krouter/rules
            readOnly: true
    target:
      kind: DaemonSet
      name: krouter-dataplane
```

Both workloads need the files: the control plane builds the engine once
at compile time to validate the program (a missing or broken file
surfaces as `InvalidExtensionRef`, exactly like the broken directive in
step 4), and every data-plane pod builds it again to enforce it.

One caveat that ConfigMap directives do not have: rule files are read
when the engine builds, not watched. Editing a file in place does not
re-trigger compilation, so roll the pods (a new image tag does this
naturally) to apply new file contents.

Two closing notes:

- The same ConfigMap can also carry a `ratelimit.hcl` key:
  [rate limiting](/docs/tutorials/rate-limiting/) runs first, so a
  limited request costs no WAF CPU. See [Extensions](/docs/extensions/)
  for composition and status details.
- On [GRPCRoute](/docs/tutorials/grpc/) rules the WAF inspects request
  headers and buffers the request message like an HTTP body. The stock
  CRS rejects the `application/grpc` content type at the header phase
  (rule 920420), so allow it in a later fragment before putting the CRS
  in front of gRPC services, and prefer scoping the WAF to unary methods
  since message buffering delays streams.

Decisions are observable as `krouter_dataplane_waf_decisions_total` and
in the access log; see [Observability](/docs/observability/).

That's the full tour, from one route to a WAF-protected, multi-tenant
edge. For the guarantees behind all of it, read the
[conformance page](/docs/conformance/) and the
[test report](/report/report.html).
