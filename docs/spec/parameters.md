# Parameters

krouter is configured through standard Kubernetes objects only; it defines
no custom resources.

Both Gateway API parameter references MUST target a core Kubernetes
ConfigMap containing a `krouter.hcl` key. krouter uses HCL native syntax and
MUST reject unknown or invalid fields.

GatewayClass and Gateway parameters use separate schemas and are never
merged.

An invalid or missing referenced parameter ConfigMap produces the Gateway
API `InvalidParameters` status reason. It MUST NOT cause the controller or
data plane to crash.

## GatewayClass parameters

`GatewayClass.spec.parametersRef` configures proxy behavior shared by that
class. The schema contains:

```hcl
version = 1

load_balancing {
  algorithm = "round_robin"
}
```

krouter supports `round_robin`. The field is versioned so other algorithms
can be added without changing Gateway infrastructure parameters.

## Gateway infrastructure parameters

`Gateway.spec.infrastructure.parametersRef` configures the concrete Service
created for that Gateway. The schema is equivalent to:

```hcl
version = 1

service {
  type                    = "NodePort"
  external_traffic_policy = "Local"

  # Optional; valid for compatible LoadBalancer implementations.
  # load_balancer_class = "example.com/load-balancer"

  annotations = {
    "example.com/setting" = "value"
  }

  node_ports = {
    # Listener name to requested NodePort.
    # "http" = 30080
  }
}

client_ip {
  # Networks whose forwarded headers are trusted, in CIDR notation.
  trusted_proxies = ["10.0.0.0/8", "2001:db8::/32"]

  # Listeners requiring a proxy protocol preamble on every connection.
  proxy_protocol {
    listeners = ["http", "https"]
  }
}
```

Defaults:

- `type = "NodePort"`
- `external_traffic_policy = "Local"`
- NodePorts are allocated by Kubernetes unless explicitly requested.
- No annotations.
- No load balancer class.
- `trusted_proxies` empty: no peer is trusted, and forwarded headers are
  regenerated from the downstream connection.
- `proxy_protocol.listeners` empty: no listener expects a preamble.

Every `trusted_proxies` entry MUST be a valid IPv4 or IPv6 prefix; a
malformed entry is an invalid parameter. What trusting a peer changes is
specified in [traffic.md](traffic.md) (Forwarding headers), and why the
list belongs to the Gateway rather than to its routes in
[security.md](security.md) (Client IP trust).

Every `proxy_protocol.listeners` entry MUST name a listener the Gateway
itself declares, and that listener MUST NOT be a UDP listener. Listing any
listener while `trusted_proxies` is empty is an invalid parameter: no peer
would be allowed to send the preamble those listeners require. Like
`node_ports`, the setting covers the Gateway's own listeners; listeners
merged from a ListenerSet are not covered.

Fields that do not apply to the selected Service type are omitted from the
generated Service. Invalid combinations are reported as invalid parameters.
