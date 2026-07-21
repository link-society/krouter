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
class. The POC schema contains:

```hcl
version = 1

load_balancing {
  algorithm = "round_robin"
}
```

The POC supports `round_robin`. The field is versioned so other algorithms
can be added without changing Gateway infrastructure parameters.

## Gateway infrastructure parameters

`Gateway.spec.infrastructure.parametersRef` configures the concrete Service
created for that Gateway. The POC schema is equivalent to:

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
```

Defaults:

- `type = "NodePort"`
- `external_traffic_policy = "Local"`
- NodePorts are allocated by Kubernetes unless explicitly requested.
- No annotations.
- No load balancer class.

Fields that do not apply to the selected Service type are omitted from the
generated Service. Invalid combinations are reported as invalid parameters.
