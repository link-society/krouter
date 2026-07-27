// Package hclparams parses the krouter parameter ConfigMaps (docs/spec/parameters.md).
// Parameters use HCL native syntax; unknown or invalid fields are rejected.
package hclparams

import (
	"fmt"

	"net/netip"

	"github.com/hashicorp/hcl/v2/hclsimple"
)

// ------------------------------------------------- GatewayClass (docs/spec/parameters.md) --

type ClassParams struct {
	Version       int                 `hcl:"version"`
	LoadBalancing *LoadBalancingBlock `hcl:"load_balancing,block"`
}

type LoadBalancingBlock struct {
	Algorithm string `hcl:"algorithm"`
}

func ParseClass(src string) (*ClassParams, error) {
	params := &ClassParams{}
	if err := hclsimple.Decode("krouter.hcl", []byte(src), nil, params); err != nil {
		return nil, err
	}

	if params.Version != 1 {
		return nil, fmt.Errorf("unsupported version %d", params.Version)
	}

	if params.LoadBalancing == nil {
		params.LoadBalancing = &LoadBalancingBlock{Algorithm: "round_robin"}
	}

	if params.LoadBalancing.Algorithm != "round_robin" {
		return nil, fmt.Errorf("unsupported load_balancing algorithm %q", params.LoadBalancing.Algorithm)
	}

	return params, nil
}

// ------------------------------------- Gateway infrastructure (docs/spec/parameters.md) --

type InfraParams struct {
	Version  int            `hcl:"version"`
	Service  *ServiceBlock  `hcl:"service,block"`
	ClientIP *ClientIPBlock `hcl:"client_ip,block"`
}

type ServiceBlock struct {
	Type                  string            `hcl:"type,optional"`
	ExternalTrafficPolicy string            `hcl:"external_traffic_policy,optional"`
	LoadBalancerClass     *string           `hcl:"load_balancer_class,optional"`
	Annotations           map[string]string `hcl:"annotations,optional"`
	NodePorts             map[string]int32  `hcl:"node_ports,optional"`
}

// ClientIPBlock lists the networks whose forwarded headers are honored
// when resolving the client IP (docs/spec/traffic.md Forwarding headers).
// Empty means no peer is trusted (docs/spec/security.md Client IP trust).
type ClientIPBlock struct {
	TrustedProxies []string            `hcl:"trusted_proxies,optional"`
	ProxyProtocol  *ProxyProtocolBlock `hcl:"proxy_protocol,block"`
}

// ProxyProtocolBlock names the listeners requiring a PROXY protocol
// preamble on every connection (docs/spec/traffic.md Proxy protocol).
type ProxyProtocolBlock struct {
	Listeners []string `hcl:"listeners,optional"`
}

func ParseInfra(src string) (*InfraParams, error) {
	params := &InfraParams{}
	if err := hclsimple.Decode("krouter.hcl", []byte(src), nil, params); err != nil {
		return nil, err
	}

	if params.Version != 1 {
		return nil, fmt.Errorf("unsupported version %d", params.Version)
	}

	if params.Service == nil {
		params.Service = &ServiceBlock{}
	}

	if params.Service.Type == "" {
		params.Service.Type = "NodePort"
	}

	switch params.Service.Type {
	case "NodePort", "LoadBalancer", "ClusterIP":

	default:
		return nil, fmt.Errorf("unsupported service type %q", params.Service.Type)
	}

	if params.Service.ExternalTrafficPolicy == "" {
		params.Service.ExternalTrafficPolicy = "Local"
	}

	switch params.Service.ExternalTrafficPolicy {
	case "Local", "Cluster":

	default:
		return nil, fmt.Errorf(
			"unsupported external_traffic_policy %q",
			params.Service.ExternalTrafficPolicy,
		)
	}

	if params.Service.Type == "ClusterIP" {
		// externalTrafficPolicy does not apply to ClusterIP services.
		params.Service.ExternalTrafficPolicy = ""
	}

	if params.ClientIP == nil {
		params.ClientIP = &ClientIPBlock{}
	}

	for _, cidr := range params.ClientIP.TrustedProxies {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return nil, fmt.Errorf("invalid trusted_proxies entry %q", cidr)
		}
	}

	if params.ClientIP.ProxyProtocol == nil {
		params.ClientIP.ProxyProtocol = &ProxyProtocolBlock{}
	}

	for _, name := range params.ClientIP.ProxyProtocol.Listeners {
		if name == "" {
			return nil, fmt.Errorf("proxy_protocol listeners must be named")
		}
	}

	// A preamble is honored only from a trusted peer, so without a trust
	// list every connection to those listeners would be refused
	// (docs/spec/parameters.md).
	if len(params.ClientIP.ProxyProtocol.Listeners) > 0 &&
		len(params.ClientIP.TrustedProxies) == 0 {
		return nil, fmt.Errorf("proxy_protocol requires trusted_proxies")
	}

	return params, nil
}
