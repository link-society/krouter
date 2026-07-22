// Package compiled defines the machine-generated configuration exchanged
// between the control plane and the data plane (docs/spec/configuration.md). It is internal,
// versioned by content hash, and stored in ConfigMaps/Secrets in the system
// namespace.
package compiled

import (
	"fmt"

	"sort"

	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

const (
	// DataKey is the ConfigMap key holding a compiled JSON payload.
	DataKey = "config.json"
	// ManifestKey is the ConfigMap key holding the manifest JSON.
	ManifestKey = "manifest.json"

	LabelManagedBy  = "app.kubernetes.io/managed-by"
	ManagedByValue  = "krouter"
	LabelGatewayUID = "krouter.link-society.com/gateway-uid"
	LabelSourceUID  = "krouter.link-society.com/source-uid"
	LabelGeneration = "krouter.link-society.com/generation"
	LabelRole       = "krouter.link-society.com/role"

	RoleManifest   = "manifest"
	RoleGatewayCfg = "gateway-config"
	RoleAttachment = "attachment"
	RoleTLS        = "tls"

	// EndpointSliceManagedBy is the krouter-specific managed-by value used
	// on mirrored frontend EndpointSlices (docs/spec/frontend.md). Label values must not
	// contain slashes.
	EndpointSliceManagedBy = "controller.krouter.link-society.com"

	// PortMapAnnotation persists internal listener port allocations on the
	// generated Service (docs/spec/frontend.md).
	PortMapAnnotation = "krouter.link-society.com/port-map"

	ObjectKindConfigMap = "ConfigMap"
	ObjectKindSecret    = "Secret"
)

// GatewayConfig is the per-generation compiled Gateway payload.
type GatewayConfig struct {
	UID       string     `json:"uid"`
	Namespace string     `json:"namespace"`
	Name      string     `json:"name"`
	Listeners []Listener `json:"listeners"`
}

type Listener struct {
	Name         string `json:"name"`
	Port         int32  `json:"port"`
	InternalPort int32  `json:"internalPort"`
	Protocol     string `json:"protocol"`
	Hostname     string `json:"hostname,omitempty"`
	// HasTLS indicates cert material under keys "<name>.tls.crt/.tls.key"
	// in the generation TLS Secret.
	HasTLS bool `json:"hasTLS,omitempty"`
}

// RouteConfig is the per-generation compiled (Gateway, HTTPRoute)
// attachment payload.
type RouteConfig struct {
	UID       string   `json:"uid"`
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Listeners []string `json:"listeners"`
	Hostnames []string `json:"hostnames,omitempty"`
	// GRPC marks a GRPCRoute attachment: its rules only match gRPC
	// requests and its backends speak cleartext HTTP/2
	// (docs/spec/traffic.md gRPC routing).
	GRPC  bool   `json:"grpc,omitempty"`
	Rules []Rule `json:"rules"`
}

type Rule struct {
	Matches  []Match   `json:"matches,omitempty"`
	Filters  []Filter  `json:"filters,omitempty"`
	Backends []Backend `json:"backends"`
}

type Match struct {
	PathType  string        `json:"pathType,omitempty"`
	PathValue string        `json:"pathValue,omitempty"`
	Headers   []HeaderMatch `json:"headers,omitempty"`
}

type HeaderMatch struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Filter struct {
	Type          string            `json:"type"`
	SetHeaders    map[string]string `json:"setHeaders,omitempty"`
	AddHeaders    map[string]string `json:"addHeaders,omitempty"`
	RemoveHeaders []string          `json:"removeHeaders,omitempty"`
}

type Backend struct {
	Namespace     string `json:"namespace"`
	Name          string `json:"name"`
	Port          int32  `json:"port"`
	Weight        int32  `json:"weight"`
	Valid         bool   `json:"valid"`
	InvalidReason string `json:"invalidReason,omitempty"`
}

// Manifest is the mutable commit marker identifying the desired generation
// and every object/checksum belonging to it (docs/spec/configuration.md).
type Manifest struct {
	GatewayUID string      `json:"gatewayUID"`
	Generation string      `json:"generation"`
	Previous   string      `json:"previous,omitempty"`
	Objects    []ObjectRef `json:"objects"`
}

type ObjectRef struct {
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Checksum string `json:"checksum"`
}

// ------------------------------------------------------------- checksums --

func ChecksumBytes(data []byte) string {
	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:])
}

// ChecksumSecret computes a deterministic checksum over secret data.
func ChecksumSecret(data map[string][]byte) string {
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	hasher := sha256.New()
	for _, key := range keys {
		fmt.Fprintf(hasher, "%s=%x\n", key, sha256.Sum256(data[key]))
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

// GenerationID derives the content-addressed generation identifier from the
// compiled payloads. It is a pure function so reconciliation is idempotent.
func GenerationID(gatewayPayload []byte, attachments map[string][]byte, secretChecksum string) string {
	uids := make([]string, 0, len(attachments))
	for uid := range attachments {
		uids = append(uids, uid)
	}
	sort.Strings(uids)

	hasher := sha256.New()
	hasher.Write(gatewayPayload)
	for _, uid := range uids {
		fmt.Fprintf(hasher, "\x00%s\x00", uid)
		hasher.Write(attachments[uid])
	}
	fmt.Fprintf(hasher, "\x00%s", secretChecksum)

	return hex.EncodeToString(hasher.Sum(nil))[:12]
}

func MarshalPayload(v any) []byte {
	payload, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("compiled: marshal: %v", err))
	}

	return payload
}

// ----------------------------------------------------------------- names --

func ManifestName(gatewayUID string) string {
	return "krouter-manifest-" + gatewayUID
}

func GatewayConfigName(gatewayUID, generation string) string {
	return "krouter-gwcfg-" + gatewayUID + "-" + generation
}

func AttachmentName(gatewayUID, routeUID, generation string) string {
	return "krouter-att-" + gatewayUID + "-" + routeUID + "-" + generation
}

func TLSSecretName(gatewayUID, generation string) string {
	return "krouter-tls-" + gatewayUID + "-" + generation
}

func BaseLabels(gatewayUID string) map[string]string {
	return map[string]string{
		LabelManagedBy:  ManagedByValue,
		LabelGatewayUID: gatewayUID,
	}
}

func ObjectLabels(gatewayUID, generation, role string) map[string]string {
	labels := BaseLabels(gatewayUID)
	labels[LabelGeneration] = generation
	labels[LabelRole] = role

	return labels
}
