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
	// BackendClientCert indicates a client certificate for backend TLS
	// connections under the BackendClientCert* keys of the generation TLS
	// Secret (docs/spec/traffic.md Backend TLS).
	BackendClientCert bool `json:"backendClientCert,omitempty"`
}

// Generation TLS Secret keys of the backend client certificate; the
// leading underscore cannot collide with listener names
// (docs/spec/traffic.md Backend TLS).
const (
	BackendClientCertKey = "_backend-client.tls.crt"
	BackendClientKeyKey  = "_backend-client.tls.key"
)

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
	// Created is the source route's creation time (unix seconds), used to
	// break matching-precedence ties: the oldest route wins
	// (docs/spec/traffic.md).
	Created int64 `json:"created,omitempty"`
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
	// Rule timeouts in milliseconds; zero means no timeout
	// (docs/spec/traffic.md).
	RequestTimeoutMillis int64 `json:"requestTimeoutMillis,omitempty"`
	BackendTimeoutMillis int64 `json:"backendTimeoutMillis,omitempty"`
}

type Match struct {
	PathType    string            `json:"pathType,omitempty"`
	PathValue   string            `json:"pathValue,omitempty"`
	Method      string            `json:"method,omitempty"`
	Headers     []HeaderMatch     `json:"headers,omitempty"`
	QueryParams []QueryParamMatch `json:"queryParams,omitempty"`
}

type HeaderMatch struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type QueryParamMatch struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// AppProtocolH2C marks backend Service ports dialed with cleartext HTTP/2
// (docs/spec/traffic.md Protocol handling).
const AppProtocolH2C = "kubernetes.io/h2c"

// CORS is the compiled CORS filter configuration
// (docs/spec/traffic.md Routing and filters).
type CORS struct {
	AllowOrigins     []string `json:"allowOrigins,omitempty"`
	AllowMethods     []string `json:"allowMethods,omitempty"`
	AllowHeaders     []string `json:"allowHeaders,omitempty"`
	ExposeHeaders    []string `json:"exposeHeaders,omitempty"`
	AllowCredentials bool     `json:"allowCredentials,omitempty"`
	MaxAgeSeconds    int32    `json:"maxAgeSeconds,omitempty"`
}

type Filter struct {
	// Type is one of RequestHeaderModifier, ResponseHeaderModifier,
	// RequestRedirect, URLRewrite, RequestMirror or CORS
	// (docs/spec/traffic.md).
	Type          string            `json:"type"`
	SetHeaders    map[string]string `json:"setHeaders,omitempty"`
	AddHeaders    map[string]string `json:"addHeaders,omitempty"`
	RemoveHeaders []string          `json:"removeHeaders,omitempty"`
	// CORS carries the CORS filter configuration
	// (docs/spec/traffic.md Routing and filters).
	CORS *CORS `json:"cors,omitempty"`
	// RequestRedirect and URLRewrite fields (docs/spec/traffic.md): unset
	// values inherit from the incoming request; StatusCode defaults to 302.
	Scheme     string `json:"scheme,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	Port       int32  `json:"port,omitempty"`
	StatusCode int    `json:"statusCode,omitempty"`
	// Path replacement shared by RequestRedirect and URLRewrite:
	// PathRewriteType is ReplaceFullPath or ReplacePrefixMatch, and
	// PathPrefix carries the rule's PathPrefix match consumed by
	// ReplacePrefixMatch (docs/spec/traffic.md).
	PathRewriteType  string `json:"pathRewriteType,omitempty"`
	PathRewriteValue string `json:"pathRewriteValue,omitempty"`
	PathPrefix       string `json:"pathPrefix,omitempty"`
	// RequestMirror target: a copy of the request goes to a single
	// endpoint of this backend; MirrorPercent (0-100) samples requests,
	// nil mirrors all of them (docs/spec/traffic.md).
	Mirror        *Backend `json:"mirror,omitempty"`
	MirrorPercent *float64 `json:"mirrorPercent,omitempty"`
}

type Backend struct {
	Namespace     string `json:"namespace"`
	Name          string `json:"name"`
	Port          int32  `json:"port"`
	Weight        int32  `json:"weight"`
	Valid         bool   `json:"valid"`
	InvalidReason string `json:"invalidReason,omitempty"`
	// AppProtocol mirrors the backend Service port appProtocol
	// (docs/spec/traffic.md Protocol handling).
	AppProtocol string `json:"appProtocol,omitempty"`
	// Filters apply only to traffic forwarded to this backend, after the
	// rule-level filters (docs/spec/traffic.md Routing and filters).
	Filters []Filter `json:"filters,omitempty"`
	// TLS carries the BackendTLSPolicy verification parameters for this
	// backend; nil means cleartext (docs/spec/traffic.md).
	TLS *BackendTLS `json:"tls,omitempty"`
}

// BackendTLS is the compiled BackendTLSPolicy applied to one backend
// (docs/spec/traffic.md): connections are upgraded to TLS with SNI and
// certificate verification. Invalid marks a rejected policy whose backends
// MUST fail closed.
type BackendTLS struct {
	Hostname  string `json:"hostname,omitempty"`
	CAPem     string `json:"caPem,omitempty"`
	SystemCAs bool   `json:"systemCAs,omitempty"`
	Invalid   bool   `json:"invalid,omitempty"`
	// SubjectAltNames, when set, replace hostname verification: the
	// backend certificate must match at least one, and Hostname is only
	// used for SNI (docs/spec/traffic.md Backend TLS).
	SubjectAltNames []SubjectAltName `json:"subjectAltNames,omitempty"`
}

// SubjectAltName is one allowed backend certificate identity: Type is
// Hostname or URI (docs/spec/traffic.md Backend TLS).
type SubjectAltName struct {
	Type  string `json:"type"`
	Value string `json:"value"`
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
