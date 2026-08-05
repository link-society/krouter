package auth

import (
	"errors"
	"fmt"

	"strings"

	"sync"

	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"

	"io"
	"math/big"

	"net/http"

	"time"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// Outcome classification of authentication failures
// (docs/spec/authentication.md Request path integration):
// ErrUnauthenticated answers 401 (UNAUTHENTICATED on gRPC rules),
// ErrUnavailable answers 503 (UNAVAILABLE) and fails closed.
var (
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrUnavailable     = errors.New("provider unavailable")
)

// clockSkew bounds exp/nbf validation (docs/spec/authentication.md).
const clockSkew = 60 * time.Second

// jwksTTL and jwksMissBackoff bound the JWKS refresh rate: periodic
// refresh plus at most one miss-triggered refetch per backoff window.
const (
	jwksTTL         = 10 * time.Minute
	jwksMissBackoff = 30 * time.Second
)

// JWTValidator validates bearer tokens against a JWKS document fetched
// and cached by this data-plane pod (docs/spec/authentication.md Bearer
// JWT). Tokens signed with `none` or symmetric algorithms are rejected.
type JWTValidator struct {
	cfg    *compiled.AuthJWT
	client *http.Client

	mu        sync.Mutex
	jwksURL   string
	keys      map[string][]crypto.PublicKey
	fetchedAt time.Time
	missedAt  time.Time
}

func NewJWTValidator(cfg *compiled.AuthJWT) *JWTValidator {
	return &JWTValidator{
		cfg:     cfg,
		client:  &http.Client{Timeout: 10 * time.Second},
		jwksURL: cfg.JWKSURL,
	}
}

// Validate checks the compact token and returns its claims as canonical
// strings (docs/spec/authentication.md Authorization): signature against
// the JWKS, `iss`, `aud`, `exp` and `nbf` with bounded clock skew.
func (v *JWTValidator) Validate(token string) (map[string][]string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: malformed token", ErrUnauthenticated)
	}

	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: malformed header", ErrUnauthenticated)
	}

	header := struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}{}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return nil, fmt.Errorf("%w: malformed header", ErrUnauthenticated)
	}

	hash, verify, ok := algorithm(header.Alg)
	if !ok {
		// `none` and symmetric algorithms land here by construction.
		return nil, fmt.Errorf("%w: algorithm %q rejected", ErrUnauthenticated, header.Alg)
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: malformed payload", ErrUnauthenticated)
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: malformed signature", ErrUnauthenticated)
	}

	keys, err := v.keysFor(header.Kid)
	if err != nil {
		return nil, err
	}

	digest := hash.New()
	digest.Write([]byte(parts[0] + "." + parts[1]))
	hashed := digest.Sum(nil)

	verified := false
	for _, key := range keys {
		if verify(key, hash, hashed, signature) {
			verified = true
			break
		}
	}

	if !verified {
		return nil, fmt.Errorf("%w: signature verification failed", ErrUnauthenticated)
	}

	return v.validateClaims(payloadRaw)
}

func (v *JWTValidator) validateClaims(payloadRaw []byte) (map[string][]string, error) {
	decoder := json.NewDecoder(strings.NewReader(string(payloadRaw)))
	decoder.UseNumber()

	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("%w: malformed claims", ErrUnauthenticated)
	}

	claims := canonicalClaims(payload)

	if got := claims["iss"]; len(got) != 1 || got[0] != v.cfg.Issuer {
		return nil, fmt.Errorf("%w: issuer mismatch", ErrUnauthenticated)
	}

	if !intersects(claims["aud"], v.cfg.Audiences) {
		return nil, fmt.Errorf("%w: audience mismatch", ErrUnauthenticated)
	}

	now := time.Now()

	exp, err := numericDate(payload["exp"])
	if err != nil || now.After(exp.Add(clockSkew)) {
		return nil, fmt.Errorf("%w: token expired", ErrUnauthenticated)
	}

	if nbf, err := numericDate(payload["nbf"]); err == nil && now.Add(clockSkew).Before(nbf) {
		return nil, fmt.Errorf("%w: token not yet valid", ErrUnauthenticated)
	}

	return claims, nil
}

// ------------------------------------------------------------------ jwks --

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// keysFor returns candidate keys for a key identifier, refreshing the
// cached JWKS periodically and on unknown identifiers at a bounded rate
// (docs/spec/authentication.md Bearer JWT).
func (v *JWTValidator) keysFor(kid string) ([]crypto.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	stale := time.Since(v.fetchedAt) > jwksTTL

	if v.keys == nil || stale {
		if err := v.fetchLocked(); err != nil {
			return nil, err
		}
	}

	if keys := v.lookupLocked(kid); len(keys) > 0 {
		return keys, nil
	}

	// Unknown identifier: one refetch per backoff window.
	if time.Since(v.missedAt) > jwksMissBackoff {
		v.missedAt = time.Now()

		if err := v.fetchLocked(); err != nil {
			return nil, err
		}

		if keys := v.lookupLocked(kid); len(keys) > 0 {
			return keys, nil
		}
	}

	return nil, fmt.Errorf("%w: no usable key", ErrUnauthenticated)
}

func (v *JWTValidator) lookupLocked(kid string) []crypto.PublicKey {
	if kid != "" {
		return v.keys[kid]
	}

	// Tokens without a kid try every key.
	var all []crypto.PublicKey
	for _, keys := range v.keys {
		all = append(all, keys...)
	}

	return all
}

func (v *JWTValidator) fetchLocked() error {
	url, err := v.resolveJWKSURLLocked()
	if err != nil {
		return err
	}

	document, err := v.fetchJSON(url)
	if err != nil {
		return err
	}

	set := struct {
		Keys []jwkKey `json:"keys"`
	}{}
	if err := json.Unmarshal(document, &set); err != nil {
		return fmt.Errorf("%w: invalid JWKS document: %v", ErrUnavailable, err)
	}

	keys := map[string][]crypto.PublicKey{}
	for _, key := range set.Keys {
		if key.Use != "" && key.Use != "sig" {
			continue
		}

		parsed, err := parseJWK(key)
		if err != nil {
			continue
		}

		keys[key.Kid] = append(keys[key.Kid], parsed)
	}

	if len(keys) == 0 {
		return fmt.Errorf("%w: JWKS holds no usable key", ErrUnavailable)
	}

	v.keys = keys
	v.fetchedAt = time.Now()

	return nil
}

// resolveJWKSURLLocked returns the configured jwks_url, or discovers it
// through the issuer's discovery document when absent.
func (v *JWTValidator) resolveJWKSURLLocked() (string, error) {
	if v.jwksURL != "" {
		return v.jwksURL, nil
	}

	document, err := v.fetchJSON(
		strings.TrimSuffix(v.cfg.Issuer, "/") + "/.well-known/openid-configuration")
	if err != nil {
		return "", err
	}

	discovery := struct {
		JWKSURI string `json:"jwks_uri"`
	}{}
	if err := json.Unmarshal(document, &discovery); err != nil || discovery.JWKSURI == "" {
		return "", fmt.Errorf("%w: discovery document has no jwks_uri", ErrUnavailable)
	}

	v.jwksURL = discovery.JWKSURI

	return v.jwksURL, nil
}

func (v *JWTValidator) fetchJSON(url string) ([]byte, error) {
	resp, err := v.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s answered %d", ErrUnavailable, url, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	return body, nil
}

func parseJWK(key jwkKey) (crypto.PublicKey, error) {
	switch key.Kty {
	case "RSA":		n, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return nil, err
		}

		e, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			return nil, err
		}

		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}, nil

	case "EC":
		curve, ok := curveFor(key.Crv)
		if !ok {
			return nil, fmt.Errorf("unsupported curve %q", key.Crv)
		}

		x, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil {
			return nil, err
		}

		y, err := base64.RawURLEncoding.DecodeString(key.Y)
		if err != nil {
			return nil, err
		}

		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported key type %q", key.Kty)
	}
}

// ------------------------------------------------------------ algorithms --

func curveFor(name string) (elliptic.Curve, bool) {
	switch name {
	case "P-256":
		return elliptic.P256(), true
	case "P-384":
		return elliptic.P384(), true
	case "P-521":
		return elliptic.P521(), true
	default:
		return nil, false
	}
}

type verifyFunc func(key crypto.PublicKey, hash crypto.Hash, hashed, signature []byte) bool

// algorithm maps a JOSE `alg` to its hash and verifier. Only asymmetric
// algorithms are present: `none` and HS* MUST be rejected
// (docs/spec/authentication.md Bearer JWT).
func algorithm(alg string) (crypto.Hash, verifyFunc, bool) {
	switch alg {
	case "RS256":
		return crypto.SHA256, verifyRSAPKCS1, true
	case "RS384":
		return crypto.SHA384, verifyRSAPKCS1, true
	case "RS512":
		return crypto.SHA512, verifyRSAPKCS1, true
	case "PS256":
		return crypto.SHA256, verifyRSAPSS, true
	case "PS384":
		return crypto.SHA384, verifyRSAPSS, true
	case "PS512":
		return crypto.SHA512, verifyRSAPSS, true
	case "ES256":
		return crypto.SHA256, verifyECDSA, true
	case "ES384":
		return crypto.SHA384, verifyECDSA, true
	case "ES512":
		return crypto.SHA512, verifyECDSA, true
	default:
		return 0, nil, false
	}
}

func verifyRSAPKCS1(key crypto.PublicKey, hash crypto.Hash, hashed, signature []byte) bool {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return false
	}

	return rsa.VerifyPKCS1v15(rsaKey, hash, hashed, signature) == nil
}

func verifyRSAPSS(key crypto.PublicKey, hash crypto.Hash, hashed, signature []byte) bool {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return false
	}

	return rsa.VerifyPSS(rsaKey, hash, hashed, signature, nil) == nil
}

func verifyECDSA(key crypto.PublicKey, hash crypto.Hash, hashed, signature []byte) bool {
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return false
	}

	size := (ecdsaKey.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*size {
		return false
	}

	r := new(big.Int).SetBytes(signature[:size])
	s := new(big.Int).SetBytes(signature[size:])

	return ecdsa.Verify(ecdsaKey, hashed, r, s)
}

// -------------------------------------------------------------- claims --

// canonicalClaims renders every claim as strings: list-valued claims
// compare per element, scalar claims in canonical string form
// (docs/spec/authentication.md Authorization).
func canonicalClaims(payload map[string]any) map[string][]string {
	claims := make(map[string][]string, len(payload))
	for name, value := range payload {
		if rendered := canonicalValues(value); rendered != nil {
			claims[name] = rendered
		}
	}

	return claims
}

func canonicalValues(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}

	case bool:
		if typed {
			return []string{"true"}
		}

		return []string{"false"}

	case json.Number:
		return []string{typed.String()}

	case []any:
		var values []string
		for _, element := range typed {
			values = append(values, canonicalValues(element)...)
		}

		return values

	default:
		return nil
	}
}

func numericDate(value any) (time.Time, error) {
	number, ok := value.(json.Number)
	if !ok {
		return time.Time{}, fmt.Errorf("not a numeric date")
	}

	seconds, err := number.Float64()
	if err != nil {
		return time.Time{}, err
	}

	return time.Unix(int64(seconds), 0), nil
}

func intersects(values, allowed []string) bool {
	for _, value := range values {
		for _, candidate := range allowed {
			if value == candidate {
				return true
			}
		}
	}

	return false
}
