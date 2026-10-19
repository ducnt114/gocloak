// Package jwt implements the small subset of JWS/JWK needed by gocloak:
// RS256 signing and verification and JWK export of RSA public keys.
package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
)

var b64 = base64.RawURLEncoding

// Claims is a decoded JWT payload.
type Claims map[string]any

func (c Claims) String(name string) string {
	s, _ := c[name].(string)
	return s
}

// Int returns a numeric claim (JSON numbers decode as float64).
func (c Claims) Int(name string) int64 {
	switch v := c[name].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	}
	return 0
}

// Audience returns the aud claim as a list.
func (c Claims) Audience() []string {
	switch v := c["aud"].(type) {
	case string:
		return []string{v}
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, a := range v {
			if s, ok := a.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
}

// Sign produces a compact RS256 JWS.
func Sign(claims Claims, kid string, key *rsa.PrivateKey) (string, error) {
	h, _ := json.Marshal(header{Alg: "RS256", Typ: "JWT", Kid: kid})
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64.EncodeToString(sig), nil
}

// ErrInvalid is returned for malformed tokens or bad signatures.
var ErrInvalid = errors.New("invalid token")

// Parse decodes a token without verifying it, returning its kid and claims.
func Parse(token string) (kid string, claims Claims, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", nil, ErrInvalid
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return "", nil, ErrInvalid
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil || h.Alg != "RS256" {
		return "", nil, ErrInvalid
	}
	pb, err := b64.DecodeString(parts[1])
	if err != nil {
		return "", nil, ErrInvalid
	}
	if err := json.Unmarshal(pb, &claims); err != nil {
		return "", nil, ErrInvalid
	}
	return h.Kid, claims, nil
}

// Verify checks the RS256 signature of token using the key returned by
// lookup for the token's kid, and returns the claims.
func Verify(token string, lookup func(kid string) *rsa.PublicKey) (Claims, error) {
	kid, claims, err := Parse(token)
	if err != nil {
		return nil, err
	}
	pub := lookup(kid)
	if pub == nil {
		return nil, ErrInvalid
	}
	i := strings.LastIndexByte(token, '.')
	sig, err := b64.DecodeString(token[i+1:])
	if err != nil {
		return nil, ErrInvalid
	}
	sum := sha256.Sum256([]byte(token[:i]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return nil, ErrInvalid
	}
	return claims, nil
}

// JWK is a JSON Web Key for an RSA public key.
type JWK struct {
	Kid     string   `json:"kid"`
	Kty     string   `json:"kty"`
	Alg     string   `json:"alg"`
	Use     string   `json:"use"`
	N       string   `json:"n"`
	E       string   `json:"e"`
	X5c     []string `json:"x5c,omitempty"`
	X5tS256 string   `json:"x5t#S256,omitempty"`
}

// PublicJWK builds the JWK for a public key.
func PublicJWK(kid string, pub *rsa.PublicKey) JWK {
	return JWK{
		Kid: kid, Kty: "RSA", Alg: "RS256", Use: "sig",
		N: b64.EncodeToString(pub.N.Bytes()),
		E: b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// GenerateKey creates a 2048-bit RSA key and returns it PEM encoded along
// with a key id derived from the public key.
func GenerateKey() (key *rsa.PrivateKey, pemStr, kid string, err error) {
	key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", "", err
	}
	pemStr = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	return key, pemStr, KeyID(&key.PublicKey), nil
}

// KeyID derives a stable key id from a public key.
func KeyID(pub *rsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	sum := sha256.Sum256(der)
	return b64.EncodeToString(sum[:])[:43]
}

// ParsePrivateKey decodes a PEM encoded RSA private key (PKCS#8 or PKCS#1).
func ParsePrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}
	return rk, nil
}

// PublicKeyBase64 returns the DER (SubjectPublicKeyInfo) public key in
// standard base64, the format Keycloak publishes in its realm info.
func PublicKeyBase64(pub *rsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	return base64.StdEncoding.EncodeToString(der)
}
