// Package jwt implements the JWS and JWK features gocloak needs: signing
// and verification with RS*, PS*, ES* and HS* algorithms, key generation
// (RSA keys come with a self-signed certificate, as in Keycloak) and JWK
// import/export.
package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"
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

// Header is the JOSE header.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
}

// Key is a signing or verification key. Private is set for asymmetric
// signing keys, Public for asymmetric verification, Secret for HMAC.
type Key struct {
	Kid         string
	Alg         string
	Private     crypto.Signer
	Public      crypto.PublicKey
	Secret      []byte
	Certificate *x509.Certificate
}

// ErrInvalid is returned for malformed tokens or bad signatures.
var ErrInvalid = errors.New("invalid token")

// Supported algorithms.
var Algorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "HS256", "HS384", "HS512"}

func hashFor(alg string) (crypto.Hash, func() hash.Hash, error) {
	if len(alg) != 5 {
		return 0, nil, fmt.Errorf("unsupported algorithm %q", alg)
	}
	switch alg[2:] {
	case "256":
		return crypto.SHA256, sha256.New, nil
	case "384":
		return crypto.SHA384, sha512.New384, nil
	case "512":
		return crypto.SHA512, sha512.New, nil
	}
	return 0, nil, fmt.Errorf("unsupported algorithm %q", alg)
}

// Family returns "RSA", "EC" or "OCT" for an algorithm.
func Family(alg string) string {
	switch {
	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"):
		return "RSA"
	case strings.HasPrefix(alg, "ES"):
		return "EC"
	case strings.HasPrefix(alg, "HS"):
		return "OCT"
	}
	return ""
}

func ecSize(curve elliptic.Curve) int { return (curve.Params().BitSize + 7) / 8 }

// Sign produces a compact JWS of claims with key k (and k.Alg).
func Sign(claims Claims, k *Key) (string, error) {
	return SignTyped(claims, k, "JWT")
}

// SignTyped is Sign with the given "typ" header (e.g. logout+jwt).
func SignTyped(claims Claims, k *Key, typ string) (string, error) {
	h, _ := json.Marshal(Header{Alg: k.Alg, Typ: typ, Kid: k.Kid})
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	sig, err := signBytes(k, []byte(signing))
	if err != nil {
		return "", err
	}
	return signing + "." + b64.EncodeToString(sig), nil
}

func signBytes(k *Key, data []byte) ([]byte, error) {
	ch, newHash, err := hashFor(k.Alg)
	if err != nil {
		return nil, err
	}
	switch Family(k.Alg) {
	case "OCT":
		if len(k.Secret) == 0 {
			return nil, errors.New("missing HMAC secret")
		}
		m := hmac.New(newHash, k.Secret)
		m.Write(data)
		return m.Sum(nil), nil
	}
	hh := newHash()
	hh.Write(data)
	digest := hh.Sum(nil)
	switch priv := k.Private.(type) {
	case *rsa.PrivateKey:
		if strings.HasPrefix(k.Alg, "PS") {
			return rsa.SignPSS(rand.Reader, priv, ch, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		if !strings.HasPrefix(k.Alg, "RS") {
			return nil, fmt.Errorf("algorithm %s does not match an RSA key", k.Alg)
		}
		return rsa.SignPKCS1v15(rand.Reader, priv, ch, digest)
	case *ecdsa.PrivateKey:
		if !strings.HasPrefix(k.Alg, "ES") {
			return nil, fmt.Errorf("algorithm %s does not match an EC key", k.Alg)
		}
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
		if err != nil {
			return nil, err
		}
		size := ecSize(priv.Curve)
		out := make([]byte, 2*size)
		r.FillBytes(out[:size])
		s.FillBytes(out[size:])
		return out, nil
	}
	return nil, errors.New("unsupported signing key")
}

// Parse decodes a token without verifying it.
func Parse(token string) (Header, Claims, error) {
	var h Header
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return h, nil, ErrInvalid
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return h, nil, ErrInvalid
	}
	if err := json.Unmarshal(hb, &h); err != nil || h.Alg == "" || h.Alg == "none" {
		return h, nil, ErrInvalid
	}
	pb, err := b64.DecodeString(parts[1])
	if err != nil {
		return h, nil, ErrInvalid
	}
	var claims Claims
	if err := json.Unmarshal(pb, &claims); err != nil {
		return h, nil, ErrInvalid
	}
	return h, claims, nil
}

// Verify checks the signature of token with the key returned by lookup for
// the token's kid and alg, and returns the claims. The key's algorithm must
// equal the token's, which rules out algorithm confusion.
func Verify(token string, lookup func(kid, alg string) *Key) (Claims, error) {
	h, claims, err := Parse(token)
	if err != nil {
		return nil, err
	}
	k := lookup(h.Kid, h.Alg)
	if k == nil || k.Alg != h.Alg {
		return nil, ErrInvalid
	}
	i := strings.LastIndexByte(token, '.')
	sig, err := b64.DecodeString(token[i+1:])
	if err != nil {
		return nil, ErrInvalid
	}
	if err := verifyBytes(k, []byte(token[:i]), sig); err != nil {
		return nil, ErrInvalid
	}
	return claims, nil
}

func verifyBytes(k *Key, data, sig []byte) error {
	ch, newHash, err := hashFor(k.Alg)
	if err != nil {
		return err
	}
	if Family(k.Alg) == "OCT" {
		if len(k.Secret) == 0 {
			return ErrInvalid
		}
		m := hmac.New(newHash, k.Secret)
		m.Write(data)
		if !hmac.Equal(m.Sum(nil), sig) {
			return ErrInvalid
		}
		return nil
	}
	hh := newHash()
	hh.Write(data)
	digest := hh.Sum(nil)
	pub := k.Public
	if pub == nil && k.Private != nil {
		pub = k.Private.Public()
	}
	switch p := pub.(type) {
	case *rsa.PublicKey:
		if strings.HasPrefix(k.Alg, "PS") {
			return rsa.VerifyPSS(p, ch, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
		}
		return rsa.VerifyPKCS1v15(p, ch, digest, sig)
	case *ecdsa.PublicKey:
		size := ecSize(p.Curve)
		if len(sig) != 2*size {
			return ErrInvalid
		}
		r, s := new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(p, digest, r, s) {
			return ErrInvalid
		}
		return nil
	}
	return ErrInvalid
}

// ---------------------------------------------------------------- JWK

// JWK is a JSON Web Key.
type JWK struct {
	Kid     string   `json:"kid"`
	Kty     string   `json:"kty"`
	Alg     string   `json:"alg,omitempty"`
	Use     string   `json:"use,omitempty"`
	N       string   `json:"n,omitempty"`
	E       string   `json:"e,omitempty"`
	Crv     string   `json:"crv,omitempty"`
	X       string   `json:"x,omitempty"`
	Y       string   `json:"y,omitempty"`
	X5c     []string `json:"x5c,omitempty"`
	X5t     string   `json:"x5t,omitempty"`
	X5tS256 string   `json:"x5t#S256,omitempty"`
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint of a public JWK.
func (j JWK) Thumbprint() (string, error) {
	var members string
	switch j.Kty {
	case "RSA":
		if j.N == "" || j.E == "" {
			return "", ErrInvalid
		}
		members = `{"e":"` + j.E + `","kty":"RSA","n":"` + j.N + `"}`
	case "EC":
		if j.Crv == "" || j.X == "" || j.Y == "" {
			return "", ErrInvalid
		}
		members = `{"crv":"` + j.Crv + `","kty":"EC","x":"` + j.X + `","y":"` + j.Y + `"}`
	default:
		return "", ErrInvalid
	}
	sum := sha256.Sum256([]byte(members))
	return b64.EncodeToString(sum[:]), nil
}

// JWK returns the public JWK of an asymmetric key.
func (k *Key) JWK() (JWK, bool) {
	pub := k.Public
	if pub == nil && k.Private != nil {
		pub = k.Private.Public()
	}
	j := JWK{Kid: k.Kid, Alg: k.Alg, Use: "sig"}
	switch p := pub.(type) {
	case *rsa.PublicKey:
		j.Kty, j.N, j.E = "RSA", b64.EncodeToString(p.N.Bytes()), b64.EncodeToString(big.NewInt(int64(p.E)).Bytes())
	case *ecdsa.PublicKey:
		size := ecSize(p.Curve)
		x, y := make([]byte, size), make([]byte, size)
		p.X.FillBytes(x)
		p.Y.FillBytes(y)
		j.Kty, j.Crv, j.X, j.Y = "EC", p.Curve.Params().Name, b64.EncodeToString(x), b64.EncodeToString(y)
	default:
		return j, false
	}
	if k.Certificate != nil {
		j.X5c = []string{base64.StdEncoding.EncodeToString(k.Certificate.Raw)}
		s1 := sha1Sum(k.Certificate.Raw)
		j.X5t = b64.EncodeToString(s1)
		s256 := sha256.Sum256(k.Certificate.Raw)
		j.X5tS256 = b64.EncodeToString(s256[:])
	}
	return j, true
}

// KeyFromJWK imports a public JWK (RSA or EC). defaultAlg is used when the
// JWK does not name its algorithm.
func KeyFromJWK(j JWK, defaultAlg string) (*Key, error) {
	alg := j.Alg
	if alg == "" {
		alg = defaultAlg
	}
	k := &Key{Kid: j.Kid, Alg: alg}
	switch j.Kty {
	case "RSA":
		n, err1 := b64.DecodeString(j.N)
		e, err2 := b64.DecodeString(j.E)
		if err1 != nil || err2 != nil || len(n) == 0 || len(e) == 0 {
			return nil, errors.New("invalid RSA JWK")
		}
		k.Public = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	case "EC":
		curve := curveByName(j.Crv)
		x, err1 := b64.DecodeString(j.X)
		y, err2 := b64.DecodeString(j.Y)
		if curve == nil || err1 != nil || err2 != nil {
			return nil, errors.New("invalid EC JWK")
		}
		k.Public = &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	default:
		return nil, fmt.Errorf("unsupported JWK type %q", j.Kty)
	}
	if len(j.X5c) > 0 {
		if der, err := base64.StdEncoding.DecodeString(j.X5c[0]); err == nil {
			k.Certificate, _ = x509.ParseCertificate(der)
		}
	}
	return k, nil
}

func curveByName(name string) elliptic.Curve {
	switch name {
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	}
	return nil
}

// CurveForAlg returns the curve name of an ES algorithm.
func CurveForAlg(alg string) string {
	switch alg {
	case "ES384":
		return "P-384"
	case "ES512":
		return "P-521"
	}
	return "P-256"
}

// ---------------------------------------------------------------- generation

// GenerateRSA creates an RSA key and a self-signed certificate for it.
func GenerateRSA(bits int, alg, commonName string) (*Key, error) {
	if bits < 2048 {
		bits = 2048
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return finishKey(priv, alg, commonName)
}

// GenerateEC creates an ECDSA key for an ES algorithm.
func GenerateEC(alg, commonName string) (*Key, error) {
	priv, err := ecdsa.GenerateKey(curveByName(CurveForAlg(alg)), rand.Reader)
	if err != nil {
		return nil, err
	}
	return finishKey(priv, alg, commonName)
}

func finishKey(priv crypto.Signer, alg, commonName string) (*Key, error) {
	k := &Key{Alg: alg, Private: priv, Public: priv.Public()}
	cert, err := SelfSignedCertificate(priv, commonName)
	if err != nil {
		return nil, err
	}
	k.Certificate = cert
	k.Kid = KeyID(priv.Public())
	return k, nil
}

// GenerateHMAC creates a random HMAC secret of size bytes.
func GenerateHMAC(alg string, size int) (*Key, error) {
	if size < 32 {
		size = 64
	}
	secret := make([]byte, size)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return &Key{Alg: alg, Secret: secret}, nil
}

// SelfSignedCertificate issues a 10 year certificate for priv, like the
// certificates Keycloak generates for its realm keys.
func SelfSignedCertificate(priv crypto.Signer, commonName string) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.AddDate(10, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// KeyID derives a stable key id from a public key.
func KeyID(pub crypto.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	sum := sha256.Sum256(der)
	return b64.EncodeToString(sum[:])[:43]
}

// ---------------------------------------------------------------- encoding

// EncodePrivateKey PEM-encodes an RSA or EC private key (PKCS#8).
func EncodePrivateKey(priv crypto.Signer) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// ParsePrivateKey decodes a PEM (PKCS#8, PKCS#1 or SEC1) private key. The
// PEM armor may be omitted, as Keycloak stores bare base64 keys.
func ParsePrivateKey(s string) (crypto.Signer, error) {
	der, err := pemOrBase64(s)
	if err != nil {
		return nil, err
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("unsupported private key type")
	}
	return signer, nil
}

// ParseCertificate decodes a PEM or bare base64 DER certificate.
func ParseCertificate(s string) (*x509.Certificate, error) {
	der, err := pemOrBase64(s)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// EncodeCertificate returns the bare base64 DER of a certificate.
func EncodeCertificate(c *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(c.Raw)
}

func pemOrBase64(s string) ([]byte, error) {
	if block, _ := pem.Decode([]byte(s)); block != nil {
		return block.Bytes, nil
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		return nil, errors.New("invalid PEM or base64 data")
	}
	return der, nil
}

// PublicKeyBase64 returns the DER (SubjectPublicKeyInfo) public key in
// standard base64, the format Keycloak publishes.
func PublicKeyBase64(pub crypto.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	return base64.StdEncoding.EncodeToString(der)
}
