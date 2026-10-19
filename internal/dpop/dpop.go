// Package dpop verifies OAuth 2.0 Demonstrating Proof of Possession
// (DPoP, RFC 9449) proofs.
package dpop

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/jwt"
)

// Proof is a verified DPoP proof.
type Proof struct {
	JKT string // thumbprint of the proof's public key
	JTI string
	IAT time.Time
}

// Error is an invalid proof; its message is safe to return to clients.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func fail(msg string) error { return &Error{msg} }

// Accepted clock skew and proof lifetime.
const (
	MaxAge  = 60 * time.Second
	MaxSkew = 10 * time.Second
)

// Verify checks a DPoP proof sent with an HTTP request: its type, signature
// with the embedded public key, the method and URL it was made for, its
// age, and, for requests to resources, the hash of the access token.
func Verify(proof, method, requestURL, accessToken string, now time.Time) (*Proof, error) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return nil, fail("DPoP proof is invalid")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fail("DPoP proof is invalid")
	}
	var header struct {
		Typ string          `json:"typ"`
		Alg string          `json:"alg"`
		JWK json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, fail("DPoP proof is invalid")
	}
	if header.Typ != "dpop+jwt" {
		return nil, fail("Invalid or missing type in DPoP header: " + header.Typ)
	}
	if f := jwt.Family(header.Alg); f == "" || f == "OCT" {
		return nil, fail("Unsupported DPoP algorithm: " + header.Alg)
	}
	var priv struct {
		D string `json:"d"`
	}
	var jwk jwt.JWK
	if len(header.JWK) == 0 || json.Unmarshal(header.JWK, &jwk) != nil || json.Unmarshal(header.JWK, &priv) != nil || priv.D != "" {
		return nil, fail("No JWK in DPoP header")
	}
	key, err := jwt.KeyFromJWK(jwk, header.Alg)
	if err != nil {
		return nil, fail("No JWK in DPoP header")
	}
	key.Alg = header.Alg
	claims, err := jwt.Verify(proof, func(string, string) *jwt.Key { return key })
	if err != nil {
		return nil, fail("DPoP verification failure")
	}
	if claims.String("htm") != method {
		return nil, fail("DPoP HTTP method mismatch")
	}
	if !sameURL(claims.String("htu"), requestURL) {
		return nil, fail("DPoP HTTP URL mismatch")
	}
	jti := claims.String("jti")
	if jti == "" {
		return nil, fail("DPoP proof has no jti")
	}
	iat := time.Unix(claims.Int("iat"), 0)
	if iat.After(now.Add(MaxSkew)) || iat.Before(now.Add(-MaxAge)) {
		return nil, fail("DPoP proof is not active")
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		if claims.String("ath") != base64.RawURLEncoding.EncodeToString(sum[:]) {
			return nil, fail("DPoP proof access token hash mismatch")
		}
	}
	jkt, err := jwk.Thumbprint()
	if err != nil {
		return nil, fail("No JWK in DPoP header")
	}
	return &Proof{JKT: jkt, JTI: jti, IAT: iat}, nil
}

// sameURL compares URLs without their query and fragment, with the scheme
// and host compared case-insensitively.
func sameURL(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host) && ua.Path == ub.Path
}

// IsError reports whether err is an invalid proof.
func IsError(err error) bool {
	var e *Error
	return errors.As(err, &e)
}
