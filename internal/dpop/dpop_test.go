package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/ducnt114/gocloak/internal/jwt"
)

func proof(t *testing.T, priv *ecdsa.PrivateKey, header map[string]any, claims map[string]any) string {
	t.Helper()
	b64 := base64.RawURLEncoding
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	signing := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
	sum := sha256.Sum256([]byte(signing))
	r, s, _ := ecdsa.Sign(rand.Reader, priv, sum[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + b64.EncodeToString(sig)
}

func TestVerify(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k := &jwt.Key{Alg: "ES256", Private: priv, Public: &priv.PublicKey}
	jwk, _ := k.JWK()
	now := time.Now()
	const u = "https://idp.example/realms/r/protocol/openid-connect/token"
	header := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
	claims := func(kv ...any) map[string]any {
		c := map[string]any{"jti": "j1", "htm": "POST", "htu": u, "iat": now.Unix()}
		for i := 0; i+1 < len(kv); i += 2 {
			c[kv[i].(string)] = kv[i+1]
		}
		return c
	}
	p, err := Verify(proof(t, priv, header, claims()), "POST", u+"?x=1", "", now)
	want, _ := jwk.Thumbprint()
	if err != nil || p.JKT != want {
		t.Fatalf("valid proof: %v %+v", err, p)
	}
	sum := sha256.Sum256([]byte("tok"))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	if _, err := Verify(proof(t, priv, header, claims("ath", ath)), "POST", u, "tok", now); err != nil {
		t.Fatalf("ath: %v", err)
	}
	withJWK := func(extra map[string]any) map[string]any {
		b, _ := json.Marshal(jwk)
		var m map[string]any
		json.Unmarshal(b, &m)
		for k, v := range extra {
			m[k] = v
		}
		return map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": m}
	}
	for name, tc := range map[string]struct {
		header, claims map[string]any
		method, token  string
	}{
		"wrong typ":     {map[string]any{"typ": "JWT", "alg": "ES256", "jwk": jwk}, claims(), "POST", ""},
		"private key":   {withJWK(map[string]any{"d": "secret"}), claims(), "POST", ""},
		"no jwk":        {map[string]any{"typ": "dpop+jwt", "alg": "ES256"}, claims(), "POST", ""},
		"wrong method":  {header, claims(), "GET", ""},
		"wrong url":     {header, claims("htu", "https://other/token"), "POST", ""},
		"old":           {header, claims("iat", now.Add(-2*MaxAge).Unix()), "POST", ""},
		"future":        {header, claims("iat", now.Add(2*MaxSkew).Unix()), "POST", ""},
		"no jti":        {header, claims("jti", ""), "POST", ""},
		"missing ath":   {header, claims(), "POST", "tok"},
		"symmetric alg": {map[string]any{"typ": "dpop+jwt", "alg": "HS256", "jwk": jwk}, claims(), "POST", ""},
	} {
		if _, err := Verify(proof(t, priv, tc.header, tc.claims), tc.method, u, tc.token, now); !IsError(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
