package jwt

import (
	"crypto/rsa"
	"strings"
	"testing"
)

func TestSignVerify(t *testing.T) {
	key, pemStr, kid, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePrivateKey(pemStr)
	if err != nil || !parsed.Equal(key) {
		t.Fatalf("PEM round trip failed: %v", err)
	}
	tok, err := Sign(Claims{"sub": "u1", "exp": 123}, kid, key)
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(k string) *rsa.PublicKey {
		if k == kid {
			return &key.PublicKey
		}
		return nil
	}
	c, err := Verify(tok, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if c.String("sub") != "u1" || c.Int("exp") != 123 {
		t.Fatalf("unexpected claims %v", c)
	}

	parts := strings.Split(tok, ".")
	tampered := parts[0] + "." + b64.EncodeToString([]byte(`{"sub":"admin"}`)) + "." + parts[2]
	if _, err := Verify(tampered, lookup); err == nil {
		t.Fatal("tampered token verified")
	}
}
