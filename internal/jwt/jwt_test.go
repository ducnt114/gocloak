package jwt

import (
	"strings"
	"testing"
)

func TestSignVerifyAllAlgorithms(t *testing.T) {
	for _, alg := range Algorithms {
		t.Run(alg, func(t *testing.T) {
			var k *Key
			var err error
			switch Family(alg) {
			case "RSA":
				k, err = GenerateRSA(2048, alg, "test")
			case "EC":
				k, err = GenerateEC(alg, "test")
			case "OCT":
				k, err = GenerateHMAC(alg, 64)
				k.Kid = "hmac"
			}
			if err != nil {
				t.Fatal(err)
			}
			tok, err := Sign(Claims{"sub": "u1", "exp": 123}, k)
			if err != nil {
				t.Fatal(err)
			}
			lookup := func(kid, a string) *Key {
				if kid == k.Kid {
					return k
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
			if j, ok := k.JWK(); ok {
				imported, err := KeyFromJWK(j, alg)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Verify(tok, func(string, string) *Key { return imported }); err != nil {
					t.Fatalf("verify with imported JWK: %v", err)
				}
			}
		})
	}
}

func TestAlgorithmConfusion(t *testing.T) {
	k, _ := GenerateRSA(2048, "RS256", "test")
	tok, _ := Sign(Claims{"sub": "x"}, k)
	// A token claiming HS256 must not verify against the RSA key.
	h := b64.EncodeToString([]byte(`{"alg":"HS256","kid":"` + k.Kid + `"}`))
	forged := h + tok[strings.IndexByte(tok, '.'):]
	if _, err := Verify(forged, func(string, string) *Key { return k }); err == nil {
		t.Fatal("algorithm confusion accepted")
	}
}

func TestPrivateKeyEncoding(t *testing.T) {
	k, _ := GenerateEC("ES256", "test")
	s, err := EncodePrivateKey(k.Private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePrivateKey(s); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCertificate(EncodeCertificate(k.Certificate)); err != nil {
		t.Fatal(err)
	}
}
