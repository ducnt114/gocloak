package password

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestHashVerify(t *testing.T) {
	for _, h := range []Hasher{Default, {Algorithm: "pbkdf2-sha512", Iterations: 1000}, {Algorithm: "pbkdf2-sha256", Iterations: 1000}, {Algorithm: "pbkdf2", Iterations: 1000}} {
		t.Run(h.Algorithm, func(t *testing.T) {
			sd, cd, err := h.Hash("s3cret")
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := Verify("s3cret", sd, cd); err != nil || !ok {
				t.Fatalf("expected match, got %v %v", ok, err)
			}
			if ok, _ := Verify("wrong", sd, cd); ok {
				t.Fatal("expected mismatch")
			}
		})
	}
}

// A credential in the layout of a Keycloak realm export.
func TestVerifyKeycloakExport(t *testing.T) {
	salt := []byte("0123456789abcdef")
	sum, _ := pbkdf2.Key(sha256.New, "admin", salt, 27500, 32)
	sd := fmt.Sprintf(`{"value":%q,"salt":%q,"additionalParameters":{}}`,
		base64.StdEncoding.EncodeToString(sum), base64.StdEncoding.EncodeToString(salt))
	cd := `{"hashIterations":27500,"algorithm":"pbkdf2-sha256","additionalParameters":{}}`
	if ok, err := Verify("admin", sd, cd); err != nil || !ok {
		t.Fatalf("expected match, got %v %v", ok, err)
	}
}
