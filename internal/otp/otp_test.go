package otp

import (
	"testing"
	"time"
)

// RFC 6238 test vectors (SHA1, 8 digits) and RFC 4226 (HOTP, 6 digits).
func TestVectors(t *testing.T) {
	secret := "12345678901234567890"
	for _, v := range []struct {
		t    int64
		code string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1234567890, "89005924"}, {2000000000, "69279037"}} {
		if got := Code(secret, uint64(v.t/30), 8, "HmacSHA1"); got != v.code {
			t.Errorf("TOTP at %d = %s, want %s", v.t, got, v.code)
		}
	}
	for i, want := range []string{"755224", "287082", "359152", "969429"} {
		if got := Code(secret, uint64(i), 6, "HmacSHA1"); got != want {
			t.Errorf("HOTP %d = %s, want %s", i, got, want)
		}
	}
	if Code(secret, 1, 8, "HmacSHA256") == Code(secret, 1, 8, "HmacSHA1") {
		t.Fatal("algorithm ignored")
	}
}

func TestValidate(t *testing.T) {
	secret := GenerateSecret()
	cd := CredentialData{SubType: "totp", Digits: 6, Period: 30, Algorithm: "HmacSHA1"}
	now := time.Unix(1700000000, 0)
	code := Code(secret, uint64(now.Unix()/30), 6, "HmacSHA1")
	if !ValidateTOTP(code, secret, cd, 1, now.Add(30*time.Second)) {
		t.Fatal("code rejected within window")
	}
	if ValidateTOTP(code, secret, cd, 1, now.Add(90*time.Second)) {
		t.Fatal("code accepted outside window")
	}
	h := CredentialData{SubType: "hotp", Digits: 6, Counter: 5, Algorithm: "HmacSHA1"}
	next, ok := ValidateHOTP(Code(secret, 6, 6, "HmacSHA1"), secret, h, 1)
	if !ok || next != 7 {
		t.Fatalf("HOTP: %v %d", ok, next)
	}
}
