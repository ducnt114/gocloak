// Package otp implements TOTP (RFC 6238) and HOTP (RFC 4226) one-time
// passwords, and how OTP credentials are stored and checked.
package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Policy is a realm's OTP policy.
type Policy struct {
	Type      string // "totp" or "hotp"
	Algorithm string // HmacSHA1, HmacSHA256, HmacSHA512
	Digits    int
	Period    int // seconds, TOTP
	LookAhead int // window, in periods (TOTP) or counter values (HOTP)
	Counter   int // initial counter, HOTP
}

// CredentialData is the credentialData JSON of an "otp" credential.
type CredentialData struct {
	SubType   string `json:"subType"`
	Digits    int    `json:"digits"`
	Counter   int    `json:"counter"`
	Period    int    `json:"period"`
	Algorithm string `json:"algorithm"`
}

// SecretData is the secretData JSON of an "otp" credential.
type SecretData struct {
	Value string `json:"value"`
}

const secretChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

// GenerateSecret returns a 20 character secret. The HMAC
// key is the secret's bytes and authenticator apps get its base32 form.
func GenerateSecret() string {
	b := make([]byte, 20)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(secretChars))))
		if err != nil {
			panic(err)
		}
		b[i] = secretChars[n.Int64()]
	}
	return string(b)
}

// Base32 is the secret as entered in authenticator apps.
func Base32(secret string) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(secret))
}

func newHash(alg string) func() hash.Hash {
	switch alg {
	case "HmacSHA256":
		return sha256.New
	case "HmacSHA512":
		return sha512.New
	}
	return sha1.New
}

// Code computes the code for a counter value.
func Code(secret string, counter uint64, digits int, algorithm string) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(newHash(algorithm), []byte(secret))
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// ValidateTOTP checks a TOTP code at time now within the look-ahead window.
func ValidateTOTP(code, secret string, cd CredentialData, window int, now time.Time) bool {
	period := cd.Period
	if period <= 0 {
		period = 30
	}
	step := now.Unix() / int64(period)
	for d := -int64(window); d <= int64(window); d++ {
		if hmac.Equal([]byte(Code(secret, uint64(step+d), cd.Digits, cd.Algorithm)), []byte(code)) {
			return true
		}
	}
	return false
}

// ValidateHOTP checks an HOTP code and returns the counter to store next.
func ValidateHOTP(code, secret string, cd CredentialData, window int) (int, bool) {
	for c := cd.Counter; c <= cd.Counter+window; c++ {
		if hmac.Equal([]byte(Code(secret, uint64(c), cd.Digits, cd.Algorithm)), []byte(code)) {
			return c + 1, true
		}
	}
	return cd.Counter, false
}

// Credential builds the stored secretData and credentialData of a new OTP credential.
func Credential(secret string, p Policy) (secretData, credentialData string) {
	sd, _ := json.Marshal(SecretData{Value: secret})
	cd, _ := json.Marshal(CredentialData{SubType: p.Type, Digits: p.Digits, Counter: p.Counter, Period: p.Period, Algorithm: p.Algorithm})
	return string(sd), string(cd)
}

// KeyURI is the otpauth:// URI shown as a QR code.
func KeyURI(secret, issuer, account string, p Policy) string {
	alg := strings.TrimPrefix(p.Algorithm, "Hmac")
	q := url.Values{"secret": {Base32(secret)}, "digits": {strconv.Itoa(p.Digits)}, "algorithm": {alg}, "issuer": {issuer}}
	if p.Type == "hotp" {
		q.Set("counter", strconv.Itoa(p.Counter))
	} else {
		q.Set("period", strconv.Itoa(p.Period))
	}
	return "otpauth://" + p.Type + "/" + url.PathEscape(issuer) + ":" + url.PathEscape(account) + "?" + q.Encode()
}
