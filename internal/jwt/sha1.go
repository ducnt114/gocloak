package jwt

import "crypto/sha1"

// sha1Sum computes the x5t thumbprint, which JWK defines with SHA-1.
func sha1Sum(b []byte) []byte {
	s := sha1.Sum(b)
	return s[:]
}
