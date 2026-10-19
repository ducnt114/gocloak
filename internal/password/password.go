// Package password hashes and verifies passwords using the same algorithms
// and storage layout as Keycloak (argon2 and pbkdf2-*), so credentials from a
// Keycloak realm export can be imported and verified unchanged.
package password

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strconv"

	"golang.org/x/crypto/argon2"
)

// SecretData is the JSON stored in credential.secretData.
type SecretData struct {
	Value                string              `json:"value"`
	Salt                 string              `json:"salt"`
	AdditionalParameters map[string][]string `json:"additionalParameters"`
}

// CredentialData is the JSON stored in credential.credentialData.
type CredentialData struct {
	HashIterations       int                 `json:"hashIterations"`
	Algorithm            string              `json:"algorithm"`
	AdditionalParameters map[string][]string `json:"additionalParameters"`
}

// Hasher creates new password hashes.
type Hasher struct {
	// Algorithm is "argon2", "pbkdf2-sha512", "pbkdf2-sha256" or "pbkdf2".
	Algorithm  string
	Iterations int
}

// Default mirrors Keycloak's default (argon2id, 5 iterations, 7 MiB).
var Default = Hasher{Algorithm: "argon2", Iterations: 5}

const (
	argonMemory      = 7168
	argonParallelism = 1
	argonHashLength  = 32
)

// Hash returns the secretData and credentialData JSON documents.
func (h Hasher) Hash(password string) (secretData, credentialData string, err error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}
	sd := SecretData{Salt: base64.StdEncoding.EncodeToString(salt), AdditionalParameters: map[string][]string{}}
	cd := CredentialData{Algorithm: h.Algorithm, HashIterations: h.Iterations, AdditionalParameters: map[string][]string{}}
	var sum []byte
	switch h.Algorithm {
	case "argon2":
		if cd.HashIterations <= 0 {
			cd.HashIterations = 5
		}
		sum = argon2.IDKey([]byte(password), salt, uint32(cd.HashIterations), argonMemory, argonParallelism, argonHashLength)
		cd.AdditionalParameters = map[string][]string{
			"hashLength":  {strconv.Itoa(argonHashLength)},
			"memory":      {strconv.Itoa(argonMemory)},
			"type":        {"id"},
			"version":     {"1.3"},
			"parallelism": {strconv.Itoa(argonParallelism)},
		}
	default:
		hf, err := pbkdf2Hash(h.Algorithm)
		if err != nil {
			return "", "", err
		}
		if cd.HashIterations <= 0 {
			cd.HashIterations = 210000
		}
		sum, err = pbkdf2.Key(hf, password, salt, cd.HashIterations, 64)
		if err != nil {
			return "", "", err
		}
	}
	sd.Value = base64.StdEncoding.EncodeToString(sum)
	sdb, _ := json.Marshal(sd)
	cdb, _ := json.Marshal(cd)
	return string(sdb), string(cdb), nil
}

// Verify checks password against a stored credential.
func Verify(password, secretData, credentialData string) (bool, error) {
	var sd SecretData
	var cd CredentialData
	if err := json.Unmarshal([]byte(secretData), &sd); err != nil {
		return false, fmt.Errorf("secretData: %w", err)
	}
	if err := json.Unmarshal([]byte(credentialData), &cd); err != nil {
		return false, fmt.Errorf("credentialData: %w", err)
	}
	want, err := base64.StdEncoding.DecodeString(sd.Value)
	if err != nil {
		return false, err
	}
	salt, err := base64.StdEncoding.DecodeString(sd.Salt)
	if err != nil {
		return false, err
	}
	var got []byte
	switch cd.Algorithm {
	case "argon2":
		p := func(name string, def int) int {
			if v := cd.AdditionalParameters[name]; len(v) > 0 {
				if n, err := strconv.Atoi(v[0]); err == nil {
					return n
				}
			}
			return def
		}
		typ := "id"
		if v := cd.AdditionalParameters["type"]; len(v) > 0 {
			typ = v[0]
		}
		if v := cd.AdditionalParameters["version"]; len(v) > 0 && v[0] != "1.3" {
			return false, fmt.Errorf("unsupported argon2 version %s", v[0])
		}
		iter, mem, par, klen := uint32(cd.HashIterations), uint32(p("memory", argonMemory)), uint8(p("parallelism", argonParallelism)), uint32(len(want))
		switch typ {
		case "id":
			got = argon2.IDKey([]byte(password), salt, iter, mem, par, klen)
		case "i":
			got = argon2.Key([]byte(password), salt, iter, mem, par, klen)
		default:
			return false, fmt.Errorf("unsupported argon2 type %q", typ)
		}
	default:
		hf, err := pbkdf2Hash(cd.Algorithm)
		if err != nil {
			return false, err
		}
		got, err = pbkdf2.Key(hf, password, salt, cd.HashIterations, len(want))
		if err != nil {
			return false, err
		}
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func pbkdf2Hash(alg string) (func() hash.Hash, error) {
	switch alg {
	case "pbkdf2-sha512":
		return sha512.New, nil
	case "pbkdf2-sha256":
		return sha256.New, nil
	case "pbkdf2":
		return sha1.New, nil
	}
	return nil, errors.New("unsupported password hash algorithm: " + alg)
}
