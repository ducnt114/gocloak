package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/store"
)

// KeyProviderType is the component type of key providers.
const KeyProviderType = "org.keycloak.keys.KeyProvider"

// Key provider ids, as in Keycloak.
const (
	KeyRSAGenerated   = "rsa-generated"
	KeyRSAImported    = "rsa"
	KeyECDSAGenerated = "ecdsa-generated"
	KeyHMACGenerated  = "hmac-generated"
)

// KeyProviders lists the supported key provider ids.
var KeyProviders = map[string]bool{KeyRSAGenerated: true, KeyRSAImported: true, KeyECDSAGenerated: true, KeyHMACGenerated: true}

// SecretKeyConfig lists component config keys that must never be returned.
var SecretKeyConfig = map[string]bool{"privateKey": true, "secret": true, "ecPrivateKey": true}

// RealmKey is a key of a realm with its provider metadata.
type RealmKey struct {
	*jwt.Key
	ComponentID string
	Provider    string
	Priority    int64
	Active      bool
	Enabled     bool
}

// Status is ACTIVE, PASSIVE or DISABLED, as shown by GET /keys.
func (k *RealmKey) Status() string {
	switch {
	case !k.Enabled:
		return "DISABLED"
	case !k.Active:
		return "PASSIVE"
	}
	return "ACTIVE"
}

type keySet struct {
	keys []*RealmKey // sorted by priority, highest first
}

func configBool(c *model.Component, key string, def bool) bool {
	switch c.Get(key) {
	case "true":
		return true
	case "false":
		return false
	}
	return def
}

// keyFromComponent loads the key material of a key provider component.
func keyFromComponent(c *model.Component) (*RealmKey, error) {
	prio, _ := strconv.ParseInt(c.Get("priority"), 10, 64)
	rk := &RealmKey{ComponentID: c.ID, Provider: c.ProviderID, Priority: prio,
		Active: configBool(c, "active", true), Enabled: configBool(c, "enabled", true)}
	alg := c.Get("algorithm")
	switch c.ProviderID {
	case KeyRSAGenerated, KeyRSAImported, KeyECDSAGenerated:
		if alg == "" {
			alg = "RS256"
			if c.ProviderID == KeyECDSAGenerated {
				alg = "ES" + strings.TrimPrefix(c.Get("ecdsaEllipticCurveKey"), "P-")
				if alg == "ES521" {
					alg = "ES512"
				}
			}
		}
		priv, err := jwt.ParsePrivateKey(c.Get("privateKey"))
		if err != nil {
			return nil, fmt.Errorf("key provider %s: %w", c.Name, err)
		}
		k := &jwt.Key{Alg: alg, Private: priv, Public: priv.Public(), Kid: jwt.KeyID(priv.Public())}
		if cert := c.Get("certificate"); cert != "" {
			if parsed, err := jwt.ParseCertificate(cert); err == nil {
				k.Certificate = parsed
			}
		}
		rk.Key = k
	case KeyHMACGenerated:
		if alg == "" {
			alg = "HS256"
		}
		secret, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(c.Get("secret"), "="))
		if err != nil || len(secret) == 0 {
			return nil, fmt.Errorf("key provider %s: invalid secret", c.Name)
		}
		rk.Key = &jwt.Key{Alg: alg, Secret: secret, Kid: c.Get("kid")}
	default:
		return nil, fmt.Errorf("unsupported key provider %q", c.ProviderID)
	}
	return rk, nil
}

// PrepareKeyComponent validates a key provider component and generates its
// key material when needed (on create, or when the algorithm or size changed).
func PrepareKeyComponent(c *model.Component, realmName string, previous *model.Component) error {
	if !KeyProviders[c.ProviderID] {
		return validationf("unsupported key provider %q", c.ProviderID)
	}
	c.ProviderType = KeyProviderType
	if c.Get("priority") == "" {
		c.Set("priority", "0")
	} else if _, err := strconv.ParseInt(c.Get("priority"), 10, 64); err != nil {
		return validationf("'Priority' should be a number")
	}
	for _, k := range []string{"enabled", "active"} {
		if c.Get(k) == "" {
			c.Set(k, "true")
		}
	}
	keep := func(keys ...string) bool {
		if previous == nil || previous.ProviderID != c.ProviderID {
			return false
		}
		for _, k := range keys {
			if c.Get(k) != previous.Get(k) {
				return false
			}
		}
		for _, k := range []string{"privateKey", "certificate", "secret", "kid"} {
			if v := previous.Get(k); v != "" && (c.Get(k) == "" || c.Get(k) == "**********") {
				c.Set(k, v)
			}
		}
		return true
	}
	switch c.ProviderID {
	case KeyRSAGenerated:
		alg := c.Get("algorithm")
		if alg == "" {
			alg = "RS256"
			c.Set("algorithm", alg)
		}
		if jwt.Family(alg) != "RSA" {
			return validationf("invalid algorithm %s for an RSA key", alg)
		}
		size := 2048
		if v := c.Get("keySize"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || (n != 1024 && n != 2048 && n != 4096) {
				return validationf("'Key size' should be 1024, 2048 or 4096")
			}
			size = n
		}
		c.Set("keySize", strconv.Itoa(size))
		if keep("keySize") {
			return nil
		}
		k, err := jwt.GenerateRSA(size, alg, realmName)
		if err != nil {
			return err
		}
		return storeAsymmetric(c, k)
	case KeyECDSAGenerated:
		curve := c.Get("ecdsaEllipticCurveKey")
		if curve == "" {
			curve = "P-256"
			c.Set("ecdsaEllipticCurveKey", curve)
		}
		alg := map[string]string{"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}[curve]
		if alg == "" {
			return validationf("invalid elliptic curve %s", curve)
		}
		c.Set("algorithm", alg)
		if keep("ecdsaEllipticCurveKey") {
			return nil
		}
		k, err := jwt.GenerateEC(alg, realmName)
		if err != nil {
			return err
		}
		return storeAsymmetric(c, k)
	case KeyRSAImported:
		if keep() && c.Get("privateKey") != "" {
			return nil
		}
		priv, err := jwt.ParsePrivateKey(c.Get("privateKey"))
		if err != nil {
			return validationf("failed to decode private key")
		}
		alg := c.Get("algorithm")
		if alg == "" {
			alg = "RS256"
			c.Set("algorithm", alg)
		}
		if cert := c.Get("certificate"); cert != "" {
			if _, err := jwt.ParseCertificate(cert); err != nil {
				return validationf("failed to decode certificate")
			}
			return nil
		}
		cert, err := jwt.SelfSignedCertificate(priv, realmName)
		if err != nil {
			return err
		}
		c.Set("certificate", jwt.EncodeCertificate(cert))
	case KeyHMACGenerated:
		alg := c.Get("algorithm")
		if alg == "" {
			alg = "HS256"
			c.Set("algorithm", alg)
		}
		if jwt.Family(alg) != "OCT" {
			return validationf("invalid algorithm %s for an HMAC key", alg)
		}
		size := 64
		if v := c.Get("secretSize"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 16 || n > 512 {
				return validationf("'Secret size' should be between 16 and 512")
			}
			size = n
		}
		c.Set("secretSize", strconv.Itoa(size))
		if keep("secretSize") {
			return nil
		}
		k, err := jwt.GenerateHMAC(alg, size)
		if err != nil {
			return err
		}
		c.Set("secret", base64.RawURLEncoding.EncodeToString(k.Secret))
		c.Set("kid", NewID())
	}
	return nil
}

func storeAsymmetric(c *model.Component, k *jwt.Key) error {
	pemStr, err := jwt.EncodePrivateKey(k.Private)
	if err != nil {
		return err
	}
	c.Set("privateKey", pemStr)
	c.Set("certificate", jwt.EncodeCertificate(k.Certificate))
	return nil
}

// CreateDefaultKeys adds the key providers of a new realm: an RS256 key for
// tokens and an HS512 key for refresh tokens and cookies, as in Keycloak.
func (s *Service) CreateDefaultKeys(ctx context.Context, st *store.Store, realm *model.Realm) error {
	for _, def := range []struct{ name, provider, alg string }{
		{"rsa-generated", KeyRSAGenerated, "RS256"},
		{"hmac-generated-hs512", KeyHMACGenerated, "HS512"},
	} {
		c := &model.Component{ID: NewID(), RealmID: realm.ID, Name: def.name, ProviderID: def.provider, ParentID: realm.ID,
			Config: map[string][]string{"priority": {"100"}, "algorithm": {def.alg}}}
		if err := PrepareKeyComponent(c, realm.Name, nil); err != nil {
			return err
		}
		if err := st.CreateComponent(ctx, c); err != nil {
			return err
		}
	}
	s.InvalidateKeys(realm.ID)
	return nil
}

// InvalidateKeys drops the cached keys of a realm.
func (s *Service) InvalidateKeys(realmID string) {
	s.mu.Lock()
	delete(s.keys, realmID)
	s.mu.Unlock()
}

func (s *Service) loadKeys(ctx context.Context, realmID string) (*keySet, error) {
	s.mu.RLock()
	ks := s.keys[realmID]
	s.mu.RUnlock()
	if ks != nil {
		return ks, nil
	}
	comps, err := s.Store.ListComponents(ctx, realmID, KeyProviderType)
	if err != nil {
		return nil, err
	}
	ks = &keySet{}
	for _, c := range comps {
		k, err := keyFromComponent(c)
		if err != nil {
			s.logger().Warn("ignoring broken key provider", "realm", realmID, "component", c.Name, "err", err)
			continue
		}
		ks.keys = append(ks.keys, k)
	}
	sort.SliceStable(ks.keys, func(i, j int) bool { return ks.keys[i].Priority > ks.keys[j].Priority })
	s.mu.Lock()
	s.keys[realmID] = ks
	s.mu.Unlock()
	return ks, nil
}

// RealmKeys returns every key of a realm, highest priority first.
func (s *Service) RealmKeys(ctx context.Context, realmID string) ([]*RealmKey, error) {
	ks, err := s.loadKeys(ctx, realmID)
	if err != nil {
		return nil, err
	}
	return ks.keys, nil
}

// SigningKey returns the active key with the highest priority for alg. When
// the realm has none, a "fallback-<alg>" generated key provider is created,
// as Keycloak does.
func (s *Service) SigningKey(ctx context.Context, realm *model.Realm, alg string) (*jwt.Key, error) {
	if alg == "" {
		alg = realm.Settings.DefaultSignatureAlgorithm
		if alg == "" {
			alg = "RS256"
		}
	}
	ks, err := s.loadKeys(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	for _, k := range ks.keys {
		if k.Enabled && k.Active && k.Alg == alg {
			return k.Key, nil
		}
	}
	provider := map[string]string{"RSA": KeyRSAGenerated, "EC": KeyECDSAGenerated, "OCT": KeyHMACGenerated}[jwt.Family(alg)]
	if provider == "" {
		return nil, fmt.Errorf("unsupported signature algorithm %q", alg)
	}
	c := &model.Component{ID: NewID(), RealmID: realm.ID, Name: "fallback-" + alg, ProviderID: provider, ParentID: realm.ID,
		Config: map[string][]string{"priority": {"-100"}, "algorithm": {alg}}}
	if provider == KeyECDSAGenerated {
		c.Set("ecdsaEllipticCurveKey", jwt.CurveForAlg(alg))
	}
	if err := PrepareKeyComponent(c, realm.Name, nil); err != nil {
		return nil, err
	}
	if err := s.Store.CreateComponent(ctx, c); err != nil && !errors.Is(err, store.ErrConflict) {
		return nil, err
	}
	s.InvalidateKeys(realm.ID)
	s.logger().Info("created fallback key provider", "realm", realm.Name, "algorithm", alg)
	ks, err = s.loadKeys(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	for _, k := range ks.keys {
		if k.Enabled && k.Active && k.Alg == alg {
			return k.Key, nil
		}
	}
	return nil, fmt.Errorf("no active key for algorithm %s", alg)
}

// VerificationKey returns the enabled key with the given kid and algorithm.
func (s *Service) VerificationKey(ctx context.Context, realmID, kid, alg string) *jwt.Key {
	ks, err := s.loadKeys(ctx, realmID)
	if err != nil {
		return nil
	}
	for _, k := range ks.keys {
		if k.Enabled && k.Kid == kid && k.Alg == alg {
			return k.Key
		}
	}
	return nil
}
