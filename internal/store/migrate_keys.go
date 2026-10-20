package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
)

// migrateRealmSettingsDefaults fills settings added in M2 (brute force,
// offline sessions, events...) with Keycloak's defaults in existing realms.
func migrateRealmSettingsDefaults(ctx context.Context, tx *Store) error {
	type row struct{ id, settings string }
	rows, err := queryList(ctx, tx, func(sc scanner) (row, error) {
		var r row
		err := sc.Scan(&r.id, &r.settings)
		return r, err
	}, `SELECT id, settings FROM realms`)
	if err != nil {
		return err
	}
	for _, r := range rows {
		merged := model.DefaultRealmSettings()
		if err := json.Unmarshal([]byte(r.settings), &merged); err != nil {
			return err
		}
		if err := tx.exec(ctx, `UPDATE realms SET settings=? WHERE id=?`, toJSON(merged), r.id); err != nil {
			return err
		}
	}
	return nil
}

// migrateRealmKeys turns the RSA keys of the realm_keys table into
// rsa-generated key provider components (with a certificate) and adds the
// HS512 key Keycloak uses for refresh tokens.
func migrateRealmKeys(ctx context.Context, tx *Store) error {
	type key struct {
		id, realmID, pem string
		active           bool
		priority         int
	}
	keys, err := queryList(ctx, tx, func(sc scanner) (key, error) {
		var k key
		err := sc.Scan(&k.id, &k.realmID, &k.pem, &k.active, &k.priority)
		return k, err
	}, `SELECT id, realm_id, private_pem, active, priority FROM realm_keys ORDER BY created_at`)
	if err != nil {
		return err
	}
	realmNames := map[string]string{}
	realms, err := queryList(ctx, tx, func(sc scanner) ([2]string, error) {
		var r [2]string
		err := sc.Scan(&r[0], &r[1])
		return r, err
	}, `SELECT id, name FROM realms`)
	if err != nil {
		return err
	}
	for _, r := range realms {
		realmNames[r[0]] = r[1]
	}
	for i, k := range keys {
		priv, err := jwt.ParsePrivateKey(k.pem)
		if err != nil {
			return err
		}
		cert, err := jwt.SelfSignedCertificate(priv, realmNames[k.realmID])
		if err != nil {
			return err
		}
		active := "false"
		if k.active {
			active = "true"
		}
		c := &model.Component{ID: uuid.NewString(), RealmID: k.realmID, Name: "rsa-generated", ProviderID: "rsa-generated",
			ProviderType: "org.gocloak.keys.KeyProvider", ParentID: k.realmID, Config: map[string][]string{
				// later keys win, as they did before
				"priority": {itoa(100 + i)}, "algorithm": {"RS256"}, "keySize": {"2048"},
				"active": {active}, "enabled": {"true"}, "privateKey": {k.pem}, "certificate": {jwt.EncodeCertificate(cert)},
			}}
		if err := tx.CreateComponent(ctx, c); err != nil {
			return err
		}
	}
	for id := range realmNames {
		secret := make([]byte, 64)
		if _, err := rand.Read(secret); err != nil {
			return err
		}
		c := &model.Component{ID: uuid.NewString(), RealmID: id, Name: "hmac-generated-hs512", ProviderID: "hmac-generated",
			ProviderType: "org.gocloak.keys.KeyProvider", ParentID: id, Config: map[string][]string{
				"priority": {"100"}, "algorithm": {"HS512"}, "secretSize": {"64"}, "active": {"true"}, "enabled": {"true"},
				"secret": {base64.RawURLEncoding.EncodeToString(secret)}, "kid": {uuid.NewString()},
			}}
		if err := tx.CreateComponent(ctx, c); err != nil {
			return err
		}
	}
	return nil
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
