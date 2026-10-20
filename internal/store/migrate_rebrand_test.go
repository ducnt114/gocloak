package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ducnt114/gocloak/internal/model"
)

// testStore opens a fresh SQLite database, or a fresh schema of
// GOCLOAK_TEST_POSTGRES_URL when it is set.
func testStore(t *testing.T) *Store {
	cfg := Config{URL: filepath.Join(t.TempDir(), "t.db")}
	if pg := os.Getenv("GOCLOAK_TEST_POSTGRES_URL"); pg != "" {
		schema := fmt.Sprintf("t_store_%d", time.Now().UnixNano())
		db, err := sql.Open("pgx", pg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`CREATE SCHEMA ` + schema); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); db.Close() })
		u, _ := url.Parse(pg)
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		cfg = Config{Driver: Postgres, URL: u.String()}
	}
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRenameUpstreamNames(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	// a realm as databases before version 25 hold it
	settings := model.DefaultRealmSettings()
	settings.LoginTheme, settings.AccountTheme = "keycloak", "keycloak.v2"
	settings.WebAuthnPolicyRpEntityName = "keycloak"
	realm := &model.Realm{ID: "r1", Name: "master", DisplayName: "Keycloak", Enabled: true, AccessTokenLifespan: 60,
		AccessCodeLifespan: 60, SSOSessionIdleTimeout: 60, SSOSessionMaxLifespan: 60, Settings: settings}
	if err := s.CreateRealm(ctx, realm); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateComponent(ctx, &model.Component{ID: "c1", RealmID: "r1", Name: "rsa", ProviderID: "rsa-generated",
		ProviderType: "org.keycloak.keys.KeyProvider", ParentID: "r1", Config: map[string][]string{}}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateIdentityProvider(ctx, &model.IdentityProvider{InternalID: "i1", RealmID: "r1", Alias: "kc",
		ProviderID: "keycloak-oidc", Enabled: true, Config: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTx(ctx, func(tx *Store) error { return renameUpstreamNames(ctx, tx) }); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetRealmByName(ctx, "master")
	if err != nil {
		t.Fatal(err)
	}
	if got.DisplayName != "gocloak" || got.Settings.LoginTheme != "gocloak" || got.Settings.AccountTheme != "gocloak.v2" ||
		got.Settings.WebAuthnPolicyRpEntityName != "gocloak" || got.Settings.OTPPolicyDigits != 6 {
		t.Fatalf("realm: %q %+v", got.DisplayName, got.Settings)
	}
	if comps, _ := s.ListComponents(ctx, "r1", "org.gocloak.keys.KeyProvider"); len(comps) != 1 {
		t.Fatalf("components: %v", comps)
	}
	if idp, err := s.GetIdentityProvider(ctx, "r1", "kc"); err != nil || idp.ProviderID != "gocloak-oidc" {
		t.Fatalf("identity provider: %v %v", idp, err)
	}
}
