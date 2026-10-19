package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestMigrateFreshAndV0Database(t *testing.T) {
	migs, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	latest := migs[len(migs)-1].version
	ctx := context.Background()

	fresh, err := Open(Config{URL: filepath.Join(t.TempDir(), "fresh.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if v, err := fresh.SchemaVersion(ctx); err != nil || v != latest {
		t.Fatalf("fresh schema version = %d, %v; want %d", v, err, latest)
	}

	// A v0 database was created from the initial schema without
	// schema_migrations; opening it must apply the later migrations.
	path := filepath.Join(t.TempDir(), "v0.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(migs[0].sql); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO realms (id, name, access_token_lifespan, access_code_lifespan,
		sso_session_idle_timeout, sso_session_max_lifespan, created_at) VALUES ('r1', 'old', 300, 60, 1800, 36000, 0)`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	st, err := Open(Config{URL: path})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if v, _ := st.SchemaVersion(ctx); v != latest {
		t.Fatalf("upgraded schema version = %d, want %d", v, latest)
	}
	r, err := st.GetRealmByName(ctx, "old")
	if err != nil {
		t.Fatal(err)
	}
	r.Settings.ResetPasswordAllowed = true
	if err := st.UpdateRealm(ctx, r); err != nil {
		t.Fatal(err)
	}
	if r, _ = st.GetRealmByName(ctx, "old"); !r.Settings.ResetPasswordAllowed {
		t.Fatal("settings not persisted")
	}
}

func TestRebind(t *testing.T) {
	r := rebinder{pg: true}
	if got := r.rebind(`SELECT a FROM t WHERE x=? AND y IN (?,?)`); got != `SELECT a FROM t WHERE x=$1 AND y IN ($2,$3)` {
		t.Fatal(got)
	}
}
