package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestCacheClassification(t *testing.T) {
	for q, want := range map[string]bool{
		`SELECT id, name FROM realms WHERE name=?`:                                               true,
		`SELECT r.id FROM roles r JOIN composite_roles c ON c.child_id=r.id WHERE c.parent_id=?`: true,
		`SELECT id FROM roles WHERE id IN (SELECT role_id FROM group_roles WHERE group_id=?)`:    true,
		`SELECT g.id FROM realm_groups g JOIN user_groups ug ON ug.group_id=g.id`:                false,
		`SELECT id FROM roles WHERE id IN (SELECT role_id FROM user_roles WHERE user_id=?)`:      false,
		`SELECT count(*) FROM revoked_tokens WHERE jti=?`:                                        false,
		`SELECT r.id FROM roles r, users u WHERE u.id=?`:                                         false,
		`SELECT id FROM clients WHERE id=? FOR UPDATE`:                                           false,
		`select id from clients`:               true,
		`UPDATE clients SET name=? WHERE id=?`: false,
	} {
		if got := readsOnlyConfig(q); got != want {
			t.Errorf("readsOnlyConfig(%q) = %v", q, got)
		}
	}
	for q, want := range map[string]bool{
		`UPDATE clients SET name=?`:                       true,
		`INSERT INTO protocol_mappers (id) VALUES (?)`:    true,
		`INSERT OR IGNORE INTO roles (id) VALUES (?)`:     true,
		`DELETE FROM user_sessions WHERE id=?`:            false,
		`  insert into events (id) values (?)`:            false,
		`ALTER TABLE clients ADD COLUMN x TEXT`:           true,
		`CREATE TABLE t (id TEXT)`:                        true,
		`UPDATE user_sessions SET last_refresh=? WHERE 1`: false,
	} {
		if got := writesConfig(q); got != want {
			t.Errorf("writesConfig(%q) = %v", q, got)
		}
	}
}

func TestCacheInvalidation(t *testing.T) {
	ctx := context.Background()
	s, err := Open(Config{URL: filepath.Join(t.TempDir(), "c.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	name := func() string {
		var v string
		if err := s.q.QueryRowContext(ctx, `SELECT display_name FROM realms WHERE name=?`, "r").Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if _, err := s.db.Exec(`INSERT INTO realms (id, name, display_name, access_token_lifespan, access_code_lifespan, sso_session_idle_timeout, sso_session_max_lifespan, created_at) VALUES ('1', 'r', 'one', 1, 1, 1, 1, 1)`); err != nil {
		t.Fatal(err)
	}
	if name() != "one" {
		t.Fatal("first read")
	}
	// a write behind the store's back is not seen until the entry expires
	s.db.Exec(`UPDATE realms SET display_name='two'`)
	if name() != "one" {
		t.Fatal("not served from the cache")
	}
	// writes through the store invalidate, transactions on commit only
	if err := s.exec(ctx, `UPDATE realms SET display_name=?`, "three"); err != nil {
		t.Fatal(err)
	}
	if name() != "three" {
		t.Fatal("write not seen")
	}
	err = s.WithTx(ctx, func(tx *Store) error {
		if err := tx.exec(ctx, `UPDATE realms SET display_name=?`, "four"); err != nil {
			return err
		}
		var v string
		tx.q.QueryRowContext(ctx, `SELECT display_name FROM realms WHERE name=?`, "r").Scan(&v)
		if v != "four" {
			t.Errorf("transaction does not read its own write: %q", v)
		}
		return nil
	})
	if err != nil || name() != "four" {
		t.Fatalf("commit not seen: %v", err)
	}
	// an unrelated write keeps the cache
	gen := s.cache.gen
	s.exec(ctx, `DELETE FROM user_sessions WHERE id=?`, "x")
	if s.cache.gen != gen {
		t.Fatal("cache emptied by a session write")
	}
	// rows scanned from the cache are not shared
	if a, b := name(), name(); a != b {
		t.Fatal("unstable")
	}
}
