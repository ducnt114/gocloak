package server

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ducnt114/gocloak/internal/store"
)

// testDB returns the database for a test: a fresh SQLite file by default, or,
// when GOCLOAK_TEST_POSTGRES_URL is set, a fresh schema in that PostgreSQL
// database (dropped after the test).
func testDB(t *testing.T) store.Config {
	t.Helper()
	pgURL := os.Getenv("GOCLOAK_TEST_POSTGRES_URL")
	if pgURL == "" {
		return store.Config{Driver: store.SQLite, URL: filepath.Join(t.TempDir(), "test.db")}
	}
	schema := fmt.Sprintf("t_%s_%d", strings.ToLower(strings.NewReplacer("/", "_", "-", "_").Replace(t.Name())), time.Now().UnixNano())
	db, err := sql.Open("pgx", pgURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		db.Close()
	})
	u, err := url.Parse(pgURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return store.Config{Driver: store.Postgres, URL: u.String()}
}
