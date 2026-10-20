// Package store persists gocloak entities in SQLite or PostgreSQL.
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

var (
	// ErrNotFound is returned when an entity does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict is returned when a uniqueness constraint is violated.
	ErrConflict = errors.New("conflict")
)

// Supported database drivers.
const (
	SQLite   = "sqlite"
	Postgres = "postgres"
)

// Config selects and locates the database.
type Config struct {
	// Driver is SQLite (default) or Postgres.
	Driver string
	// URL is a file path for SQLite, or a postgres:// URL / keyword DSN.
	URL string
}

type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// rebinder rewrites the '?' placeholders used throughout the package into
// '$n' for PostgreSQL. No query in this package has '?' inside a literal.
type rebinder struct {
	q     querier
	pg    bool
	stmts *stmtCache // prepared statements, for SQLite outside transactions
}

func (r rebinder) rebind(query string) string {
	if !r.pg {
		return query
	}
	var b strings.Builder
	n := 0
	for _, c := range query {
		if c == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

func (r rebinder) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if st := r.stmts.get(ctx, query); st != nil {
		return st.ExecContext(ctx, args...)
	}
	return r.q.ExecContext(ctx, r.rebind(query), args...)
}

func (r rebinder) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if st := r.stmts.get(ctx, query); st != nil {
		return st.QueryContext(ctx, args...)
	}
	return r.q.QueryContext(ctx, r.rebind(query), args...)
}

func (r rebinder) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	if st := r.stmts.get(ctx, query); st != nil {
		return st.QueryRowContext(ctx, args...)
	}
	return r.q.QueryRowContext(ctx, r.rebind(query), args...)
}

// stmtCache keeps prepared statements of the most used queries. The SQLite
// driver parses every query it is given again, which costs more than running
// most of them; pgx keeps its own cache per connection.
type stmtCache struct {
	db *sql.DB
	mu sync.RWMutex
	m  map[string]*sql.Stmt
}

// maxCachedStmts bounds the cache: queries built with a variable number of
// placeholders are many, and once it is full they are just not cached.
const maxCachedStmts = 1000

func (c *stmtCache) get(ctx context.Context, query string) *sql.Stmt {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	st, ok := c.m[query]
	c.mu.RUnlock()
	if ok {
		return st
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if st, ok := c.m[query]; ok {
		return st
	}
	if len(c.m) >= maxCachedStmts {
		return nil
	}
	st, err := c.db.PrepareContext(ctx, query)
	if err != nil {
		return nil // the query runs unprepared and reports its error
	}
	c.m[query] = st
	return st
}

// Store gives access to all persisted entities. A Store returned by WithTx
// runs every call inside the same transaction.
type Store struct {
	db     *sql.DB
	q      querier
	driver string
	inTx   bool
	cache  *queryCache

	// OnListenError reports a lost invalidation connection (see Listen).
	OnListenError func(error)
}

// Open opens the database and applies pending migrations.
func Open(cfg Config) (*Store, error) {
	if cfg.Driver == "" {
		cfg.Driver = SQLite
	}
	var db *sql.DB
	var err error
	switch cfg.Driver {
	case SQLite:
		dsn := "file:" + cfg.URL + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_txlock=immediate"
		if db, err = sql.Open("sqlite", dsn); err != nil {
			return nil, err
		}
		// WAL lets readers run concurrently with the single writer;
		// transactions take the write lock up front (_txlock=immediate) and
		// other writers wait on busy_timeout instead of failing.
		db.SetMaxOpenConns(8)
		db.SetMaxIdleConns(8)
	case Postgres:
		if db, err = sql.Open("pgx", cfg.URL); err != nil {
			return nil, err
		}
		db.SetMaxOpenConns(32)
		// keep connections open under load instead of the default two
		db.SetMaxIdleConns(32)
		db.SetConnMaxIdleTime(5 * time.Minute)
	default:
		return nil, fmt.Errorf("unsupported database driver %q", cfg.Driver)
	}
	s := &Store{db: db, driver: cfg.Driver, cache: newQueryCache()}
	s.q = cachingQuerier{q: rebinder{q: db, pg: cfg.Driver == Postgres}, cache: s.cache, written: s.configChanged}
	if err := s.migrate(context.Background()); err != nil {
		s.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if cfg.Driver == SQLite {
		s.q = cachingQuerier{q: rebinder{q: db, stmts: &stmtCache{db: db, m: map[string]*sql.Stmt{}}}, cache: s.cache, written: s.configChanged}
	}
	return s, nil
}

// Driver returns SQLite or Postgres.
func (s *Store) Driver() string { return s.driver }

// Close closes the underlying database.
func (s *Store) Close() error {
	s.cache.replay.Close()
	return s.db.Close()
}

// configChanged empties the configuration cache after a committed write, on
// this node and the others.
func (s *Store) configChanged() {
	s.cache.invalidate()
	_ = s.Notify(context.Background(), TopicConfig, "")
}

// InvalidateConfigCache empties the configuration cache of this node (on a
// notification from another one).
func (s *Store) InvalidateConfigCache() { s.cache.invalidate() }

// Ping checks database connectivity.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// WithTx runs fn inside a transaction. Nested calls reuse the outer one.
func (s *Store) WithTx(ctx context.Context, fn func(tx *Store) error) error {
	if s.inTx {
		return fn(s)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	dirty := false
	txs := &Store{db: s.db, driver: s.driver, inTx: true, cache: s.cache}
	txs.q = cachingQuerier{q: rebinder{q: tx, pg: s.driver == Postgres}, written: func() { dirty = true }}
	if err := fn(txs); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if dirty {
		s.configChanged()
	}
	return nil
}

// ---------------------------------------------------------------- migrations

type migration struct {
	version int
	name    string
	sql     string
	fn      func(ctx context.Context, tx *Store) error // data migration written in Go
}

// goMigrations are data migrations that need Go code; they share the
// version sequence with the SQL files.
var goMigrations = []migration{
	{version: 4, name: "0004_backfill_user_attributes", fn: backfillUserAttributes},
	{version: 7, name: "0007_realm_settings_defaults", fn: migrateRealmSettingsDefaults},
	{version: 8, name: "0008_key_components", fn: migrateRealmKeys},
	{version: 10, name: "0010_realm_settings_defaults_m3", fn: migrateRealmSettingsDefaults},
	{version: 16, name: "0016_saml_role_list_scope", fn: addSAMLRoleListScope},
	{version: 17, name: "0017_lightweight_access_tokens", fn: enableLightweightTokens},
	{version: 19, name: "0019_realm_attribute_defaults", fn: addRealmAttributeDefaults},
	{version: 22, name: "0022_client_registration_policies", fn: addRegistrationPolicies},
	{version: 25, name: "0025_rename_upstream_names", fn: renameUpstreamNames},
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		name := e.Name()
		i := strings.IndexByte(name, '_')
		if i < 0 || !strings.HasSuffix(name, ".sql") {
			return nil, fmt.Errorf("bad migration file name %q", name)
		}
		v, err := strconv.Atoi(name[:i])
		if err != nil {
			return nil, fmt.Errorf("bad migration file name %q", name)
		}
		b, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: name, sql: string(b)})
	}
	out = append(out, goMigrations...)
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i := 1; i < len(out); i++ {
		if out[i].version == out[i-1].version {
			return nil, fmt.Errorf("duplicate migration version %d", out[i].version)
		}
	}
	return out, nil
}

// migrate applies every migration not yet recorded in schema_migrations,
// each in its own transaction. On PostgreSQL an advisory lock serialises
// nodes starting at the same time.
func (s *Store) migrate(ctx context.Context) error {
	migs, err := loadMigrations()
	if err != nil {
		return err
	}
	// nodes starting together on a new database take turns
	err = s.WithTx(ctx, func(tx *Store) error {
		if err := tx.TxLock(ctx, "migrate"); err != nil {
			return err
		}
		_, err := tx.q.(cachingQuerier).q.(rebinder).q.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version BIGINT PRIMARY KEY, name TEXT NOT NULL, applied_at BIGINT NOT NULL)`)
		return err
	})
	if err != nil {
		return err
	}
	for _, m := range migs {
		err := s.WithTx(ctx, func(tx *Store) error {
			if err := tx.TxLock(ctx, "migrate"); err != nil {
				return err
			}
			var n int
			if err := tx.q.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version=?`, m.version).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return nil
			}
			if m.fn != nil {
				if err := m.fn(ctx, tx); err != nil {
					return fmt.Errorf("%s: %w", m.name, err)
				}
			} else {
				// the file as is: no placeholders to rebind
				cq := tx.q.(cachingQuerier)
				cq.written()
				if _, err := cq.q.(rebinder).q.ExecContext(ctx, m.sql); err != nil {
					return fmt.Errorf("%s: %w", m.name, err)
				}
			}
			return tx.exec(ctx, `INSERT INTO schema_migrations (version, name, applied_at) VALUES (?,?,?)`, m.version, m.name, time.Now().Unix())
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// SchemaVersion returns the highest applied migration.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v sql.NullInt64
	err := s.q.QueryRowContext(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&v)
	return int(v.Int64), err
}

// ---------------------------------------------------------------- helpers

func (s *Store) exec(ctx context.Context, query string, args ...any) error {
	_, err := s.q.ExecContext(ctx, query, args...)
	return mapErr(err)
}

// execOne executes a statement that must affect exactly one row.
func (s *Store) execOne(ctx context.Context, query string, args ...any) error {
	res, err := s.q.ExecContext(ctx, query, args...)
	if err != nil {
		return mapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return fmt.Errorf("%w: %v", ErrConflict, err)
	}
	if strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(err.Error(), "PRIMARY KEY constraint failed") {
		return fmt.Errorf("%w: %v", ErrConflict, err)
	}
	return err
}

// scanner abstracts *sql.Row and *sql.Rows.
type scanner interface{ Scan(dest ...any) error }

// queryList runs a query and maps every row with scan.
func queryList[T any](ctx context.Context, s *Store, scan func(scanner) (T, error), query string, args ...any) ([]T, error) {
	rows, err := s.q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func queryStrings(ctx context.Context, s *Store, query string, args ...any) ([]string, error) {
	return queryList(ctx, s, func(sc scanner) (string, error) {
		var v string
		err := sc.Scan(&v)
		return v, err
	}, query, args...)
}

func toJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// jsonCol is a sql.Scanner that decodes a JSON text column into Dst.
type jsonCol struct{ Dst any }

func (j jsonCol) Scan(src any) error {
	var b []byte
	switch v := src.(type) {
	case string:
		b = []byte(v)
	case []byte:
		b = v
	case nil:
		return nil
	default:
		return fmt.Errorf("unexpected json column type %T", src)
	}
	if len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, j.Dst)
}

func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

func lower(s string) string { return strings.ToLower(s) }

// limit converts a "max results" parameter into a LIMIT value; zero or
// negative means unlimited (both dialects accept a very large LIMIT).
func limit(max int) int64 {
	if max <= 0 {
		return 1 << 53
	}
	return int64(max)
}
