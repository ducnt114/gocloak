// Package store persists gocloak entities in SQLite.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

var (
	// ErrNotFound is returned when an entity does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict is returned when a uniqueness constraint is violated.
	ErrConflict = errors.New("conflict")
)

type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Store gives access to all persisted entities. A Store returned by WithTx
// runs every call inside the same transaction.
type Store struct {
	db *sql.DB
	q  querier
}

// Open opens (and migrates) the SQLite database at path.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// WAL lets readers run concurrently with the single writer; transactions
	// take the write lock up front (_txlock=immediate) and other writers wait
	// on busy_timeout instead of failing with SQLITE_BUSY.
	db.SetMaxOpenConns(8)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db, q: db}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// Ping checks database connectivity.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// WithTx runs fn inside a transaction. Nested calls reuse the outer one.
func (s *Store) WithTx(ctx context.Context, fn func(tx *Store) error) error {
	if _, ok := s.q.(*sql.Tx); ok {
		return fn(s)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(&Store{db: s.db, q: tx}); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

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
	if strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(err.Error(), "PRIMARY KEY constraint failed") {
		return fmt.Errorf("%w: %v", ErrConflict, err)
	}
	return err
}

// scanner abstracts *sql.Row and *sql.Rows.
type scanner interface{ Scan(dest ...any) error }

// queryList runs a query and maps every row with scan, closing rows before
// returning so that the single connection is freed.
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

// placeholders returns "?,?,?" for n values.
func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
