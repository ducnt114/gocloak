package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The configuration cache keeps the results of queries that read only
// realm configuration (realms, clients, scopes, mappers, roles, groups,
// flows, components): the requests on the token and login paths read them
// many times and they rarely change. Users and sessions are not cached.
//
// Results are kept as the rows the driver returned and replayed through
// database/sql, so callers scan fresh values exactly as from the database
// and never share an object. A write to a configuration table empties the
// cache once it is committed, on this node and, through Notify, on the
// others; entries also expire after cacheTTL so that writes from outside
// gocloak show up.

// configTables are the tables whose rows the cache may hold.
var configTables = map[string]bool{
	"realms": true, "clients": true, "client_scopes": true, "client_scope_links": true, "realm_default_scopes": true,
	"protocol_mappers": true, "roles": true, "composite_roles": true, "scope_mappings": true, "realm_groups": true,
	"group_roles": true, "realm_default_groups": true, "identity_providers": true, "idp_mappers": true,
	"auth_flows": true, "auth_executions": true, "authenticator_configs": true, "required_actions": true,
	"components": true,
}

// TopicConfig is the Notify topic of configuration changes.
const TopicConfig = "config"

const (
	cacheTTL        = time.Minute
	maxCacheEntries = 20000
)

type queryCache struct {
	mu      sync.Mutex
	gen     uint64
	entries map[string]*cachedRows
	replay  *sql.DB
}

type cachedRows struct {
	cols    []string
	rows    [][]driver.Value
	expires time.Time
}

func newQueryCache() *queryCache {
	replay := sql.OpenDB(replayConnector{})
	replay.SetMaxIdleConns(64)
	return &queryCache{entries: map[string]*cachedRows{}, replay: replay}
}

// invalidate empties the cache.
func (c *queryCache) invalidate() {
	c.mu.Lock()
	c.gen++
	clear(c.entries)
	c.mu.Unlock()
}

func (c *queryCache) lookup(key string) (*cachedRows, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[key]
	if e != nil && time.Now().After(e.expires) {
		delete(c.entries, key)
		e = nil
	}
	return e, c.gen
}

// store keeps rows read since generation gen, unless the cache was
// invalidated meanwhile (they might predate the write).
func (c *queryCache) store(key string, e *cachedRows, gen uint64) {
	if len(e.rows) == 0 {
		return // what is missing may be created by a node whose notice was missed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen != gen {
		return
	}
	if len(c.entries) >= maxCacheEntries {
		c.gen++
		clear(c.entries)
		return
	}
	e.expires = time.Now().Add(cacheTTL)
	c.entries[key] = e
}

// query returns the rows of a cacheable query, from the cache or from the
// database through q.
func (c *queryCache) query(ctx context.Context, q querier, key, query string, args []any) (*sql.Rows, error) {
	e, gen := c.lookup(key)
	if e == nil {
		rows, err := q.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		if e, err = readRows(rows); err != nil {
			return nil, err
		}
		c.store(key, e, gen)
	}
	return c.replay.QueryContext(context.WithValue(ctx, replayKey{}, e), "replay")
}

func readRows(rows *sql.Rows) (*cachedRows, error) {
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	e := &cachedRows{cols: cols}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make([]driver.Value, len(cols))
		for i, v := range vals {
			row[i] = v
		}
		e.rows = append(e.rows, row)
	}
	return e, rows.Err()
}

// cacheKey returns the key of a query that reads only configuration tables
// ("" if it reads anything else).
func cacheKey(query string, args []any) string {
	if !readsOnlyConfig(query) {
		return ""
	}
	var b strings.Builder
	b.WriteString(query)
	for _, a := range args {
		switch a.(type) {
		case string, int, int64, bool, nil:
			fmt.Fprintf(&b, "\x00%T:%v", a, a)
		default: // times and others: not worth caching
			return ""
		}
	}
	return b.String()
}

var sqlToken = regexp.MustCompile(`[a-z_][a-z0-9_]*|\S`)

var (
	readOnlyCache sync.Map // query -> bool
	readOnlyCount atomic.Int64
)

// readsOnlyConfig tells whether every table a SELECT reads (after FROM or
// JOIN, subqueries included) is a configuration table.
func readsOnlyConfig(query string) bool {
	if v, ok := readOnlyCache.Load(query); ok {
		return v.(bool)
	}
	ok := parseReadsOnlyConfig(query)
	if readOnlyCount.Add(1) <= maxCacheEntries {
		readOnlyCache.Store(query, ok)
	}
	return ok
}

func parseReadsOnlyConfig(query string) bool {
	toks := sqlToken.FindAllString(strings.ToLower(query), -1)
	if len(toks) == 0 || toks[0] != "select" {
		return false
	}
	seen := false
	for i := 0; i < len(toks); i++ {
		switch toks[i] {
		case "for": // FOR UPDATE / FOR SHARE: a locking read
			return false
		case "from", "join":
			if i+1 >= len(toks) || !configTables[toks[i+1]] {
				return false
			}
			seen = true
			// FROM a x, b: a table listed after a comma
			j := i + 2
			if j < len(toks) && toks[j] != "," && sqlToken.MatchString(toks[j]) && toks[j] != "where" && toks[j] != "join" {
				j++
			}
			if j < len(toks) && toks[j] == "," {
				return false
			}
		}
	}
	return seen
}

var writeStmt = regexp.MustCompile(`^\s*(?i:insert\s+(?:or\s+\w+\s+)?into|update|delete\s+from|replace\s+into)\s+(\w+)`)

// writesConfig tells whether a statement may change configuration tables:
// a write to one of them, or anything that is not a plain write (DDL).
func writesConfig(query string) bool {
	m := writeStmt.FindStringSubmatch(query)
	return m == nil || configTables[strings.ToLower(m[1])]
}

// ---------------------------------------------------------------- replay driver

type replayKey struct{}

type replayConnector struct{}

func (replayConnector) Connect(context.Context) (driver.Conn, error) { return replayConn{}, nil }
func (replayConnector) Driver() driver.Driver                        { return replayDriver{} }

type replayDriver struct{}

func (replayDriver) Open(string) (driver.Conn, error) { return replayConn{}, nil }

type replayConn struct{}

var errReplay = errors.New("replay connection only serves cached rows")

func (replayConn) Prepare(string) (driver.Stmt, error) { return nil, errReplay }
func (replayConn) Close() error                        { return nil }
func (replayConn) Begin() (driver.Tx, error)           { return nil, errReplay }

func (replayConn) QueryContext(ctx context.Context, _ string, _ []driver.NamedValue) (driver.Rows, error) {
	e, ok := ctx.Value(replayKey{}).(*cachedRows)
	if !ok {
		return nil, errReplay
	}
	return &replayRows{e: e}, nil
}

type replayRows struct {
	e *cachedRows
	i int
}

func (r *replayRows) Columns() []string { return r.e.cols }
func (r *replayRows) Close() error      { return nil }

func (r *replayRows) Next(dest []driver.Value) error {
	if r.i >= len(r.e.rows) {
		return io.EOF
	}
	for i, v := range r.e.rows[r.i] {
		if b, ok := v.([]byte); ok {
			v = append([]byte(nil), b...)
		}
		dest[i] = v
	}
	r.i++
	return nil
}

// row is query for QueryRowContext.
func (c *queryCache) row(ctx context.Context, q querier, key, query string, args []any) *sql.Row {
	e, gen := c.lookup(key)
	if e == nil {
		rows, err := q.QueryContext(ctx, query, args...)
		if err == nil {
			e, err = readRows(rows)
		}
		if err != nil {
			return q.QueryRowContext(ctx, query, args...) // reports the error
		}
		c.store(key, e, gen)
	}
	return c.replay.QueryRowContext(context.WithValue(ctx, replayKey{}, e), "replay")
}

// cachingQuerier serves the configuration reads from the cache and reports
// configuration writes.
type cachingQuerier struct {
	q       querier
	cache   *queryCache // nil in transactions, which read their own writes
	written func()      // after a statement that may change configuration
}

func (c cachingQuerier) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	res, err := c.q.ExecContext(ctx, query, args...)
	if writesConfig(query) {
		c.written()
	}
	return res, err
}

func (c cachingQuerier) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if c.cache != nil {
		if key := cacheKey(query, args); key != "" {
			return c.cache.query(ctx, c.q, key, query, args)
		}
	}
	if writeStmt.MatchString(query) && writesConfig(query) { // INSERT ... RETURNING
		c.written()
	}
	return c.q.QueryContext(ctx, query, args...)
}

func (c cachingQuerier) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	if c.cache != nil {
		if key := cacheKey(query, args); key != "" {
			return c.cache.row(ctx, c.q, key, query, args)
		}
	}
	if writeStmt.MatchString(query) && writesConfig(query) {
		c.written()
	}
	return c.q.QueryRowContext(ctx, query, args...)
}
