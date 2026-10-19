package store

import (
	"context"
	"database/sql/driver"
	"errors"
	"hash/fnv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
)

// Cluster support: nodes sharing a PostgreSQL database tell each other
// about changes to what they cache (LISTEN/NOTIFY), and take advisory locks
// so that periodic jobs run on one node at a time. With SQLite there is a
// single node and these are no-ops.

const invalidationChannel = "gocloak_invalidate"

// Notify tells the other nodes that a cached value changed: topic names the
// cache, key the entry.
func (s *Store) Notify(ctx context.Context, topic, key string) error {
	if s.driver != Postgres {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `SELECT pg_notify($1, $2)`, invalidationChannel, topic+":"+key)
	return err
}

// Listen calls fn for the invalidations other nodes send (and the ones this
// node sends), until ctx ends; the connection is reopened after failures.
// onReconnect runs after a lost connection, as notifications may have been
// missed (callers drop their whole cache).
func (s *Store) Listen(ctx context.Context, fn func(topic, key string), onReconnect func()) {
	if s.driver != Postgres {
		return
	}
	for first := true; ctx.Err() == nil; first = false {
		if !first {
			onReconnect()
		}
		if err := s.listenOnce(ctx, fn); ctx.Err() == nil && err != nil && s.OnListenError != nil {
			s.OnListenError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (s *Store) listenOnce(ctx context.Context, fn func(topic, key string)) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() {
		// the connection held LISTEN: do not return it to the pool
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		conn.Close()
	}()
	return conn.Raw(func(dc any) error {
		pc, ok := dc.(*stdlib.Conn)
		if !ok {
			return errors.New("not a pgx connection")
		}
		c := pc.Conn()
		if _, err := c.Exec(ctx, "LISTEN "+invalidationChannel); err != nil {
			return err
		}
		for {
			n, err := c.WaitForNotification(ctx)
			if err != nil {
				return err
			}
			topic, key, _ := strings.Cut(n.Payload, ":")
			fn(topic, key)
		}
	})
}

// TryLock takes a cluster-wide lock for a job if no other node holds it; the
// returned function releases it. On SQLite it always succeeds.
func (s *Store) TryLock(ctx context.Context, name string) (func(), bool, error) {
	if s.driver != Postgres {
		return func() {}, true, nil
	}
	h := fnv.New64a()
	h.Write([]byte(name))
	id := int64(h.Sum64() >> 1)
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, false, err
	}
	var ok bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, id).Scan(&ok); err != nil {
		conn.Close()
		return nil, false, err
	}
	if !ok {
		conn.Close()
		return nil, false, nil
	}
	return func() {
		_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, id)
		conn.Close()
	}, true, nil
}
