// Package store keeps Keystone's data in PostgreSQL: people, groups, passkeys, sessions, applications with their
// roles, settings, sealed secrets and the audit log.
package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

var (
	// ErrNotFound: no such row.
	ErrNotFound = errors.New("not found")
	// ErrConflict: a unique value is taken.
	ErrConflict = errors.New("already exists")
)

type Store struct {
	DB *pgxpool.Pool
}

// Open connects and applies the migrations that have not run yet (under an advisory lock, so replicas starting
// together migrate once).
func Open(ctx context.Context, url string) (*Store, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database: %w", err)
	}
	s := &Store{DB: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() { s.DB.Close() }

func (s *Store) migrate(ctx context.Context) error {
	conn, err := s.DB.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(7331901)`); err != nil {
		return err
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock(7331901)`) //nolint:errcheck
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		var done bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name = $1)`, name).Scan(&done); err != nil {
			return err
		}
		if done {
			continue
		}
		sql, err := migrations.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			tx.Rollback(ctx) //nolint:errcheck
			return fmt.Errorf("migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ($1)`, name); err != nil {
			tx.Rollback(ctx) //nolint:errcheck
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

// mapErr turns driver errors into the store's.
func mapErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return ErrConflict
	}
	return err
}

// ---- settings

// Setting reads a JSON setting into out; ok is false when it is not set.
func (s *Store) Setting(ctx context.Context, key string, out any) (bool, error) {
	var raw []byte
	err := s.DB.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, key).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(raw, out)
}

func (s *Store) PutSetting(ctx context.Context, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = now()`, key, raw)
	return err
}

// ---- audit

type AuditEntry struct {
	ID     int64          `json:"id"`
	At     string         `json:"at"`
	Actor  string         `json:"actor"`
	Action string         `json:"action"`
	Target string         `json:"target"`
	Detail map[string]any `json:"detail"`
	IP     string         `json:"ip"`
}

func (s *Store) Audit(ctx context.Context, actor, action, target, ip string, detail map[string]any) {
	if detail == nil {
		detail = map[string]any{}
	}
	raw, _ := json.Marshal(detail)
	s.DB.Exec(ctx, `INSERT INTO audit (actor, action, target, detail, ip) VALUES ($1, $2, $3, $4, $5)`, //nolint:errcheck
		actor, action, target, raw, ip)
}

// AuditLog lists entries, newest first; q filters by actor, action or target.
func (s *Store) AuditLog(ctx context.Context, q string, before int64, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if before <= 0 {
		before = 1 << 62
	}
	rows, err := s.DB.Query(ctx, `SELECT id, to_char(at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), actor, action, target, detail, ip
		FROM audit WHERE id < $1 AND ($2 = '' OR actor ILIKE '%'||$2||'%' OR action ILIKE '%'||$2||'%' OR target ILIKE '%'||$2||'%')
		ORDER BY id DESC LIMIT $3`, before, strings.TrimSpace(q), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var raw []byte
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.Action, &e.Target, &raw, &e.IP); err != nil {
			return nil, err
		}
		json.Unmarshal(raw, &e.Detail) //nolint:errcheck
		out = append(out, e)
	}
	return out, rows.Err()
}
