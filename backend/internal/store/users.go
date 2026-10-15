package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/jackc/pgx/v5"
)

// NewID returns prefix_ + 16 random hex characters.
func NewID(prefix string) string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return prefix + "_" + hex.EncodeToString(b)
}

// User is a person of SPA.
type User struct {
	ID                string     `json:"id"`
	Username          string     `json:"username"`
	Email             string     `json:"email"`
	Name              string     `json:"name"`
	Source            string     `json:"source"`
	ExternalID        string     `json:"-"`
	PasswordHash      string     `json:"-"`
	PasswordChangedAt *time.Time `json:"password_changed_at,omitempty"`
	MustChange        bool       `json:"must_change"`
	Disabled          bool       `json:"disabled"`
	SPARole           string     `json:"spa_role"`
	FailedAttempts    int        `json:"-"`
	LockedUntil       *time.Time `json:"locked_until,omitempty"`
	LastSignInAt      *time.Time `json:"last_sign_in_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

const userCols = `id, username, email, name, source, coalesce(external_id, ''), password_hash, password_changed_at, must_change,
	disabled, spa_role, failed_attempts, locked_until, last_sign_in_at, created_at, updated_at`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.Name, &u.Source, &u.ExternalID, &u.PasswordHash, &u.PasswordChangedAt,
		&u.MustChange, &u.Disabled, &u.SPARole, &u.FailedAttempts, &u.LockedUntil, &u.LastSignInAt, &u.CreatedAt, &u.UpdatedAt)
	return u, mapErr(err)
}

func (s *Store) UserByID(ctx context.Context, id string) (User, error) {
	return scanUser(s.DB.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id = $1`, id))
}

func (s *Store) UserByUsername(ctx context.Context, username string) (User, error) {
	return scanUser(s.DB.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE lower(username) = lower($1)`, username))
}

func (s *Store) UserByExternal(ctx context.Context, source, externalID string) (User, error) {
	return scanUser(s.DB.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE source = $1 AND external_id = $2`, source, externalID))
}

// UsersByEmail lists people with this e-mail (normally one).
func (s *Store) UsersByEmail(ctx context.Context, email string) ([]User, error) {
	return s.queryUsers(ctx, `SELECT `+userCols+` FROM users WHERE email <> '' AND lower(email) = lower($1)`, email)
}

func (s *Store) queryUsers(ctx context.Context, sql string, args ...any) ([]User, error) {
	rows, err := s.DB.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) Users(ctx context.Context) ([]User, error) {
	return s.queryUsers(ctx, `SELECT `+userCols+` FROM users ORDER BY lower(username)`)
}

func (s *Store) CountUsers(ctx context.Context) (n int, err error) {
	err = s.DB.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return
}

func (s *Store) CountAdmins(ctx context.Context) (n int, err error) {
	err = s.DB.QueryRow(ctx, `SELECT count(*) FROM users WHERE spa_role = 'admin' AND NOT disabled`).Scan(&n)
	return
}

func (s *Store) CreateUser(ctx context.Context, u User) (User, error) {
	if u.ID == "" {
		u.ID = NewID("usr")
	}
	if u.SPARole == "" {
		u.SPARole = "user"
	}
	var ext any
	if u.ExternalID != "" {
		ext = u.ExternalID
	}
	_, err := s.DB.Exec(ctx, `INSERT INTO users (id, username, email, name, source, external_id, password_hash, password_changed_at,
		must_change, disabled, spa_role) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		u.ID, u.Username, u.Email, u.Name, u.Source, ext, u.PasswordHash, u.PasswordChangedAt, u.MustChange, u.Disabled, u.SPARole)
	if err != nil {
		return User{}, mapErr(err)
	}
	return s.UserByID(ctx, u.ID)
}

// UpdateProfile saves the editable fields of a person.
func (s *Store) UpdateProfile(ctx context.Context, u User) error {
	tag, err := s.DB.Exec(ctx, `UPDATE users SET username = $2, email = $3, name = $4, disabled = $5, spa_role = $6, must_change = $7,
		updated_at = now() WHERE id = $1`, u.ID, u.Username, u.Email, u.Name, u.Disabled, u.SPARole, u.MustChange)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPassword stores a new password hash and keeps the old one in the history (trimmed to keep entries).
func (s *Store) SetPassword(ctx context.Context, id, hash string, mustChange bool, keep int) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var old string
	if err := tx.QueryRow(ctx, `SELECT password_hash FROM users WHERE id = $1 FOR UPDATE`, id).Scan(&old); err != nil {
		return mapErr(err)
	}
	if old != "" && keep > 0 {
		if _, err := tx.Exec(ctx, `INSERT INTO password_history (user_id, password_hash) VALUES ($1, $2)`, id, old); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM password_history WHERE user_id = $1 AND id NOT IN
		(SELECT id FROM password_history WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2)`, id, max(keep, 0)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET password_hash = $2, password_changed_at = now(), must_change = $3,
		failed_attempts = 0, locked_until = NULL, updated_at = now() WHERE id = $1`, id, hash, mustChange); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// PasswordHistory returns the earlier password hashes, newest first.
func (s *Store) PasswordHistory(ctx context.Context, id string, n int) ([]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT password_hash FROM password_history WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2`, id, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// SignInFailed counts a wrong password and locks the account for lock when attempts reach limit (limit 0: never).
func (s *Store) SignInFailed(ctx context.Context, id string, limit int, lock time.Duration) (locked bool, err error) {
	var n int
	if err := s.DB.QueryRow(ctx, `UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = $1 RETURNING failed_attempts`, id).Scan(&n); err != nil {
		return false, mapErr(err)
	}
	if limit > 0 && n >= limit {
		_, err = s.DB.Exec(ctx, `UPDATE users SET failed_attempts = 0, locked_until = now() + $2::interval WHERE id = $1`, id, lock.String())
		return true, err
	}
	return false, nil
}

func (s *Store) SignedIn(ctx context.Context, id string) error {
	_, err := s.DB.Exec(ctx, `UPDATE users SET failed_attempts = 0, locked_until = NULL, last_sign_in_at = now() WHERE id = $1`, id)
	return err
}

func (s *Store) Unlock(ctx context.Context, id string) error {
	_, err := s.DB.Exec(ctx, `UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1`, id)
	return err
}

// BindExternal makes the person's source and external ID those of a directory or provider.
func (s *Store) BindExternal(ctx context.Context, id, source, externalID string) error {
	_, err := s.DB.Exec(ctx, `UPDATE users SET source = $2, external_id = $3, password_hash = '', updated_at = now() WHERE id = $1`, id, source, externalID)
	return mapErr(err)
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `DELETE FROM role_assignments WHERE subject_type = 'user' AND subject_id = $1`, id); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}
