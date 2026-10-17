package store

import (
	"context"
)

// Before secrets moved to the secret store, the database kept password hashes (users.password_hash and the
// password_history table), recovery codes (recovery_codes), the hashes of client secrets and federation tokens
// (applications.secret_hash, token_hash) and, without OpenBao, the sealed secrets (the secrets table). These read
// what is left of them for the move; DropLegacySecrets removes them afterwards.

func (s *Store) hasColumn(ctx context.Context, table, column string) (bool, error) {
	var ok bool
	err := s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2)`, table, column).Scan(&ok)
	return ok, err
}

func (s *Store) hasTable(ctx context.Context, table string) (bool, error) {
	var ok bool
	err := s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables
		WHERE table_schema = current_schema() AND table_name = $1)`, table).Scan(&ok)
	return ok, err
}

// LegacyPassword is a password hash from the database with the earlier hashes, newest first.
type LegacyPassword struct {
	Hash    string
	History []string
}

// LegacyPasswords returns the password hashes still in the database, by person.
func (s *Store) LegacyPasswords(ctx context.Context) (map[string]LegacyPassword, error) {
	out := map[string]LegacyPassword{}
	if ok, err := s.hasColumn(ctx, "users", "password_hash"); err != nil || !ok {
		return out, err
	}
	rows, err := s.DB.Query(ctx, `SELECT id, password_hash FROM users WHERE password_hash <> ''`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, h string
		if err := rows.Scan(&id, &h); err != nil {
			rows.Close()
			return nil, err
		}
		out[id] = LegacyPassword{Hash: h}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if ok, err := s.hasTable(ctx, "password_history"); err != nil || !ok {
		return out, err
	}
	rows, err = s.DB.Query(ctx, `SELECT user_id, password_hash FROM password_history ORDER BY user_id, created_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, h string
		if err := rows.Scan(&id, &h); err != nil {
			return nil, err
		}
		p := out[id]
		p.History = append(p.History, h)
		out[id] = p
	}
	return out, rows.Err()
}

// LegacyRecoveryCodes returns the unused recovery code hashes still in the database, by person.
func (s *Store) LegacyRecoveryCodes(ctx context.Context) (map[string][]string, error) {
	out := map[string][]string{}
	if ok, err := s.hasTable(ctx, "recovery_codes"); err != nil || !ok {
		return out, err
	}
	rows, err := s.DB.Query(ctx, `SELECT user_id, code_hash FROM recovery_codes WHERE used_at IS NULL ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, h string
		if err := rows.Scan(&id, &h); err != nil {
			return nil, err
		}
		out[id] = append(out[id], h)
	}
	return out, rows.Err()
}

// LegacyAppCredential is the keyed hash of an application's client secret and federation token.
type LegacyAppCredential struct {
	SecretHash string
	TokenHash  string
}

// LegacyAppCredentials returns the credential hashes still in the database, by application.
func (s *Store) LegacyAppCredentials(ctx context.Context) (map[string]LegacyAppCredential, error) {
	out := map[string]LegacyAppCredential{}
	if ok, err := s.hasColumn(ctx, "applications", "token_hash"); err != nil || !ok {
		return out, err
	}
	rows, err := s.DB.Query(ctx, `SELECT id, secret_hash, token_hash FROM applications WHERE secret_hash <> '' OR token_hash <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var c LegacyAppCredential
		if err := rows.Scan(&id, &c.SecretHash, &c.TokenHash); err != nil {
			return nil, err
		}
		out[id] = c
	}
	return out, rows.Err()
}

// SealedPaths lists the secrets sealed in the database (the secret store without OpenBao).
func (s *Store) SealedPaths(ctx context.Context) ([]string, error) {
	if ok, err := s.hasTable(ctx, "secrets"); err != nil || !ok {
		return nil, err
	}
	return s.strings(ctx, `SELECT path FROM secrets ORDER BY path`)
}

// HasLegacySecrets tells whether the database still has any of the columns or tables of secrets.
func (s *Store) HasLegacySecrets(ctx context.Context) (bool, error) {
	for _, c := range [][2]string{{"users", "password_hash"}, {"applications", "secret_hash"}, {"applications", "token_hash"}} {
		if ok, err := s.hasColumn(ctx, c[0], c[1]); err != nil || ok {
			return ok, err
		}
	}
	for _, t := range []string{"password_history", "recovery_codes"} {
		if ok, err := s.hasTable(ctx, t); err != nil || ok {
			return ok, err
		}
	}
	paths, err := s.SealedPaths(ctx)
	return len(paths) > 0, err
}

// DropLegacySecrets removes the columns and tables that held secrets, once their values are in the secret store.
// The sealed secrets table goes only when it is empty (its rows are deleted as they are moved).
func (s *Store) DropLegacySecrets(ctx context.Context) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	for _, q := range []string{
		`ALTER TABLE users DROP COLUMN IF EXISTS password_hash`,
		`DROP TABLE IF EXISTS password_history`,
		`DROP TABLE IF EXISTS recovery_codes`,
		`ALTER TABLE applications DROP COLUMN IF EXISTS secret_hash, DROP COLUMN IF EXISTS token_hash`,
	} {
		if _, err := tx.Exec(ctx, q); err != nil {
			return err
		}
	}
	if ok, err := s.hasTable(ctx, "secrets"); err != nil {
		return err
	} else if ok {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM secrets`).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err := tx.Exec(ctx, `DROP TABLE secrets`); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}
