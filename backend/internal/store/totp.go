package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// TOTP is the authenticator app of a person (the secret is in the secret store).
type TOTP struct {
	Enabled      bool       `json:"enabled"`
	EnabledAt    *time.Time `json:"enabled_at,omitempty"`
	RecoveryLeft int        `json:"recovery_codes_left"`
	lastStep     int64
}

// TOTPOf tells whether the person has an authenticator app and how many recovery codes are left.
func (s *Store) TOTPOf(ctx context.Context, userID string) (TOTP, error) {
	var t TOTP
	var at time.Time
	err := s.DB.QueryRow(ctx, `SELECT enabled_at, last_step, (SELECT count(*) FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL)
		FROM totp WHERE user_id = $1`, userID).Scan(&at, &t.lastStep, &t.RecoveryLeft)
	if errors.Is(err, pgx.ErrNoRows) {
		return TOTP{}, nil
	}
	if err != nil {
		return t, err
	}
	t.Enabled, t.EnabledAt = true, &at
	return t, nil
}

// TOTPUsers is the set of people with an authenticator app.
func (s *Store) TOTPUsers(ctx context.Context) (map[string]bool, error) {
	ids, err := s.strings(ctx, `SELECT user_id FROM totp`)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

// EnableTOTP turns the authenticator app on (or replaces it) with the step of the confirming code and new recovery
// codes.
func (s *Store) EnableTOTP(ctx context.Context, userID string, step int64, recoveryHashes []string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `INSERT INTO totp (user_id, last_step) VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE SET enabled_at = now(), last_step = excluded.last_step`, userID, step); err != nil {
		return mapErr(err)
	}
	if err := replaceRecovery(ctx, tx, userID, recoveryHashes); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func replaceRecovery(ctx context.Context, tx pgx.Tx, userID string, hashes []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	for _, h := range hashes {
		if _, err := tx.Exec(ctx, `INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)`, userID, h); err != nil {
			return err
		}
	}
	return nil
}

// ReplaceRecoveryCodes gives the person new recovery codes (the old ones stop working).
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID string, hashes []string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := replaceRecovery(ctx, tx, userID, hashes); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// DisableTOTP removes the authenticator app and the recovery codes; false when there was none.
func (s *Store) DisableTOTP(ctx context.Context, userID string) (bool, error) {
	tag, err := s.DB.Exec(ctx, `DELETE FROM totp WHERE user_id = $1`, userID)
	if err != nil {
		return false, err
	}
	if _, err := s.DB.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, userID); err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// UseTOTPStep accepts a code's time step once: false when this or a later step was already used (a replayed code).
func (s *Store) UseTOTPStep(ctx context.Context, userID string, step int64) (bool, error) {
	tag, err := s.DB.Exec(ctx, `UPDATE totp SET last_step = $2 WHERE user_id = $1 AND last_step < $2`, userID, step)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// UseRecoveryCode spends a recovery code: false when it is unknown or was used.
func (s *Store) UseRecoveryCode(ctx context.Context, userID, hash string) (bool, error) {
	tag, err := s.DB.Exec(ctx, `UPDATE recovery_codes SET used_at = now() WHERE id = (SELECT id FROM recovery_codes
		WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL LIMIT 1)`, userID, hash)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}
