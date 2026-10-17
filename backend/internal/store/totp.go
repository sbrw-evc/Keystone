package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// TOTP is the authenticator app of a person. The secret and the recovery codes are in the secret store; here only
// whether it is on and the last time step accepted. RecoveryLeft is filled by the application from the secret store.
type TOTP struct {
	Enabled      bool       `json:"enabled"`
	EnabledAt    *time.Time `json:"enabled_at,omitempty"`
	RecoveryLeft int        `json:"recovery_codes_left"`
	lastStep     int64
}

// TOTPOf tells whether the person has an authenticator app.
func (s *Store) TOTPOf(ctx context.Context, userID string) (TOTP, error) {
	var t TOTP
	var at time.Time
	err := s.DB.QueryRow(ctx, `SELECT enabled_at, last_step FROM totp WHERE user_id = $1`, userID).Scan(&at, &t.lastStep)
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

// EnableTOTP turns the authenticator app on (or replaces it) with the step of the confirming code.
func (s *Store) EnableTOTP(ctx context.Context, userID string, step int64) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO totp (user_id, last_step) VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE SET enabled_at = now(), last_step = excluded.last_step`, userID, step)
	return mapErr(err)
}

// DisableTOTP removes the authenticator app; false when there was none.
func (s *Store) DisableTOTP(ctx context.Context, userID string) (bool, error) {
	tag, err := s.DB.Exec(ctx, `DELETE FROM totp WHERE user_id = $1`, userID)
	if err != nil {
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
