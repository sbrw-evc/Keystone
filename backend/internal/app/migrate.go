package app

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/sbrw-evc/keystone/internal/secrets"
)

// legacyTOTP is where the secret of an authenticator app was kept before it moved to users/<id>/totp.
func legacyTOTP(userID string) string { return "totp/" + userID }

// MigrateSecrets moves what earlier versions kept outside the secret store into it, once, at start-up:
//
//   - the secrets sealed in the database with the master key (sealed: nil when there is no master key) — signing keys,
//     the state key, directory and provider secrets, authenticator apps — keep their paths, except totp/<id>;
//   - authenticator apps at totp/<id> (also in an OpenBao used before) go to users/<id>/totp;
//   - password hashes and their history, recovery codes, client secret and token hashes leave the database.
//
// Then the columns and tables of the database that held them are dropped. Every step can run again: a failure leaves
// the database as it was, and the next start repeats the move. The audit log records what was moved.
func (a *App) MigrateSecrets(ctx context.Context, sealed secrets.Store) error {
	n := map[string]int{}

	paths, err := a.st.SealedPaths(ctx)
	if err != nil {
		return err
	}
	if len(paths) > 0 && sealed == nil {
		slog.Warn("the database has secrets sealed with the master key: set SPA_MASTER_KEY once so that Keystone moves them to OpenBao", "secrets", len(paths))
	}
	if sealed != nil {
		for _, p := range paths {
			m, err := sealed.Get(ctx, p)
			if err != nil {
				return fmt.Errorf("moving the sealed secret %s: %w", p, err)
			}
			if err := a.sec.Put(ctx, p, m); err != nil {
				return fmt.Errorf("moving the sealed secret %s: %w", p, err)
			}
			n["sealed"]++
		}
	}

	// authenticator apps: totp/<id> → users/<id>/totp (the recovery codes join from the database below)
	codes, err := a.st.LegacyRecoveryCodes(ctx)
	if err != nil {
		return err
	}
	users, err := a.st.TOTPUsers(ctx)
	if err != nil {
		return err
	}
	for id := range codes {
		users[id] = true
	}
	for id := range users {
		old, err := a.get(ctx, legacyTOTP(id))
		if err != nil {
			return err
		}
		t, err := a.totpSecret(ctx, id)
		if err != nil {
			return err
		}
		if old["secret"] == "" && old["pending"] == "" && codes[id] == nil {
			continue
		}
		if t.Secret == "" {
			t.Secret = old["secret"]
		}
		if t.Pending == "" {
			t.Pending = old["pending"]
		}
		if c, ok := codes[id]; ok {
			t.Recovery = c
			n["recovery_codes"] += len(c)
		}
		if err := a.putTOTP(ctx, id, t); err != nil {
			return err
		}
		if err := a.forget(ctx, legacyTOTP(id)); err != nil {
			return err
		}
		n["totp"]++
	}

	passwords, err := a.st.LegacyPasswords(ctx)
	if err != nil {
		return err
	}
	for id, p := range passwords {
		if err := a.putPassword(ctx, id, passwordRecord{Hash: p.Hash, History: p.History}); err != nil {
			return err
		}
		n["passwords"]++
	}

	creds, err := a.st.LegacyAppCredentials(ctx)
	if err != nil {
		return err
	}
	for id, c := range creds {
		if err := a.putAppCreds(ctx, id, appCreds{SecretHash: c.SecretHash, TokenHash: c.TokenHash}); err != nil {
			return err
		}
		n["applications"]++
	}

	// Everything is in the secret store: the database lets go of it.
	if sealed != nil {
		for _, p := range paths {
			if err := sealed.Delete(ctx, p); err != nil {
				return err
			}
		}
	}
	legacy, err := a.st.HasLegacySecrets(ctx)
	if err != nil {
		return err
	}
	if err := a.st.DropLegacySecrets(ctx); err != nil {
		return err
	}
	moved := 0
	detail := map[string]any{"to": a.sec.Kind()}
	for k, v := range n {
		detail[k] = v
		moved += v
	}
	if moved > 0 || legacy {
		a.st.Audit(ctx, "spa", "secrets.migrated", "", "", detail)
		slog.Info("moved secrets out of the database into the secret store", "detail", detail)
	}
	return nil
}
