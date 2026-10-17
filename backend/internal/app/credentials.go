package app

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"

	"github.com/sbrw-evc/keystone/internal/policy"
	"github.com/sbrw-evc/keystone/internal/secrets"
	"github.com/sbrw-evc/keystone/internal/store"
)

// Passwords and secrets live only in the secret store (OpenBao); the database keeps what is not secret.
//
//	users/<id>/password   {"hash", "history": JSON list of earlier hashes, newest first}
//	users/<id>/totp       {"secret", "pending", "recovery": JSON list of recovery code hashes}
//	apps/<id>/credentials {"secret_hash", "token_hash"} — keyed hashes (HMAC-SHA256) of the client secret and token
//	apptokens/<token_hash> {"app_id"} — finds the application of a federation token

func secretPassword(userID string) string { return "users/" + userID + "/password" }
func secretTOTP(userID string) string     { return "users/" + userID + "/totp" }
func secretAppCreds(appID string) string  { return "apps/" + appID + "/credentials" }
func secretAppToken(hash string) string   { return "apptokens/" + hash }

// get reads a secret; a missing one is empty.
func (a *App) get(ctx context.Context, path string) (map[string]string, error) {
	m, err := a.sec.Get(ctx, path)
	if errors.Is(err, secrets.ErrNotFound) {
		return map[string]string{}, nil
	}
	return m, err
}

func (a *App) forget(ctx context.Context, path string) error {
	if err := a.sec.Delete(ctx, path); err != nil && !errors.Is(err, secrets.ErrNotFound) {
		return err
	}
	return nil
}

func jsonList(s string) []string {
	var out []string
	if s != "" {
		json.Unmarshal([]byte(s), &out) //nolint:errcheck
	}
	return out
}

func listJSON(v []string) string {
	if v == nil {
		v = []string{}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// ---- passwords

type passwordRecord struct {
	Hash    string
	History []string
}

func (a *App) password(ctx context.Context, userID string) (passwordRecord, error) {
	m, err := a.get(ctx, secretPassword(userID))
	if err != nil {
		return passwordRecord{}, err
	}
	return passwordRecord{Hash: m["hash"], History: jsonList(m["history"])}, nil
}

func (a *App) putPassword(ctx context.Context, userID string, p passwordRecord) error {
	return a.sec.Put(ctx, secretPassword(userID), map[string]string{"hash": p.Hash, "history": listJSON(p.History)})
}

// storePassword keeps a new hash and moves the current one into the history (keep entries; 0 keeps none), then
// records the change in the database.
func (a *App) storePassword(ctx context.Context, userID, hash string, mustChange bool, keep int) error {
	unlock, err := a.st.LockUser(ctx, userID)
	if err != nil {
		return err
	}
	defer unlock()
	p, err := a.password(ctx, userID)
	if err != nil {
		return err
	}
	history := []string{}
	if keep > 0 {
		if p.Hash != "" {
			history = append(history, p.Hash)
		}
		history = append(history, p.History...)
		if len(history) > keep {
			history = history[:keep]
		}
	}
	if err := a.putPassword(ctx, userID, passwordRecord{Hash: hash, History: history}); err != nil {
		return err
	}
	return a.st.PasswordChanged(ctx, userID, mustChange)
}

// checkPassword checks the person's password; a hash that is not Keystone's current one (Argon2id from an application
// that moved its users here) is replaced after a successful check, the history kept.
func (a *App) checkPassword(ctx context.Context, u store.User, password string) (bool, error) {
	p, err := a.password(ctx, u.ID)
	if err != nil {
		return false, err
	}
	if !policy.CheckPassword(p.Hash, password) {
		return false, nil
	}
	if policy.NeedsRehash(p.Hash) {
		if hash, err := policy.HashPassword(password); err == nil {
			unlock, err := a.st.LockUser(ctx, u.ID)
			if err == nil {
				if cur, err := a.password(ctx, u.ID); err == nil && cur.Hash == p.Hash {
					cur.Hash = hash
					a.putPassword(ctx, u.ID, cur) //nolint:errcheck
				}
				unlock()
			}
		}
	}
	return true, nil
}

// ---- authenticator apps

type totpRecord struct {
	Secret   string
	Pending  string
	Recovery []string // hashes of the unused recovery codes
}

func (a *App) totpSecret(ctx context.Context, userID string) (totpRecord, error) {
	m, err := a.get(ctx, secretTOTP(userID))
	if err != nil {
		return totpRecord{}, err
	}
	return totpRecord{Secret: m["secret"], Pending: m["pending"], Recovery: jsonList(m["recovery"])}, nil
}

func (a *App) putTOTP(ctx context.Context, userID string, t totpRecord) error {
	m := map[string]string{"recovery": listJSON(t.Recovery)}
	if t.Secret != "" {
		m["secret"] = t.Secret
	}
	if t.Pending != "" {
		m["pending"] = t.Pending
	}
	return a.sec.Put(ctx, secretTOTP(userID), m)
}

// totpOf is the authenticator app of a person with the number of recovery codes left.
func (a *App) totpOf(ctx context.Context, userID string) (store.TOTP, error) {
	t, err := a.st.TOTPOf(ctx, userID)
	if err != nil || !t.Enabled {
		return t, err
	}
	rec, err := a.totpSecret(ctx, userID)
	if err != nil {
		return t, err
	}
	t.RecoveryLeft = len(rec.Recovery)
	return t, nil
}

// useRecovery spends a recovery code (its hash): false when it is unknown or was used.
func (a *App) useRecovery(ctx context.Context, userID, hash string) (bool, error) {
	unlock, err := a.st.LockUser(ctx, userID)
	if err != nil {
		return false, err
	}
	defer unlock()
	t, err := a.totpSecret(ctx, userID)
	if err != nil {
		return false, err
	}
	for i, h := range t.Recovery {
		if subtle.ConstantTimeCompare([]byte(h), []byte(hash)) == 1 {
			t.Recovery = append(t.Recovery[:i:i], t.Recovery[i+1:]...)
			return true, a.putTOTP(ctx, userID, t)
		}
	}
	return false, nil
}

// replaceRecovery gives the person new recovery codes (their hashes); the old ones stop working.
func (a *App) replaceRecovery(ctx context.Context, userID string, hashes []string) error {
	unlock, err := a.st.LockUser(ctx, userID)
	if err != nil {
		return err
	}
	defer unlock()
	t, err := a.totpSecret(ctx, userID)
	if err != nil {
		return err
	}
	t.Recovery = hashes
	return a.putTOTP(ctx, userID, t)
}

// forgetUserSecrets removes the password and the authenticator app of a person from the secret store.
func (a *App) forgetUserSecrets(ctx context.Context, userID string) error {
	if err := a.forget(ctx, secretPassword(userID)); err != nil {
		return err
	}
	return a.forget(ctx, secretTOTP(userID))
}

// ---- applications

type appCreds struct {
	SecretHash string
	TokenHash  string
}

func (a *App) appCreds(ctx context.Context, appID string) (appCreds, error) {
	m, err := a.get(ctx, secretAppCreds(appID))
	if err != nil {
		return appCreds{}, err
	}
	return appCreds{SecretHash: m["secret_hash"], TokenHash: m["token_hash"]}, nil
}

// putAppCreds keeps the credential hashes of an application and the index of its token (the old token's goes).
func (a *App) putAppCreds(ctx context.Context, appID string, c appCreds) error {
	old, err := a.appCreds(ctx, appID)
	if err != nil {
		return err
	}
	if err := a.sec.Put(ctx, secretAppCreds(appID), map[string]string{"secret_hash": c.SecretHash, "token_hash": c.TokenHash}); err != nil {
		return err
	}
	if err := a.sec.Put(ctx, secretAppToken(c.TokenHash), map[string]string{"app_id": appID}); err != nil {
		return err
	}
	if old.TokenHash != "" && old.TokenHash != c.TokenHash {
		return a.forget(ctx, secretAppToken(old.TokenHash))
	}
	return nil
}

func (a *App) forgetAppCreds(ctx context.Context, appID string) error {
	old, err := a.appCreds(ctx, appID)
	if err != nil {
		return err
	}
	if old.TokenHash != "" {
		if err := a.forget(ctx, secretAppToken(old.TokenHash)); err != nil {
			return err
		}
	}
	return a.forget(ctx, secretAppCreds(appID))
}

// appByToken finds the application of a federation token.
func (a *App) appByToken(ctx context.Context, token string) (store.Application, error) {
	h := a.secretHash(ctx, token)
	if h == "" {
		return store.Application{}, errNoApp
	}
	idx, err := a.get(ctx, secretAppToken(h))
	if err != nil {
		return store.Application{}, err
	}
	if idx["app_id"] == "" {
		return store.Application{}, errNoApp
	}
	c, err := a.appCreds(ctx, idx["app_id"])
	if err != nil {
		return store.Application{}, err
	}
	if subtle.ConstantTimeCompare([]byte(c.TokenHash), []byte(h)) != 1 {
		return store.Application{}, errNoApp
	}
	return a.st.ApplicationByID(ctx, idx["app_id"])
}

// checkClientSecret compares a client secret with the application's.
func (a *App) checkClientSecret(ctx context.Context, appID, secret string) bool {
	c, err := a.appCreds(ctx, appID)
	if err != nil || c.SecretHash == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a.secretHash(ctx, secret)), []byte(c.SecretHash)) == 1
}

// newLocalUser creates a person; hash (may be empty: no password yet) goes to the secret store. When it cannot be
// stored the person is not created.
func (a *App) newLocalUser(ctx context.Context, u store.User, hash string) (store.User, error) {
	created, err := a.st.CreateUser(ctx, u)
	if err != nil || hash == "" {
		return created, err
	}
	if err := a.putPassword(ctx, created.ID, passwordRecord{Hash: hash}); err != nil {
		a.st.DeleteUser(ctx, created.ID) //nolint:errcheck
		return store.User{}, err
	}
	return created, nil
}

// bindExternal makes a local account one of a directory or provider: its password goes.
func (a *App) bindExternal(ctx context.Context, id, source, externalID string) error {
	if err := a.st.BindExternal(ctx, id, source, externalID); err != nil {
		return err
	}
	return a.forget(ctx, secretPassword(id))
}
