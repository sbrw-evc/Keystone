package app

import (
	"context"
	"encoding/base64"
	"net/http"
	"time"

	"rsc.io/qr"

	"github.com/sbrw-evc/keystone/internal/store"
	"github.com/sbrw-evc/keystone/internal/totp"
)

// The second factor of the sign-in with a password (local accounts and LDAP / Active Directory): an authenticator
// app (TOTP, RFC 6238) and one-time recovery codes. The secret and the keyed hashes of the recovery codes are kept
// in the secret store (OpenBao) at users/<user id>/totp; the database knows only whether it is on and the last step. A passkey sign-in is two-factor by itself and never asks for a code.

const recoveryKeyPath = "totp/recovery-key"

var (
	errWrongCode = fail(http.StatusUnauthorized, "wrong_code", "The code is wrong or has expired")
	errNoTOTP    = fail(http.StatusConflict, "totp_off", "Two-step verification is not turned on")
)

// pendingSignIn is a sign-in whose password was right and that waits for its next step: the code of the
// authenticator app, a new password, or setting up the authenticator app. It travels sealed in a ticket.
type pendingSignIn struct {
	UserID  string `json:"u"`
	Method  string `json:"m"`
	MFA     bool   `json:"f"` // the second factor was given
	Request string `json:"r"`
	Return  string `json:"t"`
}

// passwordAccount: the account signs in with a password, so the second factor applies to it.
func passwordAccount(u store.User) bool { return u.Source == "local" || u.Source == "ldap" }

// secondFactorRequired: the password policy makes this person use an authenticator app.
func (a *App) secondFactorRequired(ctx context.Context, u store.User) bool {
	return passwordAccount(u) && a.policy(ctx).SecondFactorRequired(u.SPARole)
}

func (a *App) ticketError(ctx context.Context, purpose string, p pendingSignIn, ttl time.Duration, e *apiError, extra map[string]any) error {
	ticket, err := a.state.Seal(ctx, purpose, p, ttl)
	if err != nil {
		return err
	}
	if extra == nil {
		extra = map[string]any{}
	}
	extra["ticket"] = ticket
	e.Extra = extra
	return e
}

// proceed takes a sign-in with a right password through its remaining steps: the code of the authenticator app
// (when the person has one), a new password (when it expired or must be changed), setting up the authenticator app
// (when the policy requires one and the person has none); then the session.
func (a *App) proceed(w http.ResponseWriter, r *http.Request, u store.User, p pendingSignIn) (signedIn, error) {
	ctx := r.Context()
	if p.Method == "" {
		p.Method = "pwd"
	}
	if !p.MFA {
		t, err := a.totpOf(ctx, u.ID)
		if err != nil {
			return signedIn{}, err
		}
		if t.Enabled {
			return signedIn{}, a.ticketError(ctx, "totp", p, 5*time.Minute,
				fail(http.StatusConflict, "totp_required", "Enter the code from your authenticator app"), nil)
		}
	}
	if u.Source == "local" && p.Method == "pwd" {
		if u.MustChange || a.policy(ctx).Age(deref(u.PasswordChangedAt, u.CreatedAt), a.now()).Expired {
			return signedIn{}, a.ticketError(ctx, "change", p, 10*time.Minute,
				fail(http.StatusConflict, "password_change_required", "Choose a new password to continue"), map[string]any{"expired": !u.MustChange})
		}
	}
	if !p.MFA && a.secondFactorRequired(ctx, u) {
		return signedIn{}, a.ticketError(ctx, "totp_setup", p, 15*time.Minute,
			fail(http.StatusConflict, "totp_setup_required", "Set up two-step verification to continue"), nil)
	}
	return a.done(w, r, u, p.Method, p.MFA, p.Request, p.Return)
}

// checkCode checks a code of the person's authenticator app, or one of their recovery codes. Wrong codes count
// like wrong passwords (the lockout of the password policy) and go to the audit log.
func (a *App) checkCode(ctx context.Context, u store.User, code, ip string) error {
	if u.LockedUntil != nil && u.LockedUntil.After(a.now()) {
		return errLocked
	}
	if u.Disabled {
		return errDisabled
	}
	ok, recovery, err := a.matchCode(ctx, u, code)
	if err != nil {
		return err
	}
	if !ok {
		a.st.Audit(ctx, u.Username, "totp.failed", u.Username, ip, nil)
		p := a.policy(ctx)
		limit, minutes := p.LockoutAttempts, p.LockoutMinutes
		if limit == 0 {
			limit, minutes = 20, 15 // the built-in limit
		}
		if locked, _ := a.st.SignInFailed(ctx, u.ID, limit, time.Duration(minutes)*time.Minute); locked {
			a.st.Audit(ctx, "spa", "user.locked", u.Username, "", map[string]any{"minutes": minutes, "reason": "wrong codes"})
			return errLocked
		}
		return errWrongCode
	}
	if recovery {
		t, _ := a.totpOf(ctx, u.ID)
		a.st.Audit(ctx, u.Username, "totp.recovery_used", u.Username, ip, map[string]any{"left": t.RecoveryLeft})
	}
	return nil
}

func (a *App) matchCode(ctx context.Context, u store.User, code string) (ok, recovery bool, err error) {
	t, err := a.totpOf(ctx, u.ID)
	if err != nil || !t.Enabled {
		return false, false, err
	}
	if totp.IsCode(code) {
		rec, err := a.totpSecret(ctx, u.ID)
		if err != nil {
			return false, false, err
		}
		secret := rec.Secret
		step, match := totp.Check(secret, code, a.now())
		if !match || secret == "" {
			return false, false, nil
		}
		used, err := a.st.UseTOTPStep(ctx, u.ID, step)
		return used, false, err
	}
	norm, isRecovery := totp.NormalizeRecovery(code)
	if !isRecovery {
		return false, false, nil
	}
	h, err := a.recoveryHash(ctx, u.ID, norm)
	if err != nil {
		return false, false, err
	}
	used, err := a.useRecovery(ctx, u.ID, h)
	return used, used, err
}

func (a *App) recoveryHash(ctx context.Context, userID, code string) (string, error) {
	return a.recovery.Hash(ctx, userID+"\x00"+code)
}

func (a *App) newRecoveryCodes(ctx context.Context, userID string) ([]string, []string, error) {
	codes := totp.NewRecoveryCodes(totp.RecoveryCount)
	hashes := make([]string, len(codes))
	for i, c := range codes {
		norm, _ := totp.NormalizeRecovery(c)
		h, err := a.recoveryHash(ctx, userID, norm)
		if err != nil {
			return nil, nil, err
		}
		hashes[i] = h
	}
	return codes, hashes, nil
}

// totpSetup is what the person scans or types into the authenticator app.
type totpSetup struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
	QR     string `json:"qr"` // data:image/png;base64,…
}

// beginSetup makes a new secret, keeps it as pending (the current one, if any, keeps working until the new one is
// confirmed) and shows it.
func (a *App) beginSetup(ctx context.Context, u store.User) (totpSetup, error) {
	if !passwordAccount(u) {
		return totpSetup{}, fail(http.StatusConflict, "totp_not_password", "Two-step verification is for accounts that sign in with a password")
	}
	secret := totp.NewSecret()
	unlock, err := a.st.LockUser(ctx, u.ID)
	if err != nil {
		return totpSetup{}, err
	}
	t, err := a.totpSecret(ctx, u.ID)
	if err == nil {
		t.Pending = secret
		err = a.putTOTP(ctx, u.ID, t)
	}
	unlock()
	if err != nil {
		return totpSetup{}, err
	}
	issuer := a.general(ctx).Organization
	if issuer == "" {
		issuer = "Keystone"
	}
	uri := totp.URI(issuer, u.Username, secret)
	code, err := qr.Encode(uri, qr.M)
	if err != nil {
		return totpSetup{}, err
	}
	code.Scale = 6
	return totpSetup{Secret: secret, URI: uri, QR: "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())}, nil
}

// confirmSetup turns the pending secret on when code matches it, and returns the new recovery codes (shown once).
func (a *App) confirmSetup(ctx context.Context, u store.User, code, ip string) ([]string, error) {
	t, err := a.totpSecret(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	if t.Pending == "" {
		return nil, fail(http.StatusBadRequest, "totp_no_setup", "Start setting up the authenticator app again")
	}
	step, ok := totp.Check(t.Pending, code, a.now())
	if !ok {
		a.st.Audit(ctx, u.Username, "totp.failed", u.Username, ip, map[string]any{"setup": true})
		return nil, errWrongCode
	}
	codes, hashes, err := a.newRecoveryCodes(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	if err := a.putTOTP(ctx, u.ID, totpRecord{Secret: t.Pending, Recovery: hashes}); err != nil {
		return nil, err
	}
	before, _ := a.st.TOTPOf(ctx, u.ID)
	if err := a.st.EnableTOTP(ctx, u.ID, step); err != nil {
		return nil, err
	}
	a.st.Audit(ctx, u.Username, "totp.enabled", u.Username, ip, map[string]any{"replaced": before.Enabled})
	return codes, nil
}

// removeTOTP turns the second factor of a person off (the secret and the recovery codes go).
func (a *App) removeTOTP(ctx context.Context, userID string) (bool, error) {
	had, err := a.st.DisableTOTP(ctx, userID)
	if err != nil {
		return false, err
	}
	return had, a.forget(ctx, secretTOTP(userID))
}

// ---- the sign-in steps (public, with the ticket of the password step)

type ticketCodeIn struct {
	Ticket string `json:"ticket"`
	Code   string `json:"code"`
}

func (a *App) openPending(r *http.Request, purpose string, ticket string) (pendingSignIn, store.User, error) {
	var p pendingSignIn
	if err := a.state.Open(r.Context(), purpose, ticket, &p); err != nil {
		return p, store.User{}, fail(http.StatusBadRequest, "ticket_expired", "Too much time has passed. Sign in again")
	}
	u, err := a.st.UserByID(r.Context(), p.UserID)
	if err != nil {
		return p, u, fail(http.StatusBadRequest, "ticket_expired", "Too much time has passed. Sign in again")
	}
	if u.Disabled {
		return p, u, errDisabled
	}
	return p, u, nil
}

// signInTOTP: the code of the authenticator app (or a recovery code) after the password.
func (a *App) signInTOTP(w http.ResponseWriter, r *http.Request) {
	var in ticketCodeIn
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	ip := a.clientIP(r)
	if !a.limiter.Allow("totp|"+ip, a.now()) {
		writeError(w, errTooMany)
		return
	}
	p, u, err := a.openPending(r, "totp", in.Ticket)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := a.checkCode(r.Context(), u, in.Code, ip); err != nil {
		writeError(w, err)
		return
	}
	p.MFA = true
	res, err := a.proceed(w, r, u, p)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// signInTOTPSetup: a person the policy requires a second factor of sets it up during the sign-in.
func (a *App) signInTOTPSetup(w http.ResponseWriter, r *http.Request) {
	var in ticketCodeIn
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	_, u, err := a.openPending(r, "totp_setup", in.Ticket)
	if err != nil {
		writeError(w, err)
		return
	}
	s, err := a.beginSetup(r.Context(), u)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (a *App) signInTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	var in ticketCodeIn
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	ip := a.clientIP(r)
	if !a.limiter.Allow("totp|"+ip, a.now()) {
		writeError(w, errTooMany)
		return
	}
	p, u, err := a.openPending(r, "totp_setup", in.Ticket)
	if err != nil {
		writeError(w, err)
		return
	}
	codes, err := a.confirmSetup(r.Context(), u, in.Code, ip)
	if err != nil {
		writeError(w, err)
		return
	}
	p.MFA = true
	res, err := a.proceed(w, r, u, p)
	if err != nil {
		writeError(w, err)
		return
	}
	res.RecoveryCodes = codes
	writeJSON(w, http.StatusOK, res)
}

// ---- the signed-in person

type totpView struct {
	store.TOTP
	Available bool `json:"available"`
	Required  bool `json:"required"`
}

func (a *App) myTOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u := current(r).User
	t, err := a.totpOf(ctx, u.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, totpView{TOTP: t, Available: passwordAccount(u), Required: a.secondFactorRequired(ctx, u)})
}

// myTOTPSetup starts setting up the authenticator app; replacing one that is on needs a current code first.
func (a *App) myTOTPSetup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u := current(r).User
	t, err := a.totpOf(ctx, u.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	if t.Enabled {
		if _, ok := a.myCodeAction(w, r); !ok {
			return
		}
	}
	s, err := a.beginSetup(ctx, u)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

type codeIn struct {
	Code string `json:"code"`
}

func (a *App) myTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	var in codeIn
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	ip := a.clientIP(r)
	if !a.limiter.Allow("totp|"+ip, a.now()) {
		writeError(w, errTooMany)
		return
	}
	codes, err := a.confirmSetup(r.Context(), current(r).User, in.Code, ip)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// myCodeAction runs an action on the person's second factor after a current code (or a recovery code).
func (a *App) myCodeAction(w http.ResponseWriter, r *http.Request) (store.User, bool) {
	var in codeIn
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return store.User{}, false
	}
	ctx := r.Context()
	ip := a.clientIP(r)
	if !a.limiter.Allow("totp|"+ip, a.now()) {
		writeError(w, errTooMany)
		return store.User{}, false
	}
	u := current(r).User
	if t, err := a.totpOf(ctx, u.ID); err != nil || !t.Enabled {
		if err == nil {
			err = errNoTOTP
		}
		writeError(w, err)
		return u, false
	}
	if err := a.checkCode(ctx, u, in.Code, ip); err != nil {
		writeError(w, err)
		return u, false
	}
	return u, true
}

func (a *App) myTOTPDisable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if u := current(r).User; a.secondFactorRequired(ctx, u) {
		writeError(w, fail(http.StatusConflict, "totp_required_by_policy", "The password policy requires two-step verification for your account"))
		return
	}
	u, ok := a.myCodeAction(w, r)
	if !ok {
		return
	}
	if _, err := a.removeTOTP(ctx, u.ID); err != nil {
		writeError(w, err)
		return
	}
	a.st.Audit(ctx, u.Username, "totp.disabled", u.Username, a.clientIP(r), nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) myRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	u, ok := a.myCodeAction(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	codes, hashes, err := a.newRecoveryCodes(ctx, u.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := a.replaceRecovery(ctx, u.ID, hashes); err != nil {
		writeError(w, err)
		return
	}
	a.st.Audit(ctx, u.Username, "totp.recovery_renewed", u.Username, a.clientIP(r), nil)
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// ---- administration: a person who lost their authenticator app

func (a *App) resetUserTOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, err := a.st.UserByID(ctx, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	had, err := a.removeTOTP(ctx, u.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	if !had {
		writeError(w, errNoTOTP)
		return
	}
	a.st.Audit(ctx, actor(r), "user.totp_reset", u.Username, a.clientIP(r), nil)
	w.WriteHeader(http.StatusNoContent)
}
