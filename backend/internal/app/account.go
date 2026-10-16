package app

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/sbrw-evc/keystone/internal/passkey"
	"github.com/sbrw-evc/keystone/internal/store"
)

// account is the signed-in person as the web app sees them, with the applications they can open.
type account struct {
	ID                  string        `json:"id"`
	Username            string        `json:"username"`
	Name                string        `json:"name"`
	Email               string        `json:"email"`
	Source              string        `json:"source"`
	SPARole             string        `json:"spa_role"`
	MustChange          bool          `json:"must_change"`
	PasswordExpiresAt   *time.Time    `json:"password_expires_at,omitempty"`
	PasswordExpiresSoon bool          `json:"password_expires_soon"`
	Passkeys            int           `json:"passkeys"`
	PasskeysEnabled     bool          `json:"passkeys_enabled"`
	Groups              []string      `json:"groups"`
	Applications        []appLauncher `json:"applications"`
	SessionMethod       string        `json:"session_method"`
	// TOTP: two-step verification with an authenticator app is on; TOTPRequired: the password policy requires it.
	TOTP         bool `json:"totp"`
	TOTPRequired bool `json:"totp_required"`
}

type appLauncher struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	URL   string   `json:"url"`
	Roles []string `json:"roles"`
}

func (a *App) account(ctx context.Context, u store.User, s store.Session) (account, error) {
	acc := account{ID: u.ID, Username: u.Username, Name: displayName(u), Email: u.Email, Source: u.Source, SPARole: u.SPARole,
		MustChange: u.MustChange, PasskeysEnabled: a.passkeys(ctx).Enabled, SessionMethod: s.Method, Applications: []appLauncher{}}
	if u.Source == "local" {
		p := a.policy(ctx)
		age := p.Age(deref(u.PasswordChangedAt, u.CreatedAt), a.now())
		if !age.ExpiresAt.IsZero() {
			t := age.ExpiresAt
			acc.PasswordExpiresAt = &t
			acc.PasswordExpiresSoon = age.Warning
		}
	}
	keys, err := a.st.Passkeys(ctx, u.ID)
	if err != nil {
		return acc, err
	}
	acc.Passkeys = len(keys)
	t, err := a.st.TOTPOf(ctx, u.ID)
	if err != nil {
		return acc, err
	}
	acc.TOTP, acc.TOTPRequired = t.Enabled, a.secondFactorRequired(ctx, u)
	if acc.Groups, err = a.st.UserGroups(ctx, u.ID); err != nil {
		return acc, err
	}
	roles, err := a.st.UserAppRoles(ctx, u.ID)
	if err != nil {
		return acc, err
	}
	apps, err := a.st.Applications(ctx)
	if err != nil {
		return acc, err
	}
	for _, app := range apps {
		if known := knownRoles(app, roles[app.ID]); len(known) > 0 {
			acc.Applications = append(acc.Applications, appLauncher{ID: app.ID, Name: app.Name, Type: app.Type, URL: app.BaseURL, Roles: known})
		}
	}
	return acc, nil
}

func (a *App) me(w http.ResponseWriter, r *http.Request) {
	p := current(r)
	acc, err := a.account(r.Context(), p.User, p.Session)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, acc)
}

// methodsView is what the public sign-in page needs.
func (a *App) signInMethods(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	g := a.general(ctx)
	p := a.policy(ctx)
	writeJSON(w, http.StatusOK, map[string]any{"organization": g.Organization, "methods": a.methods(ctx, r), "password_policy": p})
}

// ---- own passkeys

type passkeyView struct {
	passkey.Passkey
	Kind string `json:"kind"`
}

func viewPasskeys(keys []passkey.Passkey) []passkeyView {
	out := make([]passkeyView, 0, len(keys))
	for _, k := range keys {
		out = append(out, passkeyView{Passkey: k, Kind: kindOf(k.Transports)})
	}
	return out
}

func kindOf(t []string) string {
	for _, x := range t {
		switch x {
		case "usb", "nfc", "ble":
			return "security_key"
		case "hybrid":
			return "phone"
		}
	}
	return "device"
}

func (a *App) myPasskeys(w http.ResponseWriter, r *http.Request) {
	keys, err := a.st.Passkeys(r.Context(), current(r).User.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, viewPasskeys(keys))
}

func (a *App) passkeyAccount(ctx context.Context, u store.User) (passkey.Account, error) {
	keys, err := a.st.Passkeys(ctx, u.ID)
	if err != nil {
		return passkey.Account{}, err
	}
	return passkey.Account{Handle: []byte(u.ID), Name: u.Username, Display: displayName(u), Keys: keys}, nil
}

func (a *App) addPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := current(r)
	party, err := a.party(ctx, r)
	if err != nil {
		writeError(w, err)
		return
	}
	acc, err := a.passkeyAccount(ctx, p.User)
	if err != nil {
		writeError(w, err)
		return
	}
	if len(acc.Keys) >= passkey.MaxPasskeys {
		writeError(w, fail(http.StatusConflict, "passkey_limit", "Too many passkeys: remove one first"))
		return
	}
	started, err := a.ceremonies.BeginRegistration(party, p.User.ID, acc)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, started)
}

func (a *App) addPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := current(r)
	var in passkeyFinishIn
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	acc, err := a.passkeyAccount(ctx, p.User)
	if err != nil {
		writeError(w, err)
		return
	}
	k, err := a.ceremonies.FinishRegistration(in.Ceremony, p.User.ID, acc, in.Credential, a.now())
	if err != nil {
		writeError(w, fail(http.StatusBadRequest, "passkey_failed", err.Error()))
		return
	}
	k.ID = store.NewID("pk")
	k.Name = strings.TrimSpace(in.Name)
	if k.Name == "" {
		k.Name = passkey.DefaultName(k)
	}
	if len(k.Name) > 64 {
		k.Name = k.Name[:64]
	}
	if err := a.st.AddPasskey(ctx, p.User.ID, k); err != nil {
		writeError(w, err)
		return
	}
	a.st.Audit(ctx, p.User.Username, "passkey.added", p.User.Username, a.clientIP(r), map[string]any{"name": k.Name})
	writeJSON(w, http.StatusCreated, passkeyView{Passkey: k, Kind: kindOf(k.Transports)})
}

func (a *App) renamePasskey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 64 {
		writeError(w, fail(http.StatusBadRequest, "invalid_name", "Enter a name of up to 64 characters"))
		return
	}
	if err := a.st.RenamePasskey(r.Context(), current(r).User.ID, r.PathValue("id"), name); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) removePasskey(w http.ResponseWriter, r *http.Request) {
	p := current(r)
	n, err := a.st.DeletePasskeys(r.Context(), p.User.ID, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	if n == 0 {
		writeError(w, errNotFound)
		return
	}
	a.st.Audit(r.Context(), p.User.Username, "passkey.removed", p.User.Username, a.clientIP(r), nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---- own sessions

type sessionView struct {
	store.Session
	Current bool `json:"current"`
}

func (a *App) mySessions(w http.ResponseWriter, r *http.Request) {
	p := current(r)
	list, err := a.st.UserSessions(r.Context(), p.User.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]sessionView, 0, len(list))
	for _, s := range list {
		cur := s.ID == p.Session.ID
		s.ID = s.ID[:16]
		out = append(out, sessionView{Session: s, Current: cur})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) revokeSession(w http.ResponseWriter, r *http.Request) {
	p := current(r)
	if err := a.st.DeleteSessions(r.Context(), p.User.ID, r.PathValue("id"), p.Session.ID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func sortUsers(list []FederationUser) {
	sort.Slice(list, func(i, j int) bool { return strings.ToLower(list[i].Username) < strings.ToLower(list[j].Username) })
}

var _ = json.Marshal
