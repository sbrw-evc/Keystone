package app

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sbrw-evc/keystone/internal/directory"
	"github.com/sbrw-evc/keystone/internal/entra"
	"github.com/sbrw-evc/keystone/internal/oidcx"
	"github.com/sbrw-evc/keystone/internal/passkey"
	"github.com/sbrw-evc/keystone/internal/policy"
	"github.com/sbrw-evc/keystone/internal/store"
)

var (
	errCredentials = fail(http.StatusUnauthorized, "invalid_credentials", "Wrong user name or password")
	errLocked      = fail(http.StatusForbidden, "locked", "The account is locked after too many wrong passwords. Try again later or ask an administrator")
	errDisabled    = fail(http.StatusForbidden, "disabled", "This account is disabled")
	errTooMany     = fail(http.StatusTooManyRequests, "too_many_attempts", "Too many sign-in attempts. Wait a few minutes")
)

// signedIn is the answer of a successful sign-in: who, and where the browser goes next (back to the application
// that asked, or into Keystone).
type signedIn struct {
	User account `json:"user"`
	Next string  `json:"next"`
	// RecoveryCodes: set up during this sign-in, shown once.
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
}

// done finishes a sign-in: the session, then the pending authorization request (if any) or the return path.
func (a *App) done(w http.ResponseWriter, r *http.Request, u store.User, method string, mfa bool, request, ret string) (signedIn, error) {
	s, err := a.startSession(w, r, u, method, mfa)
	if err != nil {
		return signedIn{}, err
	}
	next := safeReturn(ret)
	if request != "" {
		var req authzRequest
		if err := a.state.Open(r.Context(), "authz", request, &req); err != nil {
			return signedIn{}, fail(http.StatusBadRequest, "request_expired", "The sign-in request of the application has expired. Open the application again")
		}
		next, err = a.finishAuthorize(r.Context(), a.Issuer(r), u, s, req)
		if err != nil {
			return signedIn{}, err
		}
	}
	acc, err := a.account(r.Context(), u, s)
	return signedIn{User: acc, Next: next}, err
}

// ---- password (local accounts and LDAP / Active Directory)

type passwordIn struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Request  string `json:"request"`
	Return   string `json:"return"`
}

func (a *App) signInPassword(w http.ResponseWriter, r *http.Request) {
	var in passwordIn
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	ctx := r.Context()
	ip := a.clientIP(r)
	in.Username = strings.TrimSpace(in.Username)
	if in.Username == "" || in.Password == "" || len(in.Password) > policy.MaxPasswordLength {
		writeError(w, errCredentials)
		return
	}
	if !a.limiter.Allow(ip, a.now()) {
		writeError(w, errTooMany)
		return
	}
	u, err := a.st.UserByUsername(ctx, in.Username)
	switch {
	case err == nil && u.Source == "local":
		u, err = a.checkLocal(ctx, u, in.Password)
	case (err == nil && u.Source == "ldap") || errors.Is(err, store.ErrNotFound):
		u, err = a.checkLDAP(ctx, in.Username, in.Password)
	case err == nil:
		err = fail(http.StatusUnauthorized, "use_provider", "This account signs in with "+sourceTitle(u.Source))
	}
	if err != nil {
		a.st.Audit(ctx, in.Username, "auth.sign_in_failed", in.Username, ip, map[string]any{"reason": errCode(err)})
		writeError(w, err)
		return
	}
	method := "pwd"
	if u.Source == "ldap" {
		method = "ldap"
	}
	res, err := a.proceed(w, r, u, pendingSignIn{UserID: u.ID, Method: method, Request: in.Request, Return: in.Return})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func errCode(err error) string {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Code
	}
	return "error"
}

func deref(t *time.Time, def time.Time) time.Time {
	if t == nil {
		return def
	}
	return *t
}

func sourceTitle(s string) string {
	return map[string]string{"local": "a password", "ldap": "the directory", "entra": "Microsoft", "google": "Google", "apple": "Apple", "oidc": "the single sign-on provider"}[s]
}

func (a *App) checkLocal(ctx context.Context, u store.User, password string) (store.User, error) {
	if !a.general(ctx).AllowLocal && u.SPARole != "admin" {
		return u, fail(http.StatusForbidden, "local_off", "Sign-in with a password is turned off")
	}
	if u.LockedUntil != nil && u.LockedUntil.After(a.now()) {
		return u, errLocked
	}
	ok, err := a.checkPassword(ctx, u, password)
	if err != nil {
		return u, err
	}
	if !ok {
		p := a.policy(ctx)
		limit, minutes := p.LockoutAttempts, p.LockoutMinutes
		if limit == 0 {
			limit, minutes = 20, 15 // the built-in limit
		}
		if locked, _ := a.st.SignInFailed(ctx, u.ID, limit, time.Duration(minutes)*time.Minute); locked {
			a.st.Audit(ctx, "spa", "user.locked", u.Username, "", map[string]any{"minutes": minutes})
		}
		return u, errCredentials
	}
	if u.Disabled {
		return u, errDisabled
	}
	return u, nil
}

// checkLDAP signs a person in with the directory and creates or refreshes their Keystone account and directory groups.
func (a *App) checkLDAP(ctx context.Context, username, password string) (store.User, error) {
	c := a.ldap(ctx)
	if !c.Enabled {
		policy.CheckPassword("", password) // the same time as a real check
		return store.User{}, errCredentials
	}
	id, err := directory.Authenticate(c, secretsValue(ctx, a, secretLDAP, "bind_password"), username, password)
	if err != nil {
		if errors.Is(err, directory.ErrInvalidCredentials) || errors.Is(err, directory.ErrUserNotFound) {
			return store.User{}, errCredentials
		}
		slog.Warn("ldap sign-in failed", "err", err)
		return store.User{}, fail(http.StatusBadGateway, "directory_unavailable", "The directory does not answer. Try again later")
	}
	u, err := a.upsertExternal(ctx, "ldap", directory.NormalizeDN(id.DN), id.Username, id.Email, id.Name, true)
	if err != nil {
		return u, err
	}
	if u.Disabled {
		return u, errDisabled
	}
	if id.GroupsKnown {
		groups := make([]store.DirGroup, 0, len(id.Groups))
		for _, dn := range id.Groups {
			groups = append(groups, store.DirGroup{ExternalID: dn, Name: cnOf(dn)})
		}
		if err := a.st.SyncDirectoryGroups(ctx, u.ID, "ldap", groups); err != nil {
			return u, err
		}
	}
	return u, nil
}

// cnOf is the first value of a DN ("CN=NOC,OU=Groups,…" → "NOC").
func cnOf(dn string) string {
	first, _, _ := strings.Cut(dn, ",")
	if _, v, ok := strings.Cut(first, "="); ok && v != "" {
		return strings.TrimSpace(v)
	}
	return dn
}

// upsertExternal finds the account bound to (source, externalID), else takes over the account with the same user
// name (link: a local account of the same person becomes a directory account) or creates one.
func (a *App) upsertExternal(ctx context.Context, source, externalID, username, email, name string, link bool) (store.User, error) {
	u, err := a.st.UserByExternal(ctx, source, externalID)
	if err == nil {
		changed := false
		if email != "" && u.Email != email {
			u.Email, changed = email, true
		}
		if name != "" && u.Name != name {
			u.Name, changed = name, true
		}
		if changed {
			if err := a.st.UpdateProfile(ctx, u); err != nil {
				return u, err
			}
		}
		return u, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return u, err
	}
	if username == "" {
		username = email
	}
	if same, err := a.st.UserByUsername(ctx, username); err == nil {
		if !link || same.Source != "local" || same.SPARole == "admin" {
			return store.User{}, fail(http.StatusConflict, "account_exists", "An account named "+username+" already exists and signs in another way")
		}
		if err := a.bindExternal(ctx, same.ID, source, externalID); err != nil {
			return same, err
		}
		a.st.Audit(ctx, "spa", "user.linked", same.Username, "", map[string]any{"source": source})
		return a.st.UserByID(ctx, same.ID)
	}
	u, err = a.st.CreateUser(ctx, store.User{Username: username, Email: email, Name: name, Source: source, ExternalID: externalID})
	if err == nil {
		a.st.Audit(ctx, "spa", "user.created", u.Username, "", map[string]any{"source": source})
	}
	return u, err
}

// ---- password change (self service, also with a ticket after an expired password)

type changeIn struct {
	Ticket  string `json:"ticket"`
	Current string `json:"current"`
	New     string `json:"new"`
}

func (a *App) changePassword(w http.ResponseWriter, r *http.Request) {
	var in changeIn
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	ctx := r.Context()
	var u store.User
	var ticket pendingSignIn // a person whose password expired (or must be changed) sets a new one without a session
	if in.Ticket != "" {
		if err := a.state.Open(ctx, "change", in.Ticket, &ticket); err != nil {
			writeError(w, fail(http.StatusBadRequest, "ticket_expired", "Too much time has passed. Sign in again"))
			return
		}
		var err error
		if u, err = a.st.UserByID(ctx, ticket.UserID); err != nil {
			writeError(w, err)
			return
		}
	} else if p := current(r); p != nil {
		u = p.User
	} else {
		writeError(w, errAuth)
		return
	}
	if u.Source != "local" {
		writeError(w, fail(http.StatusConflict, "not_local", "The password of this account is changed in "+sourceTitle(u.Source)))
		return
	}
	if ok, err := a.checkPassword(ctx, u, in.Current); err != nil {
		writeError(w, err)
		return
	} else if !ok {
		writeError(w, fail(http.StatusUnauthorized, "wrong_password", "The current password is wrong"))
		return
	}
	if err := a.setPassword(ctx, u, in.New, false); err != nil {
		writeError(w, err)
		return
	}
	a.st.Audit(ctx, u.Username, "auth.password_changed", u.Username, a.clientIP(r), nil)
	if in.Ticket == "" {
		p := current(r)
		a.st.DeleteSessions(ctx, u.ID, "", p.Session.ID) //nolint:errcheck
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	u, _ = a.st.UserByID(ctx, u.ID)
	res, err := a.proceed(w, r, u, ticket)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// setPassword checks a new password against the policy and the history and stores it.
func (a *App) setPassword(ctx context.Context, u store.User, password string, mustChange bool) error {
	p := a.policy(ctx)
	if v := p.Check(password, u.Username); len(v) > 0 {
		return &apiError{Status: http.StatusBadRequest, Code: "password_policy", Message: "The password does not meet the password policy", Violations: v}
	}
	cur, err := a.password(ctx, u.ID)
	if err != nil {
		return err
	}
	if cur.Hash != "" && policy.CheckPassword(cur.Hash, password) {
		return &apiError{Status: http.StatusBadRequest, Code: "password_policy", Message: "The new password must differ from the current one", Violations: []string{policy.ViolationHistory}}
	}
	if p.HistoryCount > 0 {
		old := cur.History
		if len(old) > p.HistoryCount {
			old = old[:p.HistoryCount]
		}
		for _, h := range old {
			if policy.CheckPassword(h, password) {
				return &apiError{Status: http.StatusBadRequest, Code: "password_policy", Message: "This password was used recently", Violations: []string{policy.ViolationHistory}}
			}
		}
	}
	hash, err := policy.HashPassword(password)
	if err != nil {
		return err
	}
	return a.storePassword(ctx, u.ID, hash, mustChange, max(p.HistoryCount-1, 0))
}

// ---- passkeys

func (a *App) party(ctx context.Context, r *http.Request) (passkey.Party, error) {
	s := a.passkeys(ctx)
	if !s.Enabled {
		return passkey.Party{}, fail(http.StatusNotFound, "method_off", "Passkeys are turned off")
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = a.Issuer(r)
	}
	p, err := passkey.NewParty(s.RPID, "Keystone", origin)
	if err != nil {
		return p, fail(http.StatusBadRequest, "passkey_origin", err.Error())
	}
	return p, nil
}

func (a *App) passkeyBegin(w http.ResponseWriter, r *http.Request) {
	p, err := a.party(r.Context(), r)
	if err != nil {
		writeError(w, err)
		return
	}
	started, err := a.ceremonies.BeginLogin(p)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, started)
}

type passkeyFinishIn struct {
	Ceremony   string          `json:"ceremony"`
	Credential json.RawMessage `json:"credential"`
	Name       string          `json:"name"`
	Request    string          `json:"request"`
	Return     string          `json:"return"`
}

func (a *App) passkeyFinish(w http.ResponseWriter, r *http.Request) {
	var in passkeyFinishIn
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	ctx := r.Context()
	if !a.limiter.Allow(a.clientIP(r), a.now()) {
		writeError(w, errTooMany)
		return
	}
	var owner store.User
	lookup := func(credentialID, handle []byte) (passkey.Account, error) {
		id, err := a.st.PasskeyOwner(ctx, credentialID)
		if err != nil {
			return passkey.Account{}, passkey.ErrUnknown
		}
		u, err := a.st.UserByID(ctx, id)
		if err != nil {
			return passkey.Account{}, passkey.ErrUnknown
		}
		keys, _ := a.st.Passkeys(ctx, u.ID)
		acc, ok := passkey.AccountFor(u.Username, displayName(u), keys, credentialID, handle)
		if !ok {
			return passkey.Account{}, passkey.ErrUnknown
		}
		owner = u
		return acc, nil
	}
	_, used, err := a.ceremonies.FinishLogin(in.Ceremony, in.Credential, lookup, a.now())
	if err != nil {
		writeError(w, fail(http.StatusUnauthorized, "passkey_failed", err.Error()))
		return
	}
	if owner.Disabled {
		writeError(w, errDisabled)
		return
	}
	a.st.PasskeyUsed(ctx, used.ID, used.SignCount, used.BackupState) //nolint:errcheck
	res, err := a.done(w, r, owner, "passkey", true, in.Request, in.Return)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func displayName(u store.User) string {
	if u.Name != "" {
		return u.Name
	}
	return u.Username
}

// ---- Microsoft Entra ID, Google, Apple, OpenID Connect

const ssoCookie = "spa_sso"

// ssoState travels in the provider's state parameter (sealed) and the verifier in a cookie bound to it.
type ssoState struct {
	Kind     string `json:"k"`
	Nonce    string `json:"n"`
	Verifier string `json:"vh"`
	Request  string `json:"r"`
	Return   string `json:"t"`
}

func (a *App) ssoStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	kind := r.PathValue("kind")
	req := oidcx.NewRequest()
	st := ssoState{Kind: kind, Nonce: req.Nonce, Verifier: hashToken(req.Verifier), Request: r.URL.Query().Get("request"), Return: r.URL.Query().Get("return")}
	sealed, err := a.state.Seal(ctx, "sso", st, 10*time.Minute)
	if err != nil {
		a.signinError(w, r, err)
		return
	}
	req.State = sealed
	var target string
	if kind == "entra" {
		c := a.entra(ctx, r)
		if !c.Enabled {
			a.signinError(w, r, fail(http.StatusNotFound, "method_off", "This sign-in method is turned off"))
			return
		}
		m, err := entra.Discover(ctx, c)
		if err != nil {
			a.signinError(w, r, fail(http.StatusBadGateway, "provider_unavailable", "Microsoft did not answer. Try again later"))
			return
		}
		target = entra.AuthURL(c, m, entra.Request{State: req.State, Nonce: req.Nonce, Verifier: req.Verifier})
	} else {
		c, _, err := a.providerClient(ctx, r, kind)
		if err != nil {
			a.signinError(w, r, err)
			return
		}
		m, err := oidcx.Discover(ctx, c.Issuer)
		if err != nil {
			a.signinError(w, r, fail(http.StatusBadGateway, "provider_unavailable", "The sign-in provider did not answer. Try again later"))
			return
		}
		target = oidcx.AuthURL(c, m, req)
	}
	// Apple answers with a cross-site POST, which carries only SameSite=None cookies.
	same := http.SameSiteLaxMode
	if kind == "apple" {
		same = http.SameSiteNoneMode
	}
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: req.Verifier, Path: "/api/v1/auth/sso/", HttpOnly: true,
		Secure: a.secure(r) || same == http.SameSiteNoneMode, SameSite: same, MaxAge: 600})
	http.Redirect(w, r, target, http.StatusFound)
}

func (a *App) ssoCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	kind := r.PathValue("kind")
	if r.Method == http.MethodPost {
		r.ParseForm() //nolint:errcheck
	}
	q := r.Form
	if q == nil {
		q = r.URL.Query()
	}
	if r.Method == http.MethodGet {
		q = r.URL.Query()
	}
	if q.Get("error") != "" {
		a.signinError(w, r, fail(http.StatusUnauthorized, "provider_refused", "The provider refused the sign-in or it was cancelled"))
		return
	}
	var st ssoState
	c, cerr := r.Cookie(ssoCookie)
	if a.state.Open(ctx, "sso", q.Get("state"), &st) != nil || st.Kind != kind || cerr != nil || hashToken(c.Value) != st.Verifier {
		a.signinError(w, r, fail(http.StatusBadRequest, "state", "The sign-in took too long or was started in another browser. Try again"))
		return
	}
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: "", Path: "/api/v1/auth/sso/", MaxAge: -1})
	req := oidcx.Request{State: q.Get("state"), Nonce: st.Nonce, Verifier: c.Value}
	var u store.User
	var err error
	if kind == "entra" {
		u, err = a.completeEntra(ctx, r, q.Get("code"), req)
	} else {
		u, err = a.completeProvider(ctx, r, kind, q.Get("code"), req, q.Get("user"))
	}
	if err != nil {
		slog.Warn("provider sign-in rejected", "provider", kind, "err", err)
		a.st.Audit(ctx, "", "auth.sign_in_failed", kind, a.clientIP(r), map[string]any{"reason": err.Error()})
		a.signinError(w, r, err)
		return
	}
	if u.Disabled {
		a.signinError(w, r, errDisabled)
		return
	}
	res, err := a.done(w, r, u, kind, false, st.Request, st.Return)
	if err != nil {
		a.signinError(w, r, err)
		return
	}
	http.Redirect(w, r, res.Next, http.StatusFound)
}

// signinError shows a failed redirect sign-in on the sign-in page.
func (a *App) signinError(w http.ResponseWriter, r *http.Request, err error) {
	msg := "Sign-in failed"
	var ae *apiError
	if errors.As(err, &ae) {
		msg = ae.Message
	} else {
		slog.Warn("sign-in failed", "err", err)
	}
	http.Redirect(w, r, "/signin?error="+url.QueryEscape(msg), http.StatusFound)
}

func (a *App) completeEntra(ctx context.Context, r *http.Request, code string, req oidcx.Request) (store.User, error) {
	c := a.entra(ctx, r)
	if !c.Enabled {
		return store.User{}, fail(http.StatusNotFound, "method_off", "This sign-in method is turned off")
	}
	c.ReadGroups = true
	acc, err := entra.SignIn(ctx, c, secretsValue(ctx, a, secretEntra, "client_secret"), code,
		entra.Request{State: req.State, Nonce: req.Nonce, Verifier: req.Verifier}, a.now())
	if err != nil {
		if errors.Is(err, entra.ErrNotAllowed) {
			return store.User{}, fail(http.StatusForbidden, "not_member", "Your Microsoft account is not in the group allowed to sign in")
		}
		return store.User{}, fail(http.StatusUnauthorized, "provider_refused", "Microsoft sign-in failed: "+err.Error())
	}
	u, err := a.upsertExternal(ctx, "entra", acc.ObjectID, acc.Username, acc.Email, acc.Name, true)
	if err != nil {
		return u, err
	}
	if acc.GroupsKnown {
		groups := make([]store.DirGroup, 0, len(acc.Groups))
		for _, g := range acc.Groups {
			groups = append(groups, store.DirGroup{ExternalID: g, Name: "Entra " + g})
		}
		if err := a.st.SyncDirectoryGroups(ctx, u.ID, "entra", groups); err != nil {
			return u, err
		}
	}
	return u, nil
}

func (a *App) completeProvider(ctx context.Context, r *http.Request, kind, code string, req oidcx.Request, appleUser string) (store.User, error) {
	c, p, err := a.providerClient(ctx, r, kind)
	if err != nil {
		return store.User{}, err
	}
	m, err := oidcx.Discover(ctx, c.Issuer)
	if err != nil {
		return store.User{}, fail(http.StatusBadGateway, "provider_unavailable", "The sign-in provider did not answer. Try again later")
	}
	t, err := oidcx.Exchange(ctx, c, m, code, req)
	if err != nil {
		return store.User{}, fail(http.StatusUnauthorized, "provider_refused", err.Error())
	}
	cl, err := oidcx.Verify(ctx, m, c.ClientID, t.IDToken, req.Nonce, a.now())
	if err != nil {
		return store.User{}, fail(http.StatusUnauthorized, "provider_refused", err.Error())
	}
	sub := cl.String("sub")
	email := strings.ToLower(strings.TrimSpace(cl.String("email")))
	verified := cl.Bool("email_verified") || (kind == "oidc" && cl["email_verified"] == nil && email != "")
	if sub == "" || email == "" || !verified {
		return store.User{}, fail(http.StatusForbidden, "provider_not_allowed", "The provider gave no verified e-mail address")
	}
	domain := email[strings.LastIndex(email, "@")+1:]
	if len(p.AllowedDomains) > 0 && !contains(p.AllowedDomains, domain) {
		return store.User{}, fail(http.StatusForbidden, "provider_not_allowed", "The domain of "+email+" is not allowed")
	}
	if kind == "google" && len(p.AllowedDomains) > 0 && !contains(p.AllowedDomains, strings.ToLower(cl.String("hd"))) {
		return store.User{}, fail(http.StatusForbidden, "provider_not_allowed", email+" is not a Workspace account of an allowed domain")
	}
	if u, err := a.st.UserByExternal(ctx, kind, sub); err == nil {
		return u, nil
	}
	// The first sign-in of a person who already has an account: bind it by the verified e-mail.
	if same, err := a.st.UsersByEmail(ctx, email); err == nil && len(same) == 1 && same[0].SPARole != "admin" {
		if err := a.bindExternal(ctx, same[0].ID, kind, sub); err != nil {
			return store.User{}, err
		}
		a.st.Audit(ctx, "spa", "user.linked", same[0].Username, "", map[string]any{"source": kind})
		return a.st.UserByID(ctx, same[0].ID)
	}
	if p.ExistingOnly {
		return store.User{}, fail(http.StatusForbidden, "provider_not_allowed", email+" has no Keystone account")
	}
	name := cl.String("name")
	if kind == "apple" && appleUser != "" {
		var au struct {
			Name struct {
				FirstName string `json:"firstName"`
				LastName  string `json:"lastName"`
			} `json:"name"`
		}
		if json.Unmarshal([]byte(appleUser), &au) == nil {
			name = strings.TrimSpace(au.Name.FirstName + " " + au.Name.LastName)
		}
	}
	u, err := a.upsertExternal(ctx, kind, sub, email, email, name, false)
	if err != nil {
		return u, err
	}
	if p.GroupsClaim != "" {
		var groups []store.DirGroup
		for _, g := range cl.Strings(p.GroupsClaim) {
			groups = append(groups, store.DirGroup{ExternalID: g, Name: g})
		}
		if err := a.st.SyncDirectoryGroups(ctx, u.ID, kind, groups); err != nil {
			return u, err
		}
	}
	return u, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}
