package app

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/sbrw-evc/spa/internal/directory"
	"github.com/sbrw-evc/spa/internal/entra"
	"github.com/sbrw-evc/spa/internal/oidcx"
	"github.com/sbrw-evc/spa/internal/policy"
	"github.com/sbrw-evc/spa/internal/store"
)

func actor(r *http.Request) string {
	if p := current(r); p != nil {
		return p.User.Username
	}
	return ""
}

// ---- people

type userView struct {
	store.User
	Groups    []string            `json:"groups"`
	Passkeys  int                 `json:"passkeys"`
	Locked    bool                `json:"locked"`
	AppRoles  map[string][]string `json:"app_roles"`
	ExpiresAt string              `json:"password_expires_at,omitempty"`
}

func (a *App) userView(ctx context.Context, u store.User, p policy.PasswordPolicy) (userView, error) {
	v := userView{User: u, Locked: u.LockedUntil != nil && u.LockedUntil.After(a.now())}
	var err error
	if v.Groups, err = a.st.UserGroupIDs(ctx, u.ID); err != nil {
		return v, err
	}
	keys, err := a.st.Passkeys(ctx, u.ID)
	if err != nil {
		return v, err
	}
	v.Passkeys = len(keys)
	if v.AppRoles, err = a.st.UserAppRoles(ctx, u.ID); err != nil {
		return v, err
	}
	if u.Source == "local" {
		if age := p.Age(deref(u.PasswordChangedAt, u.CreatedAt), a.now()); !age.ExpiresAt.IsZero() {
			v.ExpiresAt = age.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")
		}
	}
	return v, nil
}

func (a *App) listUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	users, err := a.st.Users(ctx)
	if err != nil {
		writeError(w, err)
		return
	}
	p := a.policy(ctx)
	out := make([]userView, 0, len(users))
	for _, u := range users {
		v, err := a.userView(ctx, u, p)
		if err != nil {
			writeError(w, err)
			return
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

type userIn struct {
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	SPARole  string   `json:"spa_role"`
	Disabled bool     `json:"disabled"`
	Password string   `json:"password"`
	Groups   []string `json:"groups"`
}

func (in *userIn) check() error {
	in.Username, in.Name, in.Email = strings.TrimSpace(in.Username), strings.TrimSpace(in.Name), strings.TrimSpace(in.Email)
	if in.Username == "" || len(in.Username) > 128 || strings.ContainsAny(in.Username, " \t/\\") {
		return fail(http.StatusBadRequest, "invalid_username", "Enter a user name without spaces")
	}
	if in.Email != "" && (!strings.Contains(in.Email, "@") || len(in.Email) > 256) {
		return fail(http.StatusBadRequest, "invalid_email", "Enter a valid e-mail address")
	}
	switch in.SPARole {
	case "":
		in.SPARole = "user"
	case "admin", "auditor", "user":
	default:
		return fail(http.StatusBadRequest, "invalid_role", "The SPA role is admin, auditor or user")
	}
	return nil
}

func (a *App) createUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in userIn
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	if err := in.check(); err != nil {
		writeError(w, err)
		return
	}
	u := store.User{Username: in.Username, Name: in.Name, Email: in.Email, Source: "local", SPARole: in.SPARole, Disabled: in.Disabled, MustChange: true}
	p := a.policy(ctx)
	if v := p.Check(in.Password, in.Username); len(v) > 0 {
		writeError(w, &apiError{Status: http.StatusBadRequest, Code: "password_policy", Message: "The password does not meet the password policy", Violations: v})
		return
	}
	hash, err := policy.HashPassword(in.Password)
	if err != nil {
		writeError(w, err)
		return
	}
	u.PasswordHash = hash
	now := a.now()
	u.PasswordChangedAt = &now
	created, err := a.st.CreateUser(ctx, u)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, fail(http.StatusConflict, "username_taken", "This user name is taken"))
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	if err := a.setUserGroups(ctx, created.ID, in.Groups); err != nil {
		writeError(w, err)
		return
	}
	a.st.Audit(ctx, actor(r), "user.created", created.Username, a.clientIP(r), map[string]any{"spa_role": created.SPARole})
	v, err := a.userView(ctx, created, p)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

// setUserGroups puts a person into exactly these local groups (directory groups follow the directory).
func (a *App) setUserGroups(ctx context.Context, userID string, groups []string) error {
	if groups == nil {
		return nil
	}
	all, err := a.st.Groups(ctx)
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, g := range groups {
		want[g] = true
	}
	for _, g := range all {
		if g.Source != "local" {
			continue
		}
		members, err := a.st.GroupMembers(ctx, g.ID)
		if err != nil {
			return err
		}
		has := false
		next := []string{}
		for _, m := range members {
			if m == userID {
				has = true
				continue
			}
			next = append(next, m)
		}
		if want[g.ID] == has {
			continue
		}
		if want[g.ID] {
			next = append(next, userID)
		}
		if err := a.st.SetGroupMembers(ctx, g.ID, next); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) updateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, err := a.st.UserByID(ctx, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	var in userIn
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	if err := in.check(); err != nil {
		writeError(w, err)
		return
	}
	me := current(r)
	if u.ID == me.User.ID && (in.Disabled || in.SPARole != u.SPARole) {
		writeError(w, fail(http.StatusBadRequest, "self", "You cannot disable yourself or change your own SPA role"))
		return
	}
	if u.SPARole == "admin" && (in.SPARole != "admin" || in.Disabled) {
		if n, _ := a.st.CountAdmins(ctx); n <= 1 {
			writeError(w, fail(http.StatusBadRequest, "last_admin", "SPA needs at least one enabled administrator"))
			return
		}
	}
	changes := map[string]any{}
	if u.Disabled != in.Disabled {
		changes["disabled"] = in.Disabled
	}
	if u.SPARole != in.SPARole {
		changes["spa_role"] = in.SPARole
	}
	if u.Source == "local" {
		u.Username = in.Username
	}
	u.Name, u.Email, u.SPARole, u.Disabled = in.Name, in.Email, in.SPARole, in.Disabled
	if err := a.st.UpdateProfile(ctx, u); errors.Is(err, store.ErrConflict) {
		writeError(w, fail(http.StatusConflict, "username_taken", "This user name is taken"))
		return
	} else if err != nil {
		writeError(w, err)
		return
	}
	if err := a.setUserGroups(ctx, u.ID, in.Groups); err != nil {
		writeError(w, err)
		return
	}
	if in.Disabled {
		a.st.DeleteSessions(ctx, u.ID, "", "") //nolint:errcheck
	}
	a.st.Audit(ctx, actor(r), "user.updated", u.Username, a.clientIP(r), changes)
	u, _ = a.st.UserByID(ctx, u.ID)
	v, err := a.userView(ctx, u, a.policy(ctx))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (a *App) deleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, err := a.st.UserByID(ctx, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	if u.ID == current(r).User.ID {
		writeError(w, fail(http.StatusBadRequest, "self", "You cannot delete yourself"))
		return
	}
	if u.SPARole == "admin" {
		if n, _ := a.st.CountAdmins(ctx); n <= 1 {
			writeError(w, fail(http.StatusBadRequest, "last_admin", "SPA needs at least one enabled administrator"))
			return
		}
	}
	if err := a.st.DeleteUser(ctx, u.ID); err != nil {
		writeError(w, err)
		return
	}
	a.st.Audit(ctx, actor(r), "user.deleted", u.Username, a.clientIP(r), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) resetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, err := a.st.UserByID(ctx, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	if u.Source != "local" {
		writeError(w, fail(http.StatusConflict, "not_local", "This account signs in with "+sourceTitle(u.Source)))
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	if err := a.setPassword(ctx, u, in.Password, true); err != nil {
		writeError(w, err)
		return
	}
	a.st.DeleteSessions(ctx, u.ID, "", "") //nolint:errcheck
	a.st.Audit(ctx, actor(r), "user.password_reset", u.Username, a.clientIP(r), nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) unlockUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, err := a.st.UserByID(ctx, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	if err := a.st.Unlock(ctx, u.ID); err != nil {
		writeError(w, err)
		return
	}
	a.st.Audit(ctx, actor(r), "user.unlocked", u.Username, a.clientIP(r), nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) userPasskeys(w http.ResponseWriter, r *http.Request) {
	keys, err := a.st.Passkeys(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, viewPasskeys(keys))
}

func (a *App) removeUserPasskeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, err := a.st.UserByID(ctx, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	n, err := a.st.DeletePasskeys(ctx, u.ID, r.URL.Query().Get("passkey"))
	if err != nil {
		writeError(w, err)
		return
	}
	a.st.Audit(ctx, actor(r), "user.passkeys_removed", u.Username, a.clientIP(r), map[string]any{"count": n})
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) endUserSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, err := a.st.UserByID(ctx, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	a.st.DeleteSessions(ctx, u.ID, "", "") //nolint:errcheck
	a.st.Audit(ctx, actor(r), "user.signed_out", u.Username, a.clientIP(r), nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---- groups

func (a *App) listGroups(w http.ResponseWriter, r *http.Request) {
	g, err := a.st.Groups(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

type groupIn struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Members     []string `json:"members"`
	// Source and ExternalID create a directory group ahead of its members' first sign-in, so it can get roles:
	// ldap + the group's DN, or entra + the group's object ID.
	Source     string `json:"source"`
	ExternalID string `json:"external_id"`
}

type groupView struct {
	store.Group
	MemberIDs []string `json:"member_ids"`
}

func (a *App) groupView(ctx context.Context, id string) (groupView, error) {
	g, err := a.st.GroupByID(ctx, id)
	if err != nil {
		return groupView{}, err
	}
	m, err := a.st.GroupMembers(ctx, id)
	return groupView{Group: g, MemberIDs: m}, err
}

func (a *App) getGroup(w http.ResponseWriter, r *http.Request) {
	v, err := a.groupView(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (a *App) saveGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in groupIn
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 128 {
		writeError(w, fail(http.StatusBadRequest, "invalid_name", "Enter the name of the group"))
		return
	}
	id := r.PathValue("id")
	var g store.Group
	var err error
	if id == "" {
		ng := store.Group{Name: in.Name, Description: in.Description}
		switch in.Source {
		case "", "local":
		case "ldap":
			if !directory.ValidDN(in.ExternalID) {
				writeError(w, fail(http.StatusBadRequest, "invalid_dn", "Enter the distinguished name of the group, e.g. CN=NOC,OU=Groups,DC=example,DC=com"))
				return
			}
			ng.Source, ng.ExternalID = "ldap", directory.NormalizeDN(in.ExternalID)
		case "entra":
			if !entra.ValidGroupID(in.ExternalID) {
				writeError(w, fail(http.StatusBadRequest, "invalid_group_id", "Enter the object ID of the Entra group"))
				return
			}
			ng.Source, ng.ExternalID = "entra", strings.ToLower(strings.TrimSpace(in.ExternalID))
		default:
			writeError(w, fail(http.StatusBadRequest, "invalid_source", "A group is local, ldap or entra"))
			return
		}
		g, err = a.st.CreateGroup(ctx, ng)
	} else {
		if g, err = a.st.GroupByID(ctx, id); err == nil {
			g.Name, g.Description = in.Name, in.Description
			err = a.st.UpdateGroup(ctx, g)
		}
	}
	if errors.Is(err, store.ErrConflict) {
		writeError(w, fail(http.StatusConflict, "name_taken", "A group with this name exists"))
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	if in.Members != nil && g.Source == "local" {
		if err := a.st.SetGroupMembers(ctx, g.ID, in.Members); err != nil {
			writeError(w, err)
			return
		}
	}
	a.st.Audit(ctx, actor(r), "group.saved", g.Name, a.clientIP(r), map[string]any{"members": len(in.Members)})
	v, err := a.groupView(ctx, g.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	status := http.StatusOK
	if id == "" {
		status = http.StatusCreated
	}
	writeJSON(w, status, v)
}

func (a *App) deleteGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	g, err := a.st.GroupByID(ctx, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	if err := a.st.DeleteGroup(ctx, g.ID); err != nil {
		writeError(w, err)
		return
	}
	a.st.Audit(ctx, actor(r), "group.deleted", g.Name, a.clientIP(r), nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---- applications

func (a *App) listApps(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	apps, err := a.st.Applications(ctx)
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]ApplicationView, 0, len(apps))
	for _, app := range apps {
		v, err := a.appView(ctx, app)
		if err != nil {
			writeError(w, err)
			return
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"applications": out, "types": appTypeNames, "presets": appTypes})
}

type appRequest struct {
	AppInput
	Assignments []store.Assignment `json:"assignments"`
}

func (a *App) createApp(w http.ResponseWriter, r *http.Request) {
	var in appRequest
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	c, err := a.connectApp(r.Context(), r, actor(r), in.AppInput, in.Assignments)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (a *App) updateApp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	old, err := a.st.ApplicationByID(ctx, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	var in appRequest
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	app, err := in.normalize(&old)
	if err != nil {
		writeError(w, err)
		return
	}
	if old.RolesPublished == nil && len(in.Roles) > 0 {
		if app.Roles, err = checkRoles(in.Roles); err != nil {
			writeError(w, err)
			return
		}
	}
	if err := a.st.SaveApplication(ctx, app); err != nil {
		writeError(w, err)
		return
	}
	if in.Assignments != nil {
		if err := a.saveAssignments(ctx, app, in.Assignments); err != nil {
			writeError(w, err)
			return
		}
	}
	a.st.Audit(ctx, actor(r), "application.updated", app.Name, a.clientIP(r), map[string]any{"rules": len(in.Assignments)})
	app, _ = a.st.ApplicationByID(ctx, app.ID)
	v, err := a.appView(ctx, app)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (a *App) reissueKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app, err := a.st.ApplicationByID(ctx, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	secret, token := a.issueCredentials(ctx, &app)
	if err := a.st.SaveApplication(ctx, app); err != nil {
		writeError(w, err)
		return
	}
	a.st.Audit(ctx, actor(r), "application.key_issued", app.Name, a.clientIP(r), nil)
	v, err := a.appView(ctx, app)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, Connection{Application: v, Key: ConnectionKey(a.Issuer(r), app.ClientID, secret, token)})
}

func (a *App) deleteApp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app, err := a.st.ApplicationByID(ctx, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	if err := a.st.DeleteApplication(ctx, app.ID); err != nil {
		writeError(w, err)
		return
	}
	a.st.Audit(ctx, actor(r), "application.removed", app.Name, a.clientIP(r), nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---- settings

type policySummary struct {
	Policy   policy.PasswordPolicy `json:"policy"`
	Local    int                   `json:"local_users"`
	Expired  int                   `json:"expired_users"`
	Expiring int                   `json:"expiring_users"`
	Locked   int                   `json:"locked_users"`
}

func (a *App) policySummary(ctx context.Context) (policySummary, error) {
	p := a.policy(ctx)
	users, err := a.st.Users(ctx)
	if err != nil {
		return policySummary{}, err
	}
	s := policySummary{Policy: p}
	for _, u := range users {
		if u.Source != "local" || u.Disabled {
			continue
		}
		s.Local++
		age := p.Age(deref(u.PasswordChangedAt, u.CreatedAt), a.now())
		if age.Expired {
			s.Expired++
		} else if age.Warning {
			s.Expiring++
		}
		if u.LockedUntil != nil && u.LockedUntil.After(a.now()) {
			s.Locked++
		}
	}
	return s, nil
}

func (a *App) getPolicy(w http.ResponseWriter, r *http.Request) {
	s, err := a.policySummary(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (a *App) putPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in policy.PasswordPolicy
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	p, err := in.Normalize()
	if err != nil {
		writeError(w, fail(http.StatusBadRequest, "invalid_policy", err.Error()))
		return
	}
	if err := a.st.PutSetting(ctx, keyPolicy, p); err != nil {
		writeError(w, err)
		return
	}
	a.st.Audit(ctx, actor(r), "settings.password_policy", "", a.clientIP(r), map[string]any{"min_length": p.MinLength,
		"max_age_days": p.MaxAgeDays, "history": p.HistoryCount, "lockout": p.LockoutAttempts})
	a.getPolicy(w, r)
}

func (a *App) getGeneral(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	writeJSON(w, http.StatusOK, map[string]any{"general": a.general(ctx), "passkeys": a.passkeys(ctx), "issuer": a.Issuer(r),
		"secrets": a.sec.Kind(), "public_url_set": a.cfg.PublicURL != ""})
}

func (a *App) putGeneral(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in struct {
		General  General         `json:"general"`
		Passkeys PasskeySettings `json:"passkeys"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	in.General.Organization = strings.TrimSpace(in.General.Organization)
	in.Passkeys.RPID = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.Passkeys.RPID), "."))
	if in.Passkeys.RPID != "" {
		host := strings.Split(strings.TrimPrefix(strings.TrimPrefix(a.Issuer(r), "https://"), "http://"), ":")[0]
		if strings.ContainsAny(in.Passkeys.RPID, " /:@") || !hostWithin(host, in.Passkeys.RPID) {
			writeError(w, fail(http.StatusBadRequest, "passkey_domain", "The passkey domain must be the domain of SPA or a parent of it"))
			return
		}
	}
	if err := a.st.PutSetting(ctx, keyGeneral, in.General); err != nil {
		writeError(w, err)
		return
	}
	if err := a.st.PutSetting(ctx, keyPasskeys, in.Passkeys); err != nil {
		writeError(w, err)
		return
	}
	a.st.Audit(ctx, actor(r), "settings.general", "", a.clientIP(r), map[string]any{"allow_local": in.General.AllowLocal, "passkeys": in.Passkeys.Enabled})
	a.getGeneral(w, r)
}

func hostWithin(host, rp string) bool {
	return host == rp || strings.HasSuffix(host, "."+rp)
}

// ---- LDAP / Active Directory

func (a *App) getLDAP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	writeJSON(w, http.StatusOK, map[string]any{"config": a.ldap(ctx).Public(), "bind_password_set": secretsValue(ctx, a, secretLDAP, "bind_password") != ""})
}

type ldapIn struct {
	Config       directory.Config `json:"config"`
	BindPassword string           `json:"bind_password"`
	Username     string           `json:"test_username"`
	Password     string           `json:"test_password"`
}

func (a *App) putLDAP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in ldapIn
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	c, err := in.Config.Normalize()
	if err != nil {
		writeError(w, fail(http.StatusBadRequest, "invalid_directory", err.Error()))
		return
	}
	if in.BindPassword != "" {
		if err := a.sec.Put(ctx, secretLDAP, map[string]string{"bind_password": in.BindPassword}); err != nil {
			writeError(w, err)
			return
		}
	}
	if err := a.st.PutSetting(ctx, keyLDAP, c); err != nil {
		writeError(w, err)
		return
	}
	a.st.Audit(ctx, actor(r), "settings.ldap", c.URL, a.clientIP(r), map[string]any{"enabled": c.Enabled})
	a.getLDAP(w, r)
}

func (a *App) testLDAP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in ldapIn
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	pw := in.BindPassword
	if pw == "" {
		pw = secretsValue(ctx, a, secretLDAP, "bind_password")
	}
	probe, err := directory.Test(in.Config, pw, in.Username, in.Password)
	writeJSON(w, http.StatusOK, directory.Report(probe, err))
}

// ---- Microsoft Entra ID

func (a *App) getEntra(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	writeJSON(w, http.StatusOK, map[string]any{"config": a.entra(ctx, r).Public(), "client_secret_set": secretsValue(ctx, a, secretEntra, "client_secret") != "",
		"clouds": entra.Clouds})
}

type entraIn struct {
	Config       entra.Config `json:"config"`
	ClientSecret string       `json:"client_secret"`
}

func (a *App) putEntra(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in entraIn
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	in.Config.RedirectURL = a.Issuer(r) + "/api/v1/auth/sso/entra/callback"
	c, err := in.Config.Normalize()
	if err != nil {
		writeError(w, fail(http.StatusBadRequest, "invalid_entra", err.Error()))
		return
	}
	if in.ClientSecret != "" {
		if err := a.sec.Put(ctx, secretEntra, map[string]string{"client_secret": in.ClientSecret}); err != nil {
			writeError(w, err)
			return
		}
	}
	if err := a.st.PutSetting(ctx, keyEntra, c); err != nil {
		writeError(w, err)
		return
	}
	a.st.Audit(ctx, actor(r), "settings.entra", c.TenantID, a.clientIP(r), map[string]any{"enabled": c.Enabled})
	a.getEntra(w, r)
}

func (a *App) testEntra(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in entraIn
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	in.Config.RedirectURL = a.Issuer(r) + "/api/v1/auth/sso/entra/callback"
	secret := in.ClientSecret
	if secret == "" {
		secret = secretsValue(ctx, a, secretEntra, "client_secret")
	}
	probe, err := entra.Test(ctx, in.Config, secret)
	writeJSON(w, http.StatusOK, entra.Report(probe, err))
}

// ---- Google, Apple, OpenID Connect

type providerEntry struct {
	Kind            string   `json:"kind"`
	Config          Provider `json:"config"`
	ClientSecretSet bool     `json:"client_secret_set"`
	PrivateKeySet   bool     `json:"private_key_set"`
	RedirectURI     string   `json:"redirect_uri"`
}

func (a *App) getProviders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	all := a.providers(ctx)
	out := []providerEntry{}
	for _, k := range providerKinds {
		out = append(out, providerEntry{Kind: k, Config: *all.get(k),
			ClientSecretSet: secretsValue(ctx, a, secretProvider(k), "client_secret") != "",
			PrivateKeySet:   secretsValue(ctx, a, secretProvider(k), "private_key") != "",
			RedirectURI:     a.Issuer(r) + "/api/v1/auth/sso/" + k + "/callback"})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) putProvider(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	kind := r.PathValue("kind")
	all := a.providers(ctx)
	target := all.get(kind)
	if target == nil {
		writeError(w, errNotFound)
		return
	}
	var in struct {
		Config       Provider `json:"config"`
		ClientSecret string   `json:"client_secret"`
		PrivateKey   string   `json:"private_key"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	p := in.Config
	p.ClientID = strings.TrimSpace(p.ClientID)
	domains := []string{}
	for _, d := range p.AllowedDomains {
		d = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "@"))
		if d == "" {
			continue
		}
		if !strings.Contains(d, ".") || strings.ContainsAny(d, " /:@") {
			writeError(w, fail(http.StatusBadRequest, "provider_domain", d+" is not a domain name"))
			return
		}
		domains = append(domains, d)
	}
	p.AllowedDomains = domains
	switch kind {
	case "google":
		p.Issuer = GoogleIssuer
	case "apple":
		p.Issuer = AppleIssuer
	default:
		iss := strings.TrimRight(strings.TrimSpace(p.Issuer), "/")
		if !strings.HasPrefix(iss, "https://") {
			writeError(w, fail(http.StatusBadRequest, "provider_issuer", "The issuer must be an https:// address"))
			return
		}
		p.Issuer = iss
	}
	if p.Enabled {
		if p.ClientID == "" {
			writeError(w, fail(http.StatusBadRequest, "provider_client", "Enter the client ID"))
			return
		}
		if kind != "oidc" && len(p.AllowedDomains) == 0 && !p.ExistingOnly {
			writeError(w, fail(http.StatusBadRequest, "provider_domains", "Enter the allowed e-mail domains or allow only existing accounts"))
			return
		}
		if _, err := oidcx.Discover(ctx, p.Issuer); err != nil {
			writeError(w, fail(http.StatusBadRequest, "provider_unavailable", err.Error()))
			return
		}
		if kind == "apple" {
			key := in.PrivateKey
			if key == "" {
				key = secretsValue(ctx, a, secretProvider(kind), "private_key")
			}
			if p.TeamID == "" || p.KeyID == "" {
				writeError(w, fail(http.StatusBadRequest, "provider_apple", "Enter the Team ID and the Key ID"))
				return
			}
			if _, err := oidcx.AppleSecret(p.TeamID, p.KeyID, p.ClientID, key, a.now()); err != nil {
				writeError(w, fail(http.StatusBadRequest, "provider_key", "Upload the private key (.p8): "+err.Error()))
				return
			}
		} else if in.ClientSecret == "" && secretsValue(ctx, a, secretProvider(kind), "client_secret") == "" {
			writeError(w, fail(http.StatusBadRequest, "provider_secret", "Enter the client secret"))
			return
		}
	}
	if in.ClientSecret != "" || in.PrivateKey != "" {
		m, _ := a.sec.Get(ctx, secretProvider(kind))
		if m == nil {
			m = map[string]string{}
		}
		if in.ClientSecret != "" {
			m["client_secret"] = in.ClientSecret
		}
		if in.PrivateKey != "" {
			m["private_key"] = in.PrivateKey
		}
		if err := a.sec.Put(ctx, secretProvider(kind), m); err != nil {
			writeError(w, err)
			return
		}
	}
	*target = p
	if err := a.st.PutSetting(ctx, keyProviders, all); err != nil {
		writeError(w, err)
		return
	}
	a.st.Audit(ctx, actor(r), "settings.provider", kind, a.clientIP(r), map[string]any{"enabled": p.Enabled})
	a.getProviders(w, r)
}

// ---- audit

func (a *App) auditLog(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	list, err := a.st.AuditLog(r.Context(), r.URL.Query().Get("q"), before, 100)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}
