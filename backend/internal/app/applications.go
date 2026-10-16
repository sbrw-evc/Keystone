package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/sbrw-evc/keystone/internal/store"
)

func hmacHex(key []byte, v string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))
}

func writeJSONCached(w http.ResponseWriter, v any) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

// App types and their fixed role catalogues (an application replaces its catalogue when it publishes one).
// The type IDs of the Umbrella family follow the product names; the IDs used before the rename are still accepted
// (store.CanonicalAppType maps them, and migration 0004 rewrote the stored ones).
var appTypes = map[string][]store.Role{
	"beacon":          {{ID: "admin", Name: "Administrator", Description: "Everything, including settings"}, {ID: "user", Name: "User", Description: "Incidents, on-call and the catalogue"}},
	"current":         {{ID: "admin", Name: "Administrator", Description: "Everything, including settings"}},
	"ledger":          {{ID: "admin", Name: "Administrator"}, {ID: "editor", Name: "Editor"}, {ID: "viewer", Name: "Viewer"}},
	"network-control": {{ID: "admin", Name: "Administrator"}, {ID: "operator", Name: "Operator"}, {ID: "viewer", Name: "Viewer"}},
	"oidc":            {{ID: "user", Name: "User"}},
}

var appTypeNames = map[string]string{"beacon": "Beacon", "current": "Current", "ledger": "Ledger",
	"network-control": "Network Control", "oidc": "OpenID Connect application"}

var roleIDRe = regexp.MustCompile(`^[a-z0-9_.:-]{1,64}$`)

// AppInput is what an administrator enters for an application.
type AppInput struct {
	Type         string       `json:"type"`
	Name         string       `json:"name"`
	BaseURL      string       `json:"base_url"`
	RedirectURIs []string     `json:"redirect_uris"`
	LogoutURIs   []string     `json:"logout_uris"`
	Roles        []store.Role `json:"roles"`
	DefaultRole  string       `json:"default_role"`
}

func normalizeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Fragment != "" {
		return "", fail(http.StatusBadRequest, "invalid_url", "Enter an address such as https://app.example.com")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func (in AppInput) normalize(old *store.Application) (store.Application, error) {
	a := store.Application{}
	if old != nil {
		a = *old
	}
	in.Type = store.CanonicalAppType(in.Type)
	if _, ok := appTypes[in.Type]; !ok {
		return a, fail(http.StatusBadRequest, "invalid_type", "Choose the type of the application")
	}
	a.Type = in.Type
	a.Name = strings.TrimSpace(in.Name)
	if a.Name == "" {
		a.Name = appTypeNames[in.Type]
	}
	base, err := normalizeURL(in.BaseURL)
	if err != nil {
		return a, err
	}
	a.BaseURL = base
	if in.Type == "oidc" {
		a.RedirectURIs, a.LogoutURIs = nil, nil
		for _, r := range in.RedirectURIs {
			if strings.TrimSpace(r) == "" {
				continue
			}
			u, err := url.Parse(strings.TrimSpace(r))
			if err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))) || u.Fragment != "" {
				return a, fail(http.StatusBadRequest, "invalid_redirect", "Redirect addresses must be https:// addresses")
			}
			a.RedirectURIs = append(a.RedirectURIs, u.String())
		}
		if len(a.RedirectURIs) == 0 {
			return a, fail(http.StatusBadRequest, "invalid_redirect", "Enter at least one redirect address")
		}
		for _, r := range in.LogoutURIs {
			if strings.TrimSpace(r) != "" {
				a.LogoutURIs = append(a.LogoutURIs, strings.TrimSpace(r))
			}
		}
	} else {
		a.RedirectURIs = []string{base + "/api/auth/spa/callback"}
		a.LogoutURIs = []string{base + "/", base}
	}
	if a.Roles == nil || len(a.Roles) == 0 || a.RolesPublished == nil {
		if len(in.Roles) > 0 {
			roles, err := checkRoles(in.Roles)
			if err != nil {
				return a, err
			}
			a.Roles = roles
		} else if len(a.Roles) == 0 {
			a.Roles = appTypes[in.Type]
		}
	}
	a.DefaultRole = in.DefaultRole
	return a, nil
}

func checkRoles(in []store.Role) ([]store.Role, error) {
	seen := map[string]bool{}
	out := []store.Role{}
	for _, r := range in {
		r.ID = strings.TrimSpace(r.ID)
		if !roleIDRe.MatchString(r.ID) {
			return nil, fail(http.StatusBadRequest, "invalid_role", "A role ID is 1–64 of a-z 0-9 _ . : -")
		}
		if seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		r.Name = strings.TrimSpace(r.Name)
		if r.Name == "" {
			r.Name = r.ID
		}
		out = append(out, r)
	}
	if len(out) == 0 || len(out) > 200 {
		return nil, fail(http.StatusBadRequest, "invalid_role", "An application has from 1 to 200 roles")
	}
	return out, nil
}

// ApplicationView is an application as the administrator sees it.
type ApplicationView struct {
	store.Application
	Users       int                `json:"users"`
	Assignments []store.Assignment `json:"assignments"`
	Callback    string             `json:"callback"`
}

func (a *App) appView(ctx context.Context, app store.Application) (ApplicationView, error) {
	asg, err := a.st.Assignments(ctx, app.ID)
	if err != nil {
		return ApplicationView{}, err
	}
	users, err := a.st.AppUserRoles(ctx, app.ID)
	if err != nil {
		return ApplicationView{}, err
	}
	n := 0
	for _, roles := range users {
		if len(knownRoles(app, roles)) > 0 {
			n++
		}
	}
	cb := ""
	if len(app.RedirectURIs) > 0 {
		cb = app.RedirectURIs[0]
	}
	return ApplicationView{Application: app, Users: n, Assignments: asg, Callback: cb}, nil
}

// Connection is shown once, when an application is connected or gets a new key.
type Connection struct {
	Application ApplicationView `json:"application"`
	Key         string          `json:"key"`
}

// ConnectionKey is spa1. + base64url of the JSON the application reads (docs/protocol.md).
func ConnectionKey(issuer, clientID, secret, token string) string {
	raw, _ := json.Marshal(map[string]string{"issuer": issuer, "client_id": clientID, "client_secret": secret, "token": token})
	return "spa1." + base64.RawURLEncoding.EncodeToString(raw)
}

func (a *App) issueCredentials(ctx context.Context, app *store.Application) (secret, token string) {
	secret, token = randomToken(32), "spat_"+randomToken(32)
	app.SecretHash, app.TokenHash = a.secretHash(ctx, secret), a.secretHash(ctx, token)
	return
}

func (a *App) connectApp(ctx context.Context, r *http.Request, actor string, in AppInput, asg []store.Assignment) (Connection, error) {
	app, err := in.normalize(nil)
	if err != nil {
		return Connection{}, err
	}
	app.ID = store.NewID("app")
	app.ClientID = "spa_" + randomToken(12)
	secret, token := a.issueCredentials(ctx, &app)
	if err := a.st.SaveApplication(ctx, app); err != nil {
		return Connection{}, err
	}
	if err := a.saveAssignments(ctx, app, asg); err != nil {
		return Connection{}, err
	}
	a.st.Audit(ctx, actor, "application.connected", app.Name, a.clientIP(r), map[string]any{"type": app.Type, "address": app.BaseURL})
	saved, err := a.st.ApplicationByID(ctx, app.ID)
	if err != nil {
		return Connection{}, err
	}
	view, err := a.appView(ctx, saved)
	return Connection{Application: view, Key: ConnectionKey(a.Issuer(r), app.ClientID, secret, token)}, err
}

func (a *App) saveAssignments(ctx context.Context, app store.Application, list []store.Assignment) error {
	clean := []store.Assignment{}
	for _, x := range list {
		if x.SubjectType != "user" && x.SubjectType != "group" {
			return fail(http.StatusBadRequest, "invalid_assignment", "A rule gives a role to a person or a group")
		}
		if !roleIDRe.MatchString(x.Role) {
			return fail(http.StatusBadRequest, "invalid_role", "Choose a role")
		}
		if x.SubjectType == "user" {
			if _, err := a.st.UserByID(ctx, x.SubjectID); err != nil {
				return fail(http.StatusBadRequest, "invalid_assignment", "Unknown person")
			}
		} else if _, err := a.st.GroupByID(ctx, x.SubjectID); err != nil {
			return fail(http.StatusBadRequest, "invalid_assignment", "Unknown group")
		}
		clean = append(clean, x)
	}
	return a.st.SetAssignments(ctx, app.ID, clean)
}

// ---- federation API (docs/protocol.md §3)

// federated authenticates an application by its federation token.
func (a *App) federated(next func(http.ResponseWriter, *http.Request, store.Application)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || strings.TrimSpace(raw) == "" {
			writeError(w, fail(http.StatusUnauthorized, "unauthorized", "The federation token is missing"))
			return
		}
		app, err := a.st.ApplicationByToken(r.Context(), a.secretHash(r.Context(), strings.TrimSpace(raw)))
		if err != nil {
			writeError(w, fail(http.StatusUnauthorized, "unauthorized", "The federation token is not valid: issue a new connection key"))
			return
		}
		next(w, r, app)
	}
}

func writeETag(w http.ResponseWriter, r *http.Request, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		writeError(w, err)
		return
	}
	sum := sha256.Sum256(raw)
	tag := `"` + base64.RawURLEncoding.EncodeToString(sum[:16]) + `"`
	w.Header().Set("ETag", tag)
	w.Header().Set("Cache-Control", "no-cache")
	if r.Header.Get("If-None-Match") == tag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(raw) //nolint:errcheck
}

func (a *App) fedConfig(w http.ResponseWriter, r *http.Request, app store.Application) {
	iss := a.Issuer(r)
	writeETag(w, r, map[string]any{
		"application":  map[string]string{"id": app.ID, "name": app.Name, "type": app.Type},
		"roles":        app.Roles,
		"methods":      a.methods(r.Context(), r),
		"sign_out_url": iss + "/oauth2/logout",
		"account_url":  iss + "/profile",
	})
}

// FederationUser is a person with a role in the application.
type FederationUser struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Disabled  bool      `json:"disabled"`
	Roles     []string  `json:"roles"`
	Groups    []string  `json:"groups"`
	Source    string    `json:"source"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (a *App) fedUsers(w http.ResponseWriter, r *http.Request, app store.Application) {
	ctx := r.Context()
	roles, err := a.st.AppUserRoles(ctx, app.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	out := []FederationUser{}
	for id, rs := range roles {
		known := knownRoles(app, rs)
		if len(known) == 0 {
			continue
		}
		u, err := a.st.UserByID(ctx, id)
		if err != nil {
			continue
		}
		groups, _ := a.st.UserGroups(ctx, id)
		out = append(out, FederationUser{ID: u.ID, Username: u.Username, Email: u.Email, Name: displayName(u), Disabled: u.Disabled,
			Roles: known, Groups: groups, Source: u.Source, UpdatedAt: u.UpdatedAt})
	}
	sortUsers(out)
	a.st.ApplicationSynced(ctx, app.ID)
	writeETag(w, r, map[string]any{"users": out})
}

func (a *App) fedRoles(w http.ResponseWriter, r *http.Request, app store.Application) {
	var in struct {
		Roles   []store.Role `json:"roles"`
		Default string       `json:"default"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	roles, err := checkRoles(in.Roles)
	if err != nil {
		writeError(w, err)
		return
	}
	now := a.now()
	changed := !sameRoles(app.Roles, roles)
	app.Roles, app.DefaultRole, app.RolesPublished = roles, in.Default, &now
	if err := a.st.SaveApplication(r.Context(), app); err != nil {
		writeError(w, err)
		return
	}
	if changed {
		a.st.Audit(r.Context(), app.Name, "application.roles_published", app.Name, a.clientIP(r), map[string]any{"roles": len(roles)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

func sameRoles(a, b []store.Role) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
