package app

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sbrw-evc/keystone/internal/policy"
	"github.com/sbrw-evc/keystone/internal/store"
)

// CSRFHeader must accompany every state-changing request of the web app (a cross-site form cannot set it).
const CSRFHeader = "X-Requested-With"

// Handler is Keystone's HTTP interface: the web app, its API, the OpenID Connect provider and the federation API.
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()

	// OpenID Connect provider (docs/protocol.md §2)
	mux.HandleFunc("GET /.well-known/openid-configuration", a.discovery)
	mux.HandleFunc("GET /oauth2/jwks", a.jwks)
	mux.HandleFunc("GET /oauth2/authorize", a.authorize)
	mux.HandleFunc("POST /oauth2/token", a.token)
	mux.HandleFunc("GET /oauth2/userinfo", a.userinfo)
	mux.HandleFunc("POST /oauth2/userinfo", a.userinfo)
	mux.HandleFunc("GET /oauth2/logout", a.logout)

	// federation API (§3)
	mux.HandleFunc("GET /api/spa/v1/config", a.federated(a.fedConfig))
	mux.HandleFunc("GET /api/spa/v1/users", a.federated(a.fedUsers))
	mux.HandleFunc("PUT /api/spa/v1/roles", a.federated(a.fedRoles))
	mux.HandleFunc("POST /api/spa/v1/users/import", a.federated(a.fedImport))

	// sign-in
	mux.HandleFunc("GET /api/v1/auth/methods", a.signInMethods)
	mux.HandleFunc("POST /api/v1/auth/password", a.signInPassword)
	mux.HandleFunc("POST /api/v1/auth/password/change", a.changePassword)
	mux.HandleFunc("POST /api/v1/auth/totp", a.signInTOTP)
	mux.HandleFunc("POST /api/v1/auth/totp/setup", a.signInTOTPSetup)
	mux.HandleFunc("POST /api/v1/auth/totp/setup/confirm", a.signInTOTPConfirm)
	mux.HandleFunc("POST /api/v1/auth/passkey/begin", a.passkeyBegin)
	mux.HandleFunc("POST /api/v1/auth/passkey/finish", a.passkeyFinish)
	mux.HandleFunc("GET /api/v1/auth/sso/{kind}/start", a.ssoStart)
	mux.HandleFunc("GET /api/v1/auth/sso/{kind}/callback", a.ssoCallback)
	mux.HandleFunc("POST /api/v1/auth/sso/{kind}/callback", a.ssoCallback)
	mux.HandleFunc("POST /api/v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		a.endSession(w, r)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /api/v1/auth/continue", a.authed(a.continueAuthorize))

	// the signed-in person
	mux.HandleFunc("GET /api/v1/me", a.authed(a.me))
	mux.HandleFunc("GET /api/v1/me/passkeys", a.authed(a.myPasskeys))
	mux.HandleFunc("POST /api/v1/me/passkeys/begin", a.authed(a.addPasskeyBegin))
	mux.HandleFunc("POST /api/v1/me/passkeys/finish", a.authed(a.addPasskeyFinish))
	mux.HandleFunc("PATCH /api/v1/me/passkeys/{id}", a.authed(a.renamePasskey))
	mux.HandleFunc("DELETE /api/v1/me/passkeys/{id}", a.authed(a.removePasskey))
	mux.HandleFunc("GET /api/v1/me/totp", a.authed(a.myTOTP))
	mux.HandleFunc("POST /api/v1/me/totp/setup", a.authed(a.myTOTPSetup))
	mux.HandleFunc("POST /api/v1/me/totp/setup/confirm", a.authed(a.myTOTPConfirm))
	mux.HandleFunc("POST /api/v1/me/totp/disable", a.authed(a.myTOTPDisable))
	mux.HandleFunc("POST /api/v1/me/totp/recovery-codes", a.authed(a.myRecoveryCodes))
	mux.HandleFunc("GET /api/v1/me/sessions", a.authed(a.mySessions))
	mux.HandleFunc("DELETE /api/v1/me/sessions/{id}", a.authed(a.revokeSession))

	// administration: auditors read, administrators change
	read, write := a.role("auditor"), a.role("admin")
	mux.HandleFunc("GET /api/v1/onboarding", read(a.onboarding))
	mux.HandleFunc("GET /api/v1/users", read(a.listUsers))
	mux.HandleFunc("POST /api/v1/users", write(a.createUser))
	mux.HandleFunc("PUT /api/v1/users/{id}", write(a.updateUser))
	mux.HandleFunc("DELETE /api/v1/users/{id}", write(a.deleteUser))
	mux.HandleFunc("POST /api/v1/users/{id}/password", write(a.resetPassword))
	mux.HandleFunc("POST /api/v1/users/{id}/unlock", write(a.unlockUser))
	mux.HandleFunc("GET /api/v1/users/{id}/passkeys", read(a.userPasskeys))
	mux.HandleFunc("DELETE /api/v1/users/{id}/passkeys", write(a.removeUserPasskeys))
	mux.HandleFunc("DELETE /api/v1/users/{id}/sessions", write(a.endUserSessions))
	mux.HandleFunc("DELETE /api/v1/users/{id}/totp", write(a.resetUserTOTP))
	mux.HandleFunc("GET /api/v1/groups", read(a.listGroups))
	mux.HandleFunc("POST /api/v1/groups", write(a.saveGroup))
	mux.HandleFunc("GET /api/v1/groups/{id}", read(a.getGroup))
	mux.HandleFunc("PUT /api/v1/groups/{id}", write(a.saveGroup))
	mux.HandleFunc("DELETE /api/v1/groups/{id}", write(a.deleteGroup))
	mux.HandleFunc("GET /api/v1/applications", read(a.listApps))
	mux.HandleFunc("POST /api/v1/applications", write(a.createApp))
	mux.HandleFunc("PUT /api/v1/applications/{id}", write(a.updateApp))
	mux.HandleFunc("POST /api/v1/applications/{id}/key", write(a.reissueKey))
	mux.HandleFunc("POST /api/v1/applications/{id}/user-import", write(a.allowUserImport))
	mux.HandleFunc("DELETE /api/v1/applications/{id}", write(a.deleteApp))
	mux.HandleFunc("GET /api/v1/settings/password-policy", read(a.getPolicy))
	mux.HandleFunc("PUT /api/v1/settings/password-policy", write(a.putPolicy))
	mux.HandleFunc("GET /api/v1/settings/general", read(a.getGeneral))
	mux.HandleFunc("PUT /api/v1/settings/general", write(a.putGeneral))
	mux.HandleFunc("GET /api/v1/settings/ldap", read(a.getLDAP))
	mux.HandleFunc("PUT /api/v1/settings/ldap", write(a.putLDAP))
	mux.HandleFunc("POST /api/v1/settings/ldap/test", write(a.testLDAP))
	mux.HandleFunc("GET /api/v1/settings/entra", read(a.getEntra))
	mux.HandleFunc("PUT /api/v1/settings/entra", write(a.putEntra))
	mux.HandleFunc("POST /api/v1/settings/entra/test", write(a.testEntra))
	mux.HandleFunc("GET /api/v1/settings/providers", read(a.getProviders))
	mux.HandleFunc("PUT /api/v1/settings/providers/{kind}", write(a.putProvider))
	mux.HandleFunc("GET /api/v1/audit", read(a.auditLog))
	mux.HandleFunc("POST /api/v1/settings/signing-key/rotate", write(func(w http.ResponseWriter, r *http.Request) {
		if err := a.keys.Rotate(r.Context()); err != nil {
			writeError(w, err)
			return
		}
		a.st.Audit(r.Context(), actor(r), "settings.signing_key_rotated", "", a.clientIP(r), nil)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := a.st.DB.Ping(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.Handle("/", a.web())

	return a.middleware(mux)
}

func (a *App) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self' https:")
		if a.secure(r) {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		// The web app's API: state-changing calls must carry the header a cross-site form cannot send.
		if strings.HasPrefix(r.URL.Path, "/api/v1/") && r.Method != http.MethodGet && r.Method != http.MethodHead &&
			!strings.HasPrefix(r.URL.Path, "/api/v1/auth/sso/") && r.Header.Get(CSRFHeader) != "spa" {
			writeError(w, fail(http.StatusForbidden, "csrf", "The request lacks the X-Requested-With header"))
			return
		}
		next.ServeHTTP(w, a.loadSession(r))
	})
}

func (a *App) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if current(r) == nil {
			writeError(w, errAuth)
			return
		}
		next(w, r)
	}
}

// role allows people whose Keystone role is at least min (user < auditor < admin).
func (a *App) role(min string) func(http.HandlerFunc) http.HandlerFunc {
	rank := map[string]int{"user": 0, "auditor": 1, "admin": 2}
	return func(next http.HandlerFunc) http.HandlerFunc {
		return a.authed(func(w http.ResponseWriter, r *http.Request) {
			if rank[current(r).User.SPARole] < rank[min] {
				writeError(w, errForbidden)
				return
			}
			next(w, r)
		})
	}
}

// continueAuthorize finishes a pending application sign-in for someone who already has a Keystone session.
func (a *App) continueAuthorize(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Request string `json:"request"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	var req authzRequest
	if err := a.state.Open(r.Context(), "authz", in.Request, &req); err != nil {
		writeError(w, fail(http.StatusBadRequest, "request_expired", "The sign-in request of the application has expired. Open the application again"))
		return
	}
	p := current(r)
	next, err := a.finishAuthorize(r.Context(), a.Issuer(r), p.User, p.Session, req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"next": next})
}

// web serves the built web app: files as they are, every other path gets index.html (client-side routes).
func (a *App) web() http.Handler {
	dir := a.cfg.WebDir
	files := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dir == "" {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeError(w, errNotFound)
			return
		}
		p := filepath.Join(dir, filepath.Clean("/"+r.URL.Path))
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			if strings.HasPrefix(r.URL.Path, "/assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			files.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(w, r, filepath.Join(dir, "index.html"))
	})
}

// ---- first steps

type step struct {
	ID       string `json:"id"`
	Done     bool   `json:"done"`
	Optional bool   `json:"optional"`
	Path     string `json:"path"`
}

func (a *App) onboarding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := a.policy(ctx)
	apps, _ := a.st.Applications(ctx)
	asg, _ := a.st.Assignments(ctx, "")
	admins, _ := a.st.CountAdmins(ctx)
	keys, _ := a.st.Passkeys(ctx, current(r).User.ID)
	pk := a.passkeys(ctx)
	prov := a.providers(ctx)
	steps := []step{
		{ID: "public_url", Done: a.general(ctx).PublicURL != "", Path: "/settings/general"},
		{ID: "policy", Done: p.BlockCommon && p.HistoryCount > 0 && p.LockoutAttempts > 0, Path: "/settings/password-policy"},
		{ID: "passkey", Done: pk.Enabled && len(keys) > 0, Path: "/profile"},
		{ID: "directory", Optional: true, Done: a.ldap(ctx).Enabled || a.entra(ctx, r).Enabled || prov.Google.Enabled || prov.Apple.Enabled || prov.OIDC.Enabled, Path: "/settings/directories"},
		{ID: "application", Done: len(apps) > 0, Path: "/applications?connect=1"},
		{ID: "roles", Done: len(asg) > 0, Path: "/applications"},
		{ID: "second_admin", Optional: true, Done: admins > 1, Path: "/users"},
	}
	done := true
	for _, s := range steps {
		if !s.Optional && !s.Done {
			done = false
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"done": done, "steps": steps})
}

// ---- start-up

// Bootstrap creates the first administrator when Keystone has no people yet (the password must be changed at first sign-in).
func (a *App) Bootstrap(ctx context.Context, username, password string) error {
	n, err := a.st.CountUsers(ctx)
	if err != nil || n > 0 || username == "" {
		return err
	}
	if password == "" {
		slog.Warn("Keystone has no administrator: set SPA_ADMIN_USERNAME and SPA_ADMIN_PASSWORD for the first start")
		return nil
	}
	hash, err := policy.HashPassword(password)
	if err != nil {
		return err
	}
	now := a.now()
	u, err := a.newLocalUser(ctx, store.User{Username: username, Name: "Administrator", Source: "local", SPARole: "admin",
		PasswordChangedAt: &now, MustChange: true}, hash)
	if err != nil {
		return err
	}
	a.st.Audit(ctx, "spa", "user.created", u.Username, "", map[string]any{"bootstrap": true})
	slog.Info("created the first administrator", "username", username)
	return nil
}

// Housekeeping purges expired sessions and codes until ctx ends.
func (a *App) Housekeeping(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		a.st.PurgeExpired(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
