// Package app is Keystone — sign-in and access for the Umbrella family: sign-in (passwords under the
// password policy, passkeys, LDAP / Active Directory, Microsoft Entra ID, Google, Apple, OpenID Connect), people
// and groups, applications with their roles, the OpenID Connect provider and the federation API (docs/protocol.md).
package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sbrw-evc/keystone/internal/passkey"
	"github.com/sbrw-evc/keystone/internal/secrets"
	"github.com/sbrw-evc/keystone/internal/store"
)

// Config is what the process gives Keystone at start (cmd/keystone). Everything else — the public address, trusted
// proxies, the session lifetime — is in the settings (General), changed in the web app without a restart.
type Config struct {
	// WebDir holds the built web app.
	WebDir string
}

type App struct {
	cfg        Config
	st         *store.Store
	sec        secrets.Store
	ceremonies *passkey.Ceremonies
	keys       *signingKeys
	state      *stateKey
	recovery   *stateKey
	limiter    *limiter
	now        func() time.Time

	mu      sync.Mutex
	syncing map[string]bool

	genMu  sync.Mutex
	gen    General
	genAt  time.Time
	gennet []*net.IPNet
}

func New(cfg Config, st *store.Store, sec secrets.Store) *App {
	c := passkey.NewCeremonies()
	c.Keeper = store.Ceremonies{S: st}
	return &App{cfg: cfg, st: st, sec: sec, ceremonies: c, keys: &signingKeys{sec: sec},
		state: &stateKey{sec: sec}, recovery: &stateKey{sec: sec, path: recoveryKeyPath}, limiter: newLimiter(), now: time.Now, syncing: map[string]bool{}}
}

// publicURL is the configured address of Keystone (General.PublicURL), empty when not set.
func (a *App) publicURL(r *http.Request) string {
	ctx := context.Background()
	if r != nil {
		ctx = r.Context()
	}
	return a.general(ctx).PublicURL
}

// Issuer is the address of Keystone: the configured public address, else the address of the request.
func (a *App) Issuer(r *http.Request) string {
	if u := a.publicURL(r); u != "" {
		return u
	}
	if r == nil {
		return ""
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	if h := r.Header.Get("X-Forwarded-Host"); h != "" && a.trusted(r) {
		host = strings.TrimSpace(strings.Split(h, ",")[0])
	}
	return scheme + "://" + host
}

func (a *App) trusted(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	a.general(r.Context())
	a.genMu.Lock()
	nets := a.gennet
	a.genMu.Unlock()
	for _, n := range nets {
		if ip != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP is the address of the person: X-Forwarded-For from a trusted proxy, else the peer.
func (a *App) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" && a.trusted(r) {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	return host
}

func hashToken(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:])
}

// ---- answers

// apiError is an error the API answers with: HTTP status, a stable code for the web app and an English message.
type apiError struct {
	Status     int      `json:"-"`
	Code       string   `json:"code"`
	Message    string   `json:"message"`
	Violations []string `json:"violations,omitempty"`
	Extra      any      `json:"extra,omitempty"`
}

func (e *apiError) Error() string { return e.Message }

func fail(status int, code, message string) *apiError {
	return &apiError{Status: status, Code: code, Message: message}
}

var (
	errAuth      = fail(http.StatusUnauthorized, "unauthorized", "Sign in first")
	errForbidden = fail(http.StatusForbidden, "forbidden", "You are not allowed to do this")
	errNotFound  = fail(http.StatusNotFound, "not_found", "Not found")
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func writeError(w http.ResponseWriter, err error) {
	var ae *apiError
	if errors.As(err, &ae) {
		writeJSON(w, ae.Status, ae)
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, errNotFound)
		return
	}
	if errors.Is(err, store.ErrConflict) {
		writeJSON(w, http.StatusConflict, fail(http.StatusConflict, "conflict", "This name is already taken"))
		return
	}
	slog.Error("request failed", "err", err)
	writeJSON(w, http.StatusInternalServerError, fail(http.StatusInternalServerError, "internal", "Something went wrong; see the server log"))
}

func decode(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		return fail(http.StatusBadRequest, "bad_request", "The request is not valid JSON")
	}
	return nil
}

// ---- sessions

const sessionCookie = "spa_session"

type principal struct {
	User    store.User
	Session store.Session
}

type ctxKey int

const principalKey ctxKey = 0

func current(r *http.Request) *principal {
	p, _ := r.Context().Value(principalKey).(*principal)
	return p
}

// loadSession puts the signed-in person (if any) into the request context.
func (a *App) loadSession(r *http.Request) *http.Request {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return r
	}
	ctx := r.Context()
	s, err := a.st.SessionByID(ctx, hashToken(c.Value))
	if err != nil {
		return r
	}
	u, err := a.st.UserByID(ctx, s.UserID)
	if err != nil || u.Disabled {
		return r
	}
	a.st.TouchSession(ctx, s.ID)
	return r.WithContext(context.WithValue(ctx, principalKey, &principal{User: u, Session: s}))
}

// startSession signs the person in: a new session and its cookie (Lax, so the sign-in pages of applications that
// send people here find it on the top-level navigation).
func (a *App) startSession(w http.ResponseWriter, r *http.Request, u store.User, method string, mfa bool) (store.Session, error) {
	ctx := r.Context()
	raw := randomToken(32)
	s := store.Session{ID: hashToken(raw), UserID: u.ID, Method: method, MFA: mfa, IP: a.clientIP(r),
		UserAgent: truncate(r.UserAgent(), 256), ExpiresAt: a.now().Add(time.Duration(a.general(ctx).SessionHours) * time.Hour)}
	if err := a.st.CreateSession(ctx, s); err != nil {
		return s, err
	}
	a.st.SignedIn(ctx, u.ID) //nolint:errcheck
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: raw, Path: "/", HttpOnly: true, Secure: a.secure(r),
		SameSite: http.SameSiteLaxMode, Expires: s.ExpiresAt})
	a.st.Audit(ctx, u.Username, "auth.sign_in", u.Username, s.IP, map[string]any{"method": method, "mfa": mfa})
	s.CreatedAt = a.now()
	return s, nil
}

func (a *App) endSession(w http.ResponseWriter, r *http.Request) {
	if p := current(r); p != nil {
		a.st.DeleteSessions(r.Context(), p.User.ID, p.Session.ID, "") //nolint:errcheck
		a.st.Audit(r.Context(), p.User.Username, "auth.sign_out", p.User.Username, a.clientIP(r), nil)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: a.secure(r),
		SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func (a *App) secure(r *http.Request) bool {
	if u := a.publicURL(r); u != "" {
		return strings.HasPrefix(u, "https://")
	}
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// safeReturn keeps same-site paths only.
func safeReturn(p string) string {
	if p == "" || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") {
		return "/"
	}
	if u, err := url.Parse(p); err != nil || u.Host != "" {
		return "/"
	}
	return p
}
