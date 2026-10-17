// Package setup is the setup wizard of Keystone: /api/setup and its steps. Keystone without bootstrap.json starts in
// the setup mode, where the wizard (and the web app that shows it) is all it serves. Nothing is accepted without the
// one-time setup code, printed to the log and written to <data>/setup-code; wrong codes are limited, and after too
// many a new code replaces the old one. The steps:
//
//	storage       PostgreSQL and OpenBao (the built-in one is initialised here) → bootstrap.json; Keystone switches
//	              to the normal mode without a restart and moves the secrets of an older installation into OpenBao
//	admin         the first administrator (skipped for a database that has people)
//	organization  the name shown on the sign-in page and the public address
//	proxies       the reverse proxies whose X-Forwarded-* are trusted
//	done          the code stops working
package setup

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sbrw-evc/keystone/internal/app"
	"github.com/sbrw-evc/keystone/internal/bootstrap"
	"github.com/sbrw-evc/keystone/internal/secrets"
)

// StageStorage is the first step (no bootstrap.json); the others are app.Setup*.
const StageStorage = "storage"

// MaxAttempts wrong codes are accepted; then a new code replaces the old one.
const MaxAttempts = 10

// Legacy is what an installation from before the wizard had in its environment: the wizard fills its form from it
// and moves the secrets sealed with the master key into OpenBao.
type Legacy struct {
	DatabaseURL string // with its password
	MasterKey   bool   // SPA_MASTER_KEY is set: the database has sealed secrets to move
	BaoAddr     string
}

// Activate opens Keystone with the storage of f and puts it in charge of every request but /api/setup; it returns
// the application (the wizard continues with it).
type Activate func(ctx context.Context, f *bootstrap.File) (*app.App, error)

type Wizard struct {
	Dir      string // the data directory
	Legacy   Legacy
	Activate Activate
	// Defaults of the storage form: the services of the compose file.
	DefaultPostgres PostgresIn
	DefaultOpenBao  string
	// BaoWait is the pause between checks that the built-in OpenBao became active (tests make it short).
	BaoWait time.Duration

	mu       sync.Mutex
	app      *app.App
	code     string
	attempts int
	done     bool
}

// Attach gives the wizard Keystone in the normal mode (a start with bootstrap.json); a wizard not finished yet
// continues with its next step.
func (wz *Wizard) Attach(ctx context.Context, a *app.App) error {
	step, err := a.SetupStep(ctx)
	if err != nil {
		return err
	}
	wz.mu.Lock()
	defer wz.mu.Unlock()
	wz.app = a
	wz.done = step == app.SetupDone
	if wz.done {
		wz.forgetCode()
	}
	return nil
}

// Start makes the setup code when the wizard is not finished.
func (wz *Wizard) Start() error {
	wz.mu.Lock()
	defer wz.mu.Unlock()
	if wz.done {
		return nil
	}
	return wz.newCode()
}

const codeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func (wz *Wizard) codePath() string { return filepath.Join(wz.Dir, "setup-code") }

func (wz *Wizard) newCode() error {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	for i := range b {
		b[i] = codeAlphabet[int(b[i])%len(codeAlphabet)] // 256 is a multiple of 32: no bias
	}
	wz.code, wz.attempts = string(b), 0
	shown := wz.code[:4] + "-" + wz.code[4:8] + "-" + wz.code[8:]
	if err := bootstrap.WritePrivate(wz.codePath(), []byte(shown+"\n")); err != nil {
		slog.Warn("the setup code cannot be written", "path", wz.codePath(), "err", err)
	}
	slog.Warn("Keystone is not set up yet: open it in a browser and enter the setup code", "setup_code", shown, "file", wz.codePath())
	return nil
}

func (wz *Wizard) forgetCode() {
	wz.code = ""
	os.Remove(wz.codePath()) //nolint:errcheck
}

func normalizeCode(s string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(s)))
}

// ---- answers

type apiErr struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Extra   any    `json:"extra,omitempty"`
}

func (e *apiErr) Error() string { return e.Message }

func (e *apiErr) HTTPStatus() int { return e.Status }

func fail(status int, code, message string) *apiErr {
	return &apiErr{Status: status, Code: code, Message: message}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

// writeError answers with an error of the wizard or of Keystone (the password policy and the like: they carry their
// HTTP status); anything else is a failed step with its message.
func writeError(w http.ResponseWriter, err error) {
	var known interface{ HTTPStatus() int }
	if errors.As(err, &known) {
		writeJSON(w, known.HTTPStatus(), known)
		return
	}
	slog.Error("setup step failed", "err", err)
	writeJSON(w, http.StatusBadRequest, fail(http.StatusBadRequest, "setup_failed", err.Error()))
}

var (
	errDone      = fail(http.StatusConflict, "setup_done", "Keystone is set up already")
	errWrongCode = fail(http.StatusUnauthorized, "wrong_setup_code", "The setup code is wrong. It is in the log of Keystone and in the file setup-code of its data directory")
	errTooMany   = fail(http.StatusTooManyRequests, "setup_code_replaced", "Too many wrong codes: Keystone made a new setup code. Take it from the log again")
)

// Handler serves /api/setup and /api/setup/….
func (wz *Wizard) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/setup", wz.status)
	mux.HandleFunc("POST /api/setup/code", wz.step("", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "stage": wz.stage(r.Context())})
	}))
	mux.HandleFunc("POST /api/setup/postgres/test", wz.step(StageStorage, wz.testPostgres))
	mux.HandleFunc("POST /api/setup/openbao/test", wz.step(StageStorage, wz.testOpenBao))
	mux.HandleFunc("POST /api/setup/storage", wz.step(StageStorage, wz.storage))
	mux.HandleFunc("POST /api/setup/admin", wz.step(app.SetupAdmin, wz.admin))
	mux.HandleFunc("POST /api/setup/organization", wz.step(app.SetupOrganization, wz.organization))
	mux.HandleFunc("POST /api/setup/proxies", wz.step(app.SetupProxies, wz.proxies))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		mux.ServeHTTP(w, r)
	})
}

// stage is where the wizard is.
func (wz *Wizard) stage(ctx context.Context) string {
	wz.mu.Lock()
	a, done := wz.app, wz.done
	wz.mu.Unlock()
	if done {
		return app.SetupDone
	}
	if a == nil {
		return StageStorage
	}
	s, err := a.SetupStep(ctx)
	if err != nil {
		return StageStorage
	}
	return s
}

// step checks the setup code (header X-Setup-Code) and that the wizard is at stage (any when empty).
func (wz *Wizard) step(stage string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		wz.mu.Lock()
		if wz.done {
			wz.mu.Unlock()
			writeError(w, errDone)
			return
		}
		given := normalizeCode(r.Header.Get("X-Setup-Code"))
		if wz.code == "" || subtle.ConstantTimeCompare([]byte(given), []byte(wz.code)) != 1 {
			wz.attempts++
			if wz.attempts >= MaxAttempts {
				wz.newCode() //nolint:errcheck
				wz.mu.Unlock()
				writeError(w, errTooMany)
				return
			}
			left := MaxAttempts - wz.attempts
			wz.mu.Unlock()
			e := *errWrongCode
			e.Extra = map[string]int{"attempts_left": left}
			writeError(w, &e)
			return
		}
		wz.mu.Unlock()
		if stage != "" {
			if cur := wz.stage(r.Context()); cur != stage {
				e := fail(http.StatusConflict, "wrong_stage", "This step is done already")
				e.Extra = map[string]string{"stage": cur}
				writeError(w, e)
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		next(w, r)
	}
}

func decode(r *http.Request, v any) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return fail(http.StatusBadRequest, "bad_request", "The request is not valid JSON")
	}
	return nil
}

// ---- GET /api/setup

func (wz *Wizard) status(w http.ResponseWriter, r *http.Request) {
	stage := wz.stage(r.Context())
	out := map[string]any{"stage": stage}
	if stage == app.SetupDone {
		writeJSON(w, http.StatusOK, out)
		return
	}
	pg := wz.DefaultPostgres
	legacy := map[string]any{"master_key": wz.Legacy.MasterKey}
	if wz.Legacy.DatabaseURL != "" {
		if in, ok := parsePostgres(wz.Legacy.DatabaseURL); ok {
			pg = in
			legacy["database"] = true
		}
	}
	pg.Password = ""
	bao := wz.DefaultOpenBao
	if wz.Legacy.BaoAddr != "" {
		bao = wz.Legacy.BaoAddr
	}
	out["defaults"] = map[string]any{"postgres": pg, "openbao": map[string]string{"addr": bao}}
	out["legacy"] = legacy
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		host = strings.TrimSpace(strings.Split(h, ",")[0])
	}
	out["public_url_hint"] = scheme + "://" + host
	if r.Header.Get("X-Forwarded-For") != "" {
		if peer, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			out["proxy_hint"] = peer
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- storage

// PostgresIn is the PostgreSQL of the form: an address, or its parts.
type PostgresIn struct {
	DSN      string `json:"dsn,omitempty"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	User     string `json:"user"`
	Password string `json:"password,omitempty"`
	SSLMode  string `json:"sslmode"`
}

func parsePostgres(dsn string) (PostgresIn, bool) {
	c, err := pgx.ParseConfig(dsn)
	if err != nil {
		return PostgresIn{}, false
	}
	ssl := "disable"
	if c.TLSConfig != nil {
		ssl = "require"
	}
	return PostgresIn{Host: c.Host, Port: int(c.Port), Database: c.Database, User: c.User, Password: c.Password, SSLMode: ssl}, true
}

// resolve gives the address without its password and the password; an empty password is the one of the legacy
// address.
func (wz *Wizard) resolvePostgres(in PostgresIn) (dsn, password string, err error) {
	if strings.TrimSpace(in.DSN) != "" {
		dsn, password, err = bootstrap.SplitDSN(in.DSN)
		if err != nil {
			return "", "", fail(http.StatusBadRequest, "invalid_postgres", err.Error())
		}
	} else {
		if in.Host == "" || in.Database == "" || in.User == "" {
			return "", "", fail(http.StatusBadRequest, "invalid_postgres", "Enter the host, the database and the user of PostgreSQL")
		}
		dsn, password = bootstrap.BuildDSN(in.Host, in.Port, in.Database, in.User, in.SSLMode), in.Password
	}
	if password == "" && wz.Legacy.DatabaseURL != "" {
		if old, ok := parsePostgres(wz.Legacy.DatabaseURL); ok {
			password = old.Password
		}
	}
	return dsn, password, nil
}

func checkPostgres(ctx context.Context, dsn, password string) error {
	c, err := pgx.ParseConfig(dsn)
	if err != nil {
		return err
	}
	if password != "" {
		c.Password = password
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, c)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	return conn.Ping(ctx)
}

func (wz *Wizard) testPostgres(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Postgres PostgresIn `json:"postgres"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	dsn, pw, err := wz.resolvePostgres(in.Postgres)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := checkPostgres(r.Context(), dsn, pw); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// OpenBaoIn is the OpenBao of the form.
type OpenBaoIn struct {
	// Mode: "builtin" — the OpenBao of the compose file, initialised by the wizard; "external" — an OpenBao with an
	// AppRole for Keystone (role_id, secret_id) on a KV v2 mount.
	Mode     string `json:"mode"`
	Addr     string `json:"addr"`
	Mount    string `json:"mount"`
	RoleID   string `json:"role_id"`
	SecretID string `json:"secret_id"`
	// RootToken: for a built-in OpenBao initialised before (the wizard needs it to set up AppRole).
	RootToken string `json:"root_token"`
}

func (in *OpenBaoIn) check() error {
	in.Addr = strings.TrimRight(strings.TrimSpace(in.Addr), "/")
	if !strings.HasPrefix(in.Addr, "http://") && !strings.HasPrefix(in.Addr, "https://") {
		return fail(http.StatusBadRequest, "invalid_openbao", "Enter the address of OpenBao, such as http://openbao:8200")
	}
	in.Mount = strings.Trim(strings.TrimSpace(in.Mount), "/")
	if in.Mount == "" {
		in.Mount = bootstrap.DefaultMount
	}
	switch in.Mode {
	case "builtin":
	case "external":
		in.RoleID, in.SecretID = strings.TrimSpace(in.RoleID), strings.TrimSpace(in.SecretID)
		if in.RoleID == "" || in.SecretID == "" {
			return fail(http.StatusBadRequest, "invalid_openbao", "Enter the role_id and secret_id of the AppRole of Keystone")
		}
	default:
		return fail(http.StatusBadRequest, "invalid_openbao", "Choose the built-in OpenBao or an external one")
	}
	return nil
}

func (wz *Wizard) baoInit(in OpenBaoIn) *bootstrap.BaoInit {
	return &bootstrap.BaoInit{Addr: in.Addr, Mount: in.Mount, Dir: wz.Dir, Wait: wz.BaoWait}
}

// externalStore checks an AppRole by logging in with it (the secret_id goes to a scratch file next to the real one).
func (wz *Wizard) externalStore(ctx context.Context, in OpenBaoIn, secretIDFile string) (*secrets.OpenBao, error) {
	if err := bootstrap.WritePrivate(secretIDFile, []byte(in.SecretID+"\n")); err != nil {
		return nil, err
	}
	b := secrets.NewOpenBaoAppRole(in.Addr, in.Mount, in.RoleID, secretIDFile)
	if err := b.Login(ctx); err != nil {
		return nil, fmt.Errorf("the AppRole does not sign in: %w", err)
	}
	if err := secrets.Check(ctx, b); err != nil {
		return nil, fmt.Errorf("the AppRole cannot write to %s/: %w", in.Mount, err)
	}
	return b, nil
}

func (wz *Wizard) testOpenBao(w http.ResponseWriter, r *http.Request) {
	var in struct {
		OpenBao OpenBaoIn `json:"openbao"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	if err := in.OpenBao.check(); err != nil {
		writeError(w, err)
		return
	}
	ctx := r.Context()
	if in.OpenBao.Mode == "builtin" {
		initialized, err := wz.baoInit(in.OpenBao).Status(ctx)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		_, pendErr := os.Stat(wz.baoInit(in.OpenBao).PendingPath())
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "initialized": initialized, "root_token_needed": initialized && pendErr != nil})
		return
	}
	probe := filepath.Join(wz.Dir, "approle", "secret_id.probe")
	defer os.Remove(probe) //nolint:errcheck
	if _, err := wz.externalStore(ctx, in.OpenBao, probe); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (wz *Wizard) storage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in struct {
		Postgres PostgresIn `json:"postgres"`
		OpenBao  OpenBaoIn  `json:"openbao"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	if err := in.OpenBao.check(); err != nil {
		writeError(w, err)
		return
	}
	dsn, pw, err := wz.resolvePostgres(in.Postgres)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := checkPostgres(ctx, dsn, pw); err != nil {
		writeError(w, fail(http.StatusBadRequest, "postgres_unavailable", "PostgreSQL: "+err.Error()))
		return
	}

	secretID := bootstrap.SecretIDPath(wz.Dir)
	f := &bootstrap.File{Postgres: bootstrap.Postgres{DSN: dsn},
		OpenBao: bootstrap.OpenBao{Addr: in.OpenBao.Addr, Mount: in.OpenBao.Mount, Auth: "approle", SecretIDFile: secretID}}
	var shown bootstrap.Shown
	var sec *secrets.OpenBao
	if in.OpenBao.Mode == "builtin" {
		var roleID string
		shown, roleID, err = wz.baoInit(in.OpenBao).Run(ctx, strings.TrimSpace(in.OpenBao.RootToken))
		if err != nil {
			writeError(w, fail(http.StatusBadRequest, "openbao_setup_failed", err.Error()))
			return
		}
		f.OpenBao.RoleID = roleID
		sec = secrets.NewOpenBaoAppRole(f.OpenBao.Addr, f.OpenBao.Mount, roleID, secretID)
		if err := secrets.Check(ctx, sec); err != nil {
			writeError(w, fail(http.StatusBadRequest, "openbao_setup_failed", "the new AppRole cannot write: "+err.Error()))
			return
		}
	} else {
		f.OpenBao.RoleID = in.OpenBao.RoleID
		if sec, err = wz.externalStore(ctx, in.OpenBao, secretID); err != nil {
			writeError(w, fail(http.StatusBadRequest, "openbao_unavailable", err.Error()))
			return
		}
	}
	if err := sec.Put(ctx, bootstrap.PostgresSecret, map[string]string{"password": pw}); err != nil {
		writeError(w, fail(http.StatusBadRequest, "openbao_unavailable", "keeping the PostgreSQL password: "+err.Error()))
		return
	}
	if err := bootstrap.Save(wz.Dir, f); err != nil {
		writeError(w, err)
		return
	}
	a, err := wz.Activate(ctx, f)
	if err != nil {
		os.Remove(bootstrap.Path(wz.Dir)) //nolint:errcheck // the step can be repeated
		writeError(w, fail(http.StatusBadRequest, "activation_failed", err.Error()))
		return
	}
	if err := wz.Attach(ctx, a); err != nil {
		writeError(w, err)
		return
	}
	a.Store().Audit(ctx, "spa", "setup.storage", "", a.ClientIP(r), map[string]any{"openbao": in.OpenBao.Mode, "postgres": dsn})
	out := map[string]any{"stage": wz.stage(ctx)}
	if shown.RootToken != "" && in.OpenBao.RootToken == "" {
		out["openbao_init"] = shown
	}
	if out["stage"] == app.SetupDone {
		wz.finish()
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- the steps with Keystone running

func (wz *Wizard) current() *app.App {
	wz.mu.Lock()
	defer wz.mu.Unlock()
	return wz.app
}

func (wz *Wizard) admin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	a := wz.current()
	ctx := r.Context()
	if _, err := a.CreateFirstAdmin(ctx, in.Username, in.Name, in.Email, in.Password, a.ClientIP(r)); err != nil {
		writeError(w, err)
		return
	}
	if err := a.SetSetupStep(ctx, app.SetupOrganization); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"stage": app.SetupOrganization})
}

func (wz *Wizard) organization(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Organization string `json:"organization"`
		PublicURL    string `json:"public_url"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	a := wz.current()
	ctx := r.Context()
	if _, err := a.SetupGeneral(ctx, app.SetupSettings{Organization: &in.Organization, PublicURL: &in.PublicURL}, a.ClientIP(r)); err != nil {
		writeError(w, err)
		return
	}
	if err := a.SetSetupStep(ctx, app.SetupProxies); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"stage": app.SetupProxies})
}

func (wz *Wizard) proxies(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TrustedProxies []string `json:"trusted_proxies"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	if in.TrustedProxies == nil {
		in.TrustedProxies = []string{}
	}
	a := wz.current()
	ctx := r.Context()
	if _, err := a.SetupGeneral(ctx, app.SetupSettings{TrustedProxies: &in.TrustedProxies}, a.ClientIP(r)); err != nil {
		writeError(w, err)
		return
	}
	if err := a.SetupFinished(ctx, a.ClientIP(r)); err != nil {
		writeError(w, err)
		return
	}
	wz.finish()
	writeJSON(w, http.StatusOK, map[string]any{"stage": app.SetupDone})
}

// finish closes the wizard: the code stops working, the root token kept for a repeated step goes.
func (wz *Wizard) finish() {
	wz.mu.Lock()
	defer wz.mu.Unlock()
	wz.done = true
	wz.forgetCode()
	bootstrap.ForgetPending(wz.Dir)
	slog.Info("the setup wizard is finished")
}
