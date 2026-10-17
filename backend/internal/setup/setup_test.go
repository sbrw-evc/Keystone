package setup_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sbrw-evc/keystone/internal/app"
	"github.com/sbrw-evc/keystone/internal/bootstrap"
	"github.com/sbrw-evc/keystone/internal/bootstrap/baotest"
	"github.com/sbrw-evc/keystone/internal/setup"
	"github.com/sbrw-evc/keystone/internal/store"
)

func testDB(t *testing.T) string {
	base := os.Getenv("SPA_TEST_POSTGRES")
	if base == "" {
		t.Skip("SPA_TEST_POSTGRES is not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	rand.Read(b) //nolint:errcheck
	name := "spa_test_" + hex.EncodeToString(b)
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)") //nolint:errcheck
		conn.Close(context.Background())
	})
	u, _ := url.Parse(base)
	u.Path = "/" + name
	return u.String()
}

type harness struct {
	t      *testing.T
	dir    string
	wz     *setup.Wizard
	srv    *httptest.Server
	app    *app.App
	st     *store.Store
	bao    *baotest.Server
	dbURL  string
	served http.Handler
}

func newHarness(t *testing.T) *harness {
	h := &harness{t: t, dir: t.TempDir(), bao: baotest.New(), dbURL: testDB(t)}
	t.Cleanup(h.bao.Close)
	h.wz = &setup.Wizard{Dir: h.dir, BaoWait: time.Millisecond, DefaultOpenBao: h.bao.URL,
		Activate: func(ctx context.Context, f *bootstrap.File) (*app.App, error) {
			st, sec, err := f.Open(ctx)
			if err != nil {
				return nil, err
			}
			t.Cleanup(st.Close)
			a := app.New(app.Config{}, st, sec)
			if err := a.MigrateSecrets(ctx, nil); err != nil {
				return nil, err
			}
			h.app, h.st, h.served = a, st, a.Handler()
			return a, nil
		}}
	if err := h.wz.Start(); err != nil {
		t.Fatal(err)
	}
	wizard := h.wz.Handler()
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/setup") {
			wizard.ServeHTTP(w, r)
			return
		}
		if h.served == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		h.served.ServeHTTP(w, r)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *harness) code() string {
	b, err := os.ReadFile(filepath.Join(h.dir, "setup-code"))
	if err != nil {
		h.t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

type answer struct {
	Code        string         `json:"code"`
	Message     string         `json:"message"`
	Stage       string         `json:"stage"`
	OK          bool           `json:"ok"`
	Extra       map[string]any `json:"extra"`
	OpenBaoInit *struct {
		RootToken   string `json:"root_token"`
		RecoveryKey string `json:"recovery_key"`
	} `json:"openbao_init"`
}

func (h *harness) post(code, path string, body any) (int, answer) {
	h.t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", h.srv.URL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if code != "" {
		req.Header.Set("X-Setup-Code", code)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	var a answer
	json.Unmarshal(b, &a) //nolint:errcheck
	return res.StatusCode, a
}

func (h *harness) stage() string {
	res, err := http.Get(h.srv.URL + "/api/setup")
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	var a answer
	json.NewDecoder(res.Body).Decode(&a) //nolint:errcheck
	return a.Stage
}

func (h *harness) postgres() map[string]any {
	return map[string]any{"dsn": h.dbURL}
}

func TestSetupCode(t *testing.T) {
	h := newHarness(t)
	if h.stage() != setup.StageStorage {
		t.Fatalf("stage %q", h.stage())
	}
	code := h.code()
	if len(strings.ReplaceAll(code, "-", "")) != 12 {
		t.Fatalf("code %q", code)
	}
	if st, a := h.post("", "/api/setup/code", nil); st != http.StatusUnauthorized || a.Code != "wrong_setup_code" {
		t.Fatalf("without a code: %d %+v", st, a)
	}
	if st, a := h.post("", "/api/setup/storage", map[string]any{"postgres": h.postgres()}); st != http.StatusUnauthorized {
		t.Fatalf("a step without a code: %d %+v", st, a)
	}
	// typed in lower case without dashes
	if st, a := h.post(strings.ToLower(strings.ReplaceAll(code, "-", "")), "/api/setup/code", nil); st != http.StatusOK || a.Stage != setup.StageStorage {
		t.Fatalf("the right code: %d %+v", st, a)
	}
	var last answer
	for i := 0; i < setup.MaxAttempts-3; i++ {
		_, last = h.post("WRONG-CODE-0000", "/api/setup/code", nil)
	}
	if last.Extra["attempts_left"] != float64(1) {
		t.Fatalf("attempts left: %+v", last)
	}
	if st, a := h.post("WRONG-CODE-0000", "/api/setup/code", nil); st != http.StatusTooManyRequests || a.Code != "setup_code_replaced" {
		t.Fatalf("too many: %d %+v", st, a)
	}
	if st, _ := h.post(code, "/api/setup/code", nil); st != http.StatusUnauthorized {
		t.Fatal("the replaced code still works")
	}
	if st, _ := h.post(h.code(), "/api/setup/code", nil); st != http.StatusOK {
		t.Fatal("the new code does not work")
	}
}

func TestSetupBuiltinOpenBao(t *testing.T) {
	h := newHarness(t)
	code := h.code()
	if st, a := h.post(code, "/api/setup/openbao/test", map[string]any{"openbao": map[string]string{"mode": "builtin", "addr": h.bao.URL}}); st != http.StatusOK || !a.OK {
		t.Fatalf("test openbao: %d %+v", st, a)
	}
	if st, a := h.post(code, "/api/setup/postgres/test", map[string]any{"postgres": h.postgres()}); st != http.StatusOK || !a.OK {
		t.Fatalf("test postgres: %d %+v", st, a)
	}
	if st, a := h.post(code, "/api/setup/postgres/test", map[string]any{"postgres": map[string]any{"host": "127.0.0.1", "port": 1, "database": "x", "user": "x"}}); st != http.StatusOK || a.OK {
		t.Fatalf("a wrong postgres passed: %d %+v", st, a)
	}
	if st, a := h.post(code, "/api/setup/admin", map[string]string{"username": "root", "password": "Correct-Horse-9!"}); st != http.StatusConflict || a.Code != "wrong_stage" {
		t.Fatalf("a later step first: %d %+v", st, a)
	}

	st, a := h.post(code, "/api/setup/storage", map[string]any{"postgres": h.postgres(), "openbao": map[string]string{"mode": "builtin", "addr": h.bao.URL}})
	if st != http.StatusOK || a.Stage != app.SetupAdmin || a.OpenBaoInit == nil || a.OpenBaoInit.RootToken != "root-token" || a.OpenBaoInit.RecoveryKey != "recovery-key" {
		t.Fatalf("storage: %d %+v", st, a)
	}
	// bootstrap.json: no password, the secret_id apart; the PostgreSQL password is in OpenBao
	raw, err := os.ReadFile(bootstrap.Path(h.dir))
	if err != nil {
		t.Fatal(err)
	}
	pgURL, _ := url.Parse(h.dbURL)
	pw, _ := pgURL.User.Password()
	if strings.Contains(string(raw), ":"+pw+"@") || strings.Contains(string(raw), "secret-keystone") || strings.Contains(string(raw), "root-token") {
		t.Fatalf("bootstrap.json holds a secret: %s", raw)
	}
	if info, _ := os.Stat(bootstrap.Path(h.dir)); runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("bootstrap.json mode %v", info.Mode())
	}
	if got := h.bao.Secret("keystone/infra/postgres"); got["password"] != pw {
		t.Fatalf("the PostgreSQL password in OpenBao: %v", got)
	}
	if b, _ := os.ReadFile(bootstrap.SecretIDPath(h.dir)); strings.TrimSpace(string(b)) != "secret-keystone" {
		t.Fatalf("secret_id %q", b)
	}
	// repeating the step
	if st, a := h.post(code, "/api/setup/storage", map[string]any{"postgres": h.postgres(), "openbao": map[string]string{"mode": "builtin", "addr": h.bao.URL}}); st != http.StatusConflict || a.Code != "wrong_stage" {
		t.Fatalf("storage again: %d %+v", st, a)
	}
	// Keystone runs: its API answers
	res, err := http.Get(h.srv.URL + "/api/v1/auth/methods")
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("Keystone after the storage step: %v %v", res, err)
	}
	res.Body.Close()

	if st, a := h.post(code, "/api/setup/admin", map[string]string{"username": "root", "password": "short"}); st != http.StatusBadRequest || a.Code != "password_policy" {
		t.Fatalf("a weak password: %d %+v", st, a)
	}
	if st, a := h.post(code, "/api/setup/admin", map[string]string{"username": "root", "name": "Root", "password": "Correct-Horse-9!"}); st != http.StatusOK || a.Stage != app.SetupOrganization {
		t.Fatalf("admin: %d %+v", st, a)
	}
	if st, a := h.post(code, "/api/setup/organization", map[string]string{"organization": "Example", "public_url": "ftp://bad"}); st != http.StatusBadRequest || a.Code != "invalid_public_url" {
		t.Fatalf("a bad address: %d %+v", st, a)
	}
	if st, a := h.post(code, "/api/setup/organization", map[string]string{"organization": "Example", "public_url": "https://id.example.com"}); st != http.StatusOK || a.Stage != app.SetupProxies {
		t.Fatalf("organization: %d %+v", st, a)
	}
	if st, a := h.post(code, "/api/setup/proxies", map[string]any{"trusted_proxies": []string{"192.168.0.100"}}); st != http.StatusOK || a.Stage != app.SetupDone {
		t.Fatalf("proxies: %d %+v", st, a)
	}

	// closed: the code and the kept root token are gone, every step answers setup_done
	if _, err := os.Stat(filepath.Join(h.dir, "setup-code")); !os.IsNotExist(err) {
		t.Fatal("the setup code file is left")
	}
	if _, err := os.Stat(filepath.Join(h.dir, "openbao-init.json")); !os.IsNotExist(err) {
		t.Fatal("the root token is left on disk")
	}
	if st, a := h.post(code, "/api/setup/proxies", map[string]any{}); st != http.StatusConflict || a.Code != "setup_done" {
		t.Fatalf("after the end: %d %+v", st, a)
	}
	if h.stage() != app.SetupDone {
		t.Fatalf("stage %q", h.stage())
	}
	res, _ = http.Get(h.srv.URL + "/.well-known/openid-configuration")
	var d struct {
		Issuer string `json:"issuer"`
	}
	json.NewDecoder(res.Body).Decode(&d) //nolint:errcheck
	res.Body.Close()
	if d.Issuer != "https://id.example.com" {
		t.Fatalf("issuer %q", d.Issuer)
	}
	if n, _ := h.st.CountAdmins(context.Background()); n != 1 {
		t.Fatalf("admins %d", n)
	}

	// a restart: bootstrap.json opens Keystone without the wizard
	f, err := bootstrap.Load(h.dir)
	if err != nil || f == nil {
		t.Fatalf("bootstrap.json: %v", err)
	}
	st2, _, err := f.Open(context.Background())
	if err != nil {
		t.Fatalf("open after a restart: %v", err)
	}
	st2.Close()
}

func TestSetupExternalOpenBao(t *testing.T) {
	h := newHarness(t)
	roleID, secretID := h.bao.SetUp("secrets")
	code := h.code()
	bad := map[string]string{"mode": "external", "addr": h.bao.URL, "mount": "secrets", "role_id": roleID, "secret_id": "wrong"}
	if st, a := h.post(code, "/api/setup/openbao/test", map[string]any{"openbao": bad}); st != http.StatusOK || a.OK {
		t.Fatalf("a wrong secret_id passed: %d %+v", st, a)
	}
	good := map[string]string{"mode": "external", "addr": h.bao.URL, "mount": "secrets", "role_id": roleID, "secret_id": secretID}
	if st, a := h.post(code, "/api/setup/openbao/test", map[string]any{"openbao": good}); st != http.StatusOK || !a.OK {
		t.Fatalf("test: %d %+v", st, a)
	}
	st, a := h.post(code, "/api/setup/storage", map[string]any{"postgres": h.postgres(), "openbao": good})
	if st != http.StatusOK || a.Stage != app.SetupAdmin || a.OpenBaoInit != nil {
		t.Fatalf("storage: %d %+v", st, a)
	}
	if h.bao.Secret("secrets/infra/postgres") == nil {
		t.Fatal("the PostgreSQL password is not in OpenBao")
	}
}
