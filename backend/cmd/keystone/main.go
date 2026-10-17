// Command keystone runs Keystone — sign-in and access for the Umbrella family.
//
// Keystone reads where its storage is from <data>/bootstrap.json, written by the setup wizard: the address of
// PostgreSQL (its password is in OpenBao) and the AppRole of OpenBao (the secret_id in <data>/approle/secret_id).
// Without bootstrap.json it starts in the setup mode: open it in a browser and enter the setup code from the log.
// Everything else is set in the wizard and in Settings.
//
// Environment:
//
//	SPA_DATA_DIR   the data directory (default /data)
//	SPA_LISTEN     listen address (default :8080)
//	SPA_WEB_DIR    the built web app (default ./web)
//
// Taken over once from an installation from before the wizard (when there is no bootstrap.json yet): SPA_DATABASE_URL,
// BAO_ADDR / BAO_TOKEN / BAO_MOUNT, SPA_MASTER_KEY (or SPA_MASTER_KEY_FILE: the secrets sealed with it are moved to
// OpenBao), SPA_PUBLIC_URL, SPA_TRUSTED_PROXIES, SPA_SESSION_HOURS, SPA_ADMIN_USERNAME / SPA_ADMIN_PASSWORD.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sbrw-evc/keystone/internal/app"
	"github.com/sbrw-evc/keystone/internal/bootstrap"
	"github.com/sbrw-evc/keystone/internal/secrets"
	"github.com/sbrw-evc/keystone/internal/setup"
	"github.com/sbrw-evc/keystone/internal/store"
)

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("keystone stopped", "err", err)
		os.Exit(1)
	}
}

// masterKey is SPA_MASTER_KEY (or the file SPA_MASTER_KEY_FILE) of an older installation; nil when not set.
func masterKey() ([]byte, error) {
	raw := env("SPA_MASTER_KEY", "")
	if f := env("SPA_MASTER_KEY_FILE", ""); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		raw = strings.TrimSpace(string(b))
	}
	if raw == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, errors.New("SPA_MASTER_KEY must be base64 of 32 bytes")
	}
	return key, nil
}

// legacyDatabaseURL is the database of an older installation: SPA_DATABASE_URL, or the PostgreSQL of the old compose
// file (whose address was built from POSTGRES_PASSWORD).
func legacyDatabaseURL(hasOld bool) string {
	if v := env("SPA_DATABASE_URL", ""); v != "" {
		return v
	}
	if pw := env("POSTGRES_PASSWORD", ""); pw != "" && hasOld {
		return "postgres://spa:" + url.QueryEscape(pw) + "@postgres:5432/spa?sslmode=disable"
	}
	return ""
}

type server struct {
	dataDir string
	webDir  string
	key     []byte // the master key of an older installation, to move its sealed secrets
	legacy  bool   // no bootstrap.json yet: settings of the environment are taken over

	handler atomic.Pointer[http.Handler]
	mu      sync.Mutex
	app     *app.App
	st      *store.Store
	ctx     context.Context
}

// activate opens Keystone with the storage of f: migrations, the move of secrets into OpenBao, the settings of an
// older installation, and from then on it answers every request but the wizard's.
func (s *server) activate(ctx context.Context, f *bootstrap.File) (*app.App, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.app != nil {
		return s.app, nil
	}
	st, sec, err := f.Open(ctx)
	if err != nil {
		return nil, err
	}
	a := app.New(app.Config{WebDir: s.webDir}, st, sec)
	var sealed secrets.Store
	if s.key != nil {
		if sealed, err = secrets.NewSealed(st, s.key); err != nil {
			st.Close()
			return nil, err
		}
	}
	if err := a.MigrateSecrets(ctx, sealed); err != nil {
		st.Close()
		return nil, fmt.Errorf("moving the secrets into OpenBao: %w", err)
	}
	if s.legacy {
		if err := a.ImportLegacySettings(ctx, app.LegacySettings{PublicURL: env("SPA_PUBLIC_URL", ""),
			TrustedProxies: env("SPA_TRUSTED_PROXIES", ""), SessionHours: env("SPA_SESSION_HOURS", "")}); err != nil {
			st.Close()
			return nil, err
		}
		if pw := env("SPA_ADMIN_PASSWORD", ""); pw != "" {
			if err := a.Bootstrap(ctx, env("SPA_ADMIN_USERNAME", "admin"), pw); err != nil {
				st.Close()
				return nil, err
			}
		}
	}
	h := a.Handler()
	s.handler.Store(&h)
	s.app, s.st = a, st
	go a.Housekeeping(s.ctx)
	slog.Info("keystone is running", "secrets", sec.Kind(), "openbao", f.OpenBao.Addr)
	return a, nil
}

// adoptLegacy writes bootstrap.json for an older installation that had both its database and OpenBao in the
// environment (SPA_DATABASE_URL, BAO_ADDR, BAO_TOKEN), so that it starts without the wizard.
func (s *server) adoptLegacy(ctx context.Context, dbURL string) (*bootstrap.File, error) {
	addr, token := env("BAO_ADDR", ""), env("BAO_TOKEN", "")
	if dbURL == "" || addr == "" || token == "" {
		return nil, nil
	}
	dsn, pw, err := bootstrap.SplitDSN(dbURL)
	if err != nil {
		return nil, fmt.Errorf("SPA_DATABASE_URL: %w", err)
	}
	tokenFile := filepath.Join(s.dataDir, "openbao-token")
	if err := bootstrap.WritePrivate(tokenFile, []byte(token+"\n")); err != nil {
		return nil, err
	}
	f := &bootstrap.File{Postgres: bootstrap.Postgres{DSN: dsn},
		OpenBao: bootstrap.OpenBao{Addr: addr, Mount: env("BAO_MOUNT", "spa"), Auth: "token", TokenFile: tokenFile}}
	sec, err := f.Secrets()
	if err != nil {
		return nil, err
	}
	if err := sec.Put(ctx, bootstrap.PostgresSecret, map[string]string{"password": pw}); err != nil {
		return nil, fmt.Errorf("OpenBao (%s): %w", addr, err)
	}
	if err := bootstrap.Save(s.dataDir, f); err != nil {
		return nil, err
	}
	slog.Warn("took the storage of SPA_DATABASE_URL and BAO_ADDR/BAO_TOKEN over into bootstrap.json; remove them, SPA_MASTER_KEY and the other SPA_ settings from .env now",
		"bootstrap", bootstrap.Path(s.dataDir))
	return f, nil
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s := &server{dataDir: env("SPA_DATA_DIR", "/data"), webDir: env("SPA_WEB_DIR", "web"), ctx: ctx}
	var err error
	if s.key, err = masterKey(); err != nil {
		return err
	}
	f, err := bootstrap.Load(s.dataDir)
	if err != nil {
		return err
	}
	hasOld := s.key != nil || env("BAO_ADDR", "") != "" || env("SPA_PUBLIC_URL", "") != ""
	dbURL := legacyDatabaseURL(hasOld)
	if f == nil {
		s.legacy = true
		if f, err = s.adoptLegacy(ctx, dbURL); err != nil {
			return err
		}
	}

	wz := &setup.Wizard{Dir: s.dataDir, Activate: s.activate,
		Legacy:          setup.Legacy{DatabaseURL: dbURL, MasterKey: s.key != nil, BaoAddr: env("BAO_ADDR", "")},
		DefaultPostgres: setup.PostgresIn{Host: "postgres", Port: 5432, Database: "spa", User: "spa", SSLMode: "disable"},
		DefaultOpenBao:  "http://openbao:8200"}
	// The setup mode: the web app (it shows the wizard) and the wizard's API; other API calls wait for the setup.
	web := app.WebHandler(s.webDir)
	var setupMode http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true,"setup":true}`)) //nolint:errcheck
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/oauth2/") || strings.HasPrefix(r.URL.Path, "/.well-known/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"code":"setup_required","message":"Keystone is not set up yet: open it in a browser"}`)) //nolint:errcheck
			return
		}
		web.ServeHTTP(w, r)
	})
	s.handler.Store(&setupMode)

	if f != nil {
		a, err := s.activate(ctx, f)
		if err != nil {
			return err
		}
		if err := wz.Attach(ctx, a); err != nil {
			return err
		}
	} else {
		slog.Warn("no bootstrap.json: Keystone starts in the setup mode", "data", s.dataDir)
	}
	if err := wz.Start(); err != nil {
		return err
	}
	defer func() {
		s.mu.Lock()
		if s.st != nil {
			s.st.Close()
		}
		s.mu.Unlock()
	}()

	wizard := wz.Handler()
	root := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/setup" || strings.HasPrefix(r.URL.Path, "/api/setup/") {
			wizard.ServeHTTP(w, r)
			return
		}
		(*s.handler.Load()).ServeHTTP(w, r)
	})
	srv := &http.Server{Addr: env("SPA_LISTEN", ":8080"), Handler: root, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 120 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdown) //nolint:errcheck
	}()
	slog.Info("keystone listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
