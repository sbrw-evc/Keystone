//go:build spae2e

// Package spae2e runs Umbrella Monitoring for the end-to-end check of SPA (scripts/e2e-monitoring.mjs).
//
// The script copies this file into a snapshot of the Umbrella Monitoring repository
// (app/backend/cmd/spa-e2e/) and builds it as a test binary: a test, because OpenBao is the fake
// OpenBao of Monitoring's own tests (secretstest), which needs a *testing.T. Everything else is
// what cmd/umbrella does after its setup wizard: the state in PostgreSQL, the system and preset
// roles, the migrations, the application with its background work (the SPA schedule among it) and
// the built web UI. Nothing in the Monitoring repository is changed.
//
// Environment: UM_ADDR (listen address), UM_POSTGRES (host:port:user:password:database, an
// empty database), UM_WEB_DIR (the built web UI), SPA_CONNECTION_KEY and SPA_PUBLIC_URL as
// Monitoring reads them.
package spae2e

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sbrw-evc/umbrella-monitoring/app/backend/internal/app"
	"github.com/sbrw-evc/umbrella-monitoring/app/backend/internal/auth"
	"github.com/sbrw-evc/umbrella-monitoring/app/backend/internal/config"
	"github.com/sbrw-evc/umbrella-monitoring/app/backend/internal/httpx"
	"github.com/sbrw-evc/umbrella-monitoring/app/backend/internal/ingest"
	"github.com/sbrw-evc/umbrella-monitoring/app/backend/internal/secrets/secretstest"
	"github.com/sbrw-evc/umbrella-monitoring/app/backend/internal/spa"
	"github.com/sbrw-evc/umbrella-monitoring/app/backend/internal/store"
)

func pgConfig(t *testing.T) store.PGConfig {
	p := strings.Split(os.Getenv("UM_POSTGRES"), ":")
	if len(p) != 5 {
		t.Skip("UM_POSTGRES is not set (host:port:user:password:database)")
	}
	port, _ := strconv.Atoi(p[1])
	return store.PGConfig{Host: p[0], Port: port, User: p[2], Password: p[3], Database: p[4], SSLMode: "disable"}
}

func TestServe(t *testing.T) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pg := pgConfig(t)
	_, vault := secretstest.New(t)

	backend, err := store.OpenPostgres(ctx, pg)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	st := store.New()
	if _, err := st.Attach(ctx, backend); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	st.Write(func(d *store.Data) { // what the setup wizard does on a new install
		d.Settings.DefaultLocale = "en"
		d.Settings.SetupAt = now
		d.Settings.SetupBy = "setup"
		d.EnsureSystemRoles(now)
		d.EnsurePresetRoles("en", now)
	})
	if err := st.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := app.Migrate(ctx, st, vault); err != nil {
		t.Fatal(err)
	}
	stored := pg
	stored.Password = ""
	a := app.New(app.Options{Version: "spa-e2e", Web: httpx.Web(os.Getenv("UM_WEB_DIR")), Ingest: ingest.DefaultConfig(),
		SPAKey: os.Getenv(spa.Env), SPAPublicURL: os.Getenv(spa.EnvPublicURL)},
		app.Deps{Config: config.File{Postgres: stored, CompletedAt: &now}, Vault: vault, Backend: backend, Store: st, Sessions: auth.NewSessions()})

	bg, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); vault.Run(bg) }()
	go func() { defer wg.Done(); st.Run(bg, 2*time.Second) }()
	go func() { defer wg.Done(); a.Run(bg) }()

	ln, err := net.Listen("tcp", os.Getenv("UM_ADDR"))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: a.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = srv.Shutdown(sctx)
	}()
	fmt.Println("UMBRELLA READY", ln.Addr().String())
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Error(err)
	}
	cancel()
	wg.Wait()
}
