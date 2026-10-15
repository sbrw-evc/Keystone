// Command spa runs SPA — the Single Point of Authorization of the Umbrella family.
//
// Environment:
//
//	SPA_DATABASE_URL     PostgreSQL connection string (required)
//	SPA_PUBLIC_URL       the address of SPA and its OpenID Connect issuer, e.g. https://spa.example.com
//	SPA_LISTEN           listen address (default :8080)
//	SPA_MASTER_KEY       base64 of 32 bytes that seals secrets in the database (or SPA_MASTER_KEY_FILE)
//	BAO_ADDR, BAO_TOKEN  keep secrets in OpenBao instead (KV v2, mount BAO_MOUNT, default "spa")
//	SPA_ADMIN_USERNAME   first administrator, created when SPA has no people (default "admin")
//	SPA_ADMIN_PASSWORD   their initial password, to be changed at first sign-in
//	SPA_SESSION_HOURS    SPA session lifetime (default 12)
//	SPA_TRUSTED_PROXIES  comma-separated networks whose X-Forwarded-For/-Host are trusted
//	SPA_WEB_DIR          the built web app (default ./web)
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sbrw-evc/spa/internal/app"
	"github.com/sbrw-evc/spa/internal/secrets"
	"github.com/sbrw-evc/spa/internal/store"
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
		slog.Error("spa stopped", "err", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dbURL := env("SPA_DATABASE_URL", "")
	if dbURL == "" {
		return errors.New("SPA_DATABASE_URL is required")
	}
	st, err := store.Open(ctx, dbURL)
	if err != nil {
		return err
	}
	defer st.Close()

	var sec secrets.Store
	if addr := env("BAO_ADDR", ""); addr != "" {
		sec = secrets.NewOpenBao(addr, env("BAO_TOKEN", ""), env("BAO_MOUNT", "spa"))
	} else {
		raw := env("SPA_MASTER_KEY", "")
		if f := env("SPA_MASTER_KEY_FILE", ""); f != "" {
			b, err := os.ReadFile(f)
			if err != nil {
				return err
			}
			raw = strings.TrimSpace(string(b))
		}
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(key) != 32 {
			return errors.New("set SPA_MASTER_KEY to base64 of 32 random bytes (openssl rand -base64 32), or configure OpenBao")
		}
		if sec, err = secrets.NewSealed(st, key); err != nil {
			return err
		}
	}

	hours, _ := strconv.Atoi(env("SPA_SESSION_HOURS", "12"))
	cfg := app.Config{PublicURL: env("SPA_PUBLIC_URL", ""), SessionHours: hours, WebDir: env("SPA_WEB_DIR", "web")}
	for _, n := range strings.Split(env("SPA_TRUSTED_PROXIES", ""), ",") {
		if n = strings.TrimSpace(n); n == "" {
			continue
		}
		if !strings.Contains(n, "/") {
			if strings.Contains(n, ":") {
				n += "/128"
			} else {
				n += "/32"
			}
		}
		_, ipn, err := net.ParseCIDR(n)
		if err != nil {
			return errors.New("SPA_TRUSTED_PROXIES: " + err.Error())
		}
		cfg.TrustedProxies = append(cfg.TrustedProxies, ipn)
	}
	if cfg.PublicURL == "" {
		slog.Warn("SPA_PUBLIC_URL is not set: the issuer follows the request address; set it in production")
	}

	a := app.New(cfg, st, sec)
	if err := a.Bootstrap(ctx, env("SPA_ADMIN_USERNAME", "admin"), env("SPA_ADMIN_PASSWORD", "")); err != nil {
		return err
	}
	go a.Housekeeping(ctx)

	srv := &http.Server{Addr: env("SPA_LISTEN", ":8080"), Handler: a.Handler(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdown) //nolint:errcheck
	}()
	slog.Info("spa listening", "addr", srv.Addr, "issuer", cfg.PublicURL, "secrets", sec.Kind())
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
