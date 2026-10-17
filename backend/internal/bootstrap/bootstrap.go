// Package bootstrap is what Keystone needs to reach its storage: <data>/bootstrap.json (0600) with the address of
// PostgreSQL without its password, the address of OpenBao and the AppRole role_id; the secret_id in
// <data>/approle/secret_id (0600) — the only secret on disk, the key to all the others. The PostgreSQL password is in
// OpenBao (infra/postgres). The setup wizard writes these files; without them Keystone starts in the setup mode.
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/sbrw-evc/keystone/internal/secrets"
	"github.com/sbrw-evc/keystone/internal/store"
)

// PostgresSecret is the path of the PostgreSQL password in OpenBao ({"password"}).
const PostgresSecret = "infra/postgres"

// DefaultMount is the KV v2 mount of a new installation.
const DefaultMount = "keystone"

type File struct {
	Postgres Postgres `json:"postgres"`
	OpenBao  OpenBao  `json:"openbao"`
}

type Postgres struct {
	// DSN is a postgres:// address without the password.
	DSN string `json:"dsn"`
}

type OpenBao struct {
	Addr  string `json:"addr"`
	Mount string `json:"mount"`
	// Auth: "approle" (role_id + the secret_id in SecretIDFile) or "token" (a fixed token in TokenFile, taken over from
	// BAO_TOKEN of an installation from before the wizard).
	Auth         string `json:"auth"`
	RoleID       string `json:"role_id,omitempty"`
	SecretIDFile string `json:"secret_id_file,omitempty"`
	TokenFile    string `json:"token_file,omitempty"`
}

func Path(dir string) string { return filepath.Join(dir, "bootstrap.json") }

// Load reads bootstrap.json; nil when there is none.
func Load(dir string) (*File, error) {
	raw, err := os.ReadFile(Path(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", Path(dir), err)
	}
	return &f, nil
}

// Save writes bootstrap.json (0600).
func Save(dir string, f *File) error {
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return WritePrivate(Path(dir), append(raw, '\n'))
}

// WritePrivate writes a file only its owner reads (0600, the directory 0700), replacing it at once.
func WritePrivate(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Secrets is the secret store of the file.
func (f *File) Secrets() (*secrets.OpenBao, error) {
	switch f.OpenBao.Auth {
	case "approle", "":
		if f.OpenBao.RoleID == "" || f.OpenBao.SecretIDFile == "" {
			return nil, errors.New("bootstrap.json: openbao.role_id and openbao.secret_id_file are required")
		}
		return secrets.NewOpenBaoAppRole(f.OpenBao.Addr, f.OpenBao.Mount, f.OpenBao.RoleID, f.OpenBao.SecretIDFile), nil
	case "token":
		raw, err := os.ReadFile(f.OpenBao.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("the OpenBao token: %w", err)
		}
		return secrets.NewOpenBao(f.OpenBao.Addr, strings.TrimSpace(string(raw)), f.OpenBao.Mount), nil
	}
	return nil, fmt.Errorf("bootstrap.json: unknown openbao.auth %q", f.OpenBao.Auth)
}

// Open connects to OpenBao, takes the PostgreSQL password from it and opens the database (applying migrations).
func (f *File) Open(ctx context.Context) (*store.Store, *secrets.OpenBao, error) {
	sec, err := f.Secrets()
	if err != nil {
		return nil, nil, err
	}
	m, err := sec.Get(ctx, PostgresSecret)
	if err != nil && !errors.Is(err, secrets.ErrNotFound) {
		return nil, nil, fmt.Errorf("OpenBao (%s): %w", f.OpenBao.Addr, err)
	}
	st, err := store.OpenPassword(ctx, f.Postgres.DSN, m["password"])
	if err != nil {
		return nil, nil, err
	}
	return st, sec, nil
}

// SplitDSN takes the password out of a postgres:// address.
func SplitDSN(dsn string) (clean, password string, err error) {
	u, err := url.Parse(strings.TrimSpace(dsn))
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" {
		return "", "", errors.New("the database address must look like postgres://user@host:5432/database")
	}
	if u.User != nil {
		password, _ = u.User.Password()
		u.User = url.User(u.User.Username())
	}
	return u.String(), password, nil
}

// BuildDSN makes a postgres:// address (without a password) from its parts.
func BuildDSN(host string, port int, database, user, sslmode string) string {
	if port == 0 {
		port = 5432
	}
	if sslmode == "" {
		sslmode = "disable"
	}
	u := url.URL{Scheme: "postgres", User: url.User(user), Host: fmt.Sprintf("%s:%d", host, port), Path: "/" + database,
		RawQuery: url.Values{"sslmode": {sslmode}}.Encode()}
	return u.String()
}
