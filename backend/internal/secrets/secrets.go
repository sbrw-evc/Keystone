// Package secrets keeps Keystone's secrets in OpenBao (KV v2): password hashes and their history, the secrets of
// authenticator apps and the recovery codes, the hashes of client secrets and federation tokens, the signing keys,
// directory bind passwords, provider client secrets, the Apple key and the PostgreSQL password. Keystone signs in to
// OpenBao with AppRole and renews its token.
//
// Sealed keeps secrets sealed with AES-256-GCM in the database, as Keystone did without OpenBao before; it is only
// read to move those secrets to OpenBao.
package secrets

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sbrw-evc/keystone/internal/store"
)

// ErrNotFound: no secret at the path.
var ErrNotFound = errors.New("secret not found")

type Store interface {
	Get(ctx context.Context, path string) (map[string]string, error)
	Put(ctx context.Context, path string, data map[string]string) error
	Delete(ctx context.Context, path string) error
	Kind() string
}

// Value reads one field; empty when the secret or the field is missing.
func Value(ctx context.Context, s Store, path, field string) string {
	m, err := s.Get(ctx, path)
	if err != nil {
		return ""
	}
	return m[field]
}

// ---- sealed in PostgreSQL (the source of the move to OpenBao)

type Sealed struct {
	db  *store.Store
	gcm cipher.AEAD
}

// NewSealed uses a 32-byte master key.
func NewSealed(db *store.Store, key []byte) (*Sealed, error) {
	if len(key) != 32 {
		return nil, errors.New("the master key must be 32 bytes (SPA_MASTER_KEY, base64)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealed{db: db, gcm: gcm}, nil
}

func (s *Sealed) Kind() string { return "database" }

func (s *Sealed) Get(ctx context.Context, path string) (map[string]string, error) {
	b, err := s.db.Sealed(ctx, path)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	n := s.gcm.NonceSize()
	if len(b) < n {
		return nil, errors.New("sealed secret is damaged")
	}
	plain, err := s.gcm.Open(nil, b[:n], b[n:], []byte(path))
	if err != nil {
		return nil, errors.New("sealed secret cannot be opened: wrong master key")
	}
	out := map[string]string{}
	return out, json.Unmarshal(plain, &out)
}

func (s *Sealed) Put(ctx context.Context, path string, data map[string]string) error {
	plain, err := json.Marshal(data)
	if err != nil {
		return err
	}
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	return s.db.PutSealed(ctx, path, append(nonce, s.gcm.Seal(nil, nonce, plain, []byte(path))...))
}

func (s *Sealed) Delete(ctx context.Context, path string) error { return s.db.DeleteSealed(ctx, path) }

// ---- OpenBao KV v2

// OpenBao is a KV v2 mount of OpenBao. It signs in with AppRole (role_id and the secret_id read from a file) or uses a
// fixed token, and keeps its token fresh: renewed at half of its lifetime, a new login when renewal is refused.
type OpenBao struct {
	Addr  string
	Mount string
	HTTP  *http.Client

	roleID       string
	secretIDFile string

	mu      sync.Mutex
	token   string
	renewAt time.Time // zero: a fixed token, never renewed
	now     func() time.Time
}

// NewOpenBao uses a fixed token (BAO_TOKEN of installations from before the setup wizard).
func NewOpenBao(addr, token, mount string) *OpenBao {
	b := newOpenBao(addr, mount)
	b.token = token
	return b
}

// NewOpenBaoAppRole signs in with AppRole; the secret_id is read from secretIDFile at every login.
func NewOpenBaoAppRole(addr, mount, roleID, secretIDFile string) *OpenBao {
	b := newOpenBao(addr, mount)
	b.roleID, b.secretIDFile = roleID, secretIDFile
	return b
}

func newOpenBao(addr, mount string) *OpenBao {
	if mount == "" {
		mount = "keystone"
	}
	return &OpenBao{Addr: strings.TrimRight(addr, "/"), Mount: strings.Trim(mount, "/"), HTTP: &http.Client{Timeout: 10 * time.Second}, now: time.Now}
}

func (b *OpenBao) Kind() string { return "openbao" }

func (b *OpenBao) approle() bool { return b.roleID != "" }

type authAnswer struct {
	Auth struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	} `json:"auth"`
}

func (b *OpenBao) raw(ctx context.Context, method, url, token string, body any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, b.Addr+url, rd)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	req.Header.Set("Content-Type", "application/json")
	return b.HTTP.Do(req)
}

func (b *OpenBao) authCall(ctx context.Context, url, token string, body any) (authAnswer, error) {
	var a authAnswer
	res, err := b.raw(ctx, http.MethodPost, url, token, body)
	if err != nil {
		return a, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return a, fmt.Errorf("openbao: %s: HTTP %d", url, res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(&a); err != nil {
		return a, err
	}
	if a.Auth.ClientToken == "" {
		return a, fmt.Errorf("openbao: %s gave no token", url)
	}
	return a, nil
}

// Login signs in with AppRole now (also a check of role_id and secret_id).
func (b *OpenBao) Login(ctx context.Context) error {
	raw, err := os.ReadFile(b.secretIDFile)
	if err != nil {
		return fmt.Errorf("openbao: the AppRole secret_id: %w", err)
	}
	a, err := b.authCall(ctx, "/v1/auth/approle/login", "", map[string]string{"role_id": b.roleID, "secret_id": strings.TrimSpace(string(raw))})
	if err != nil {
		return err
	}
	b.setToken(a)
	return nil
}

func (b *OpenBao) setToken(a authAnswer) {
	b.token = a.Auth.ClientToken
	ttl := time.Duration(a.Auth.LeaseDuration) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	b.renewAt = b.now().Add(ttl / 2)
}

// currentToken returns a token that is fresh: with AppRole it renews or logs in again past half of the lifetime.
func (b *OpenBao) currentToken(ctx context.Context) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.approle() {
		return b.token, nil
	}
	if b.token == "" {
		return b.token, b.Login(ctx)
	}
	if b.now().Before(b.renewAt) {
		return b.token, nil
	}
	if a, err := b.authCall(ctx, "/v1/auth/token/renew-self", b.token, map[string]any{}); err == nil {
		b.setToken(a)
		return b.token, nil
	}
	if err := b.Login(ctx); err != nil {
		return "", err
	}
	return b.token, nil
}

// forget drops the token after OpenBao refused it, so the next call logs in again.
func (b *OpenBao) forget(token string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.approle() && b.token == token {
		b.token = ""
	}
}

func (b *OpenBao) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		token, err := b.currentToken(ctx)
		if err != nil {
			return nil, err
		}
		res, err := b.raw(ctx, method, "/v1/"+b.Mount+path, token, body)
		if err != nil {
			return nil, err
		}
		if res.StatusCode == http.StatusForbidden && b.approle() && attempt == 0 {
			res.Body.Close()
			b.forget(token)
			continue
		}
		return res, nil
	}
}

func (b *OpenBao) Get(ctx context.Context, path string) (map[string]string, error) {
	res, err := b.do(ctx, http.MethodGet, "/data/"+path, nil)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openbao: HTTP %d", res.StatusCode)
	}
	var v struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return nil, err
	}
	if v.Data.Data == nil {
		return nil, ErrNotFound
	}
	return v.Data.Data, nil
}

func (b *OpenBao) Put(ctx context.Context, path string, data map[string]string) error {
	res, err := b.do(ctx, http.MethodPost, "/data/"+path, map[string]any{"data": data})
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode >= 300 {
		return fmt.Errorf("openbao: HTTP %d", res.StatusCode)
	}
	return nil
}

func (b *OpenBao) Delete(ctx context.Context, path string) error {
	res, err := b.do(ctx, http.MethodDelete, "/metadata/"+path, nil)
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode != http.StatusNotFound {
		return fmt.Errorf("openbao: HTTP %d", res.StatusCode)
	}
	return nil
}

// Check writes, reads and deletes a probe secret: the address, the credentials and the policy all work.
func Check(ctx context.Context, s Store) error {
	probe := "keystone/probe"
	want := map[string]string{"at": time.Now().UTC().Format(time.RFC3339Nano)}
	if err := s.Put(ctx, probe, want); err != nil {
		return err
	}
	got, err := s.Get(ctx, probe)
	if err != nil {
		return err
	}
	if got["at"] != want["at"] {
		return errors.New("openbao: the probe secret reads back differently")
	}
	return s.Delete(ctx, probe)
}

// ---- in memory (tests)

type Memory struct {
	mu sync.Mutex
	m  map[string]map[string]string
}

func NewMemory() *Memory { return &Memory{m: map[string]map[string]string{}} }

func (m *Memory) Kind() string { return "memory" }

func (m *Memory) Get(_ context.Context, path string) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.m[path]
	if !ok {
		return nil, ErrNotFound
	}
	out := map[string]string{}
	for k, x := range v {
		out[k] = x
	}
	return out, nil
}

func (m *Memory) Put(_ context.Context, path string, data map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := map[string]string{}
	for k, x := range data {
		c[k] = x
	}
	m.m[path] = c
	return nil
}

func (m *Memory) Delete(_ context.Context, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.m, path)
	return nil
}

// Paths lists the stored paths (tests).
func (m *Memory) Paths() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.m))
	for p := range m.m {
		out = append(out, p)
	}
	return out
}
