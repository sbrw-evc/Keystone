// Package secrets keeps Keystone's secrets — the signing keys, directory bind passwords, provider client secrets and
// the Apple key — in OpenBao (KV v2) when it is configured, otherwise sealed with AES-256-GCM in the database.
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
	"strings"
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

// ---- sealed in PostgreSQL

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

type OpenBao struct {
	Addr  string
	Token string
	Mount string
	HTTP  *http.Client
}

func NewOpenBao(addr, token, mount string) *OpenBao {
	if mount == "" {
		mount = "spa"
	}
	return &OpenBao{Addr: strings.TrimRight(addr, "/"), Token: token, Mount: strings.Trim(mount, "/"), HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func (b *OpenBao) Kind() string { return "openbao" }

func (b *OpenBao) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, b.Addr+"/v1/"+b.Mount+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", b.Token)
	req.Header.Set("Content-Type", "application/json")
	return b.HTTP.Do(req)
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

// ---- in memory (tests)

type Memory struct{ m map[string]map[string]string }

func NewMemory() *Memory { return &Memory{m: map[string]map[string]string{}} }

func (m *Memory) Kind() string { return "memory" }

func (m *Memory) Get(_ context.Context, path string) (map[string]string, error) {
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
	c := map[string]string{}
	for k, x := range data {
		c[k] = x
	}
	m.m[path] = c
	return nil
}

func (m *Memory) Delete(_ context.Context, path string) error {
	delete(m.m, path)
	return nil
}
