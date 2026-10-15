package app

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/sbrw-evc/spa/internal/oidcx"
	"github.com/sbrw-evc/spa/internal/secrets"
)

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---- the RSA key that signs ID tokens (kept in the secret store, made on first use)

const signingPath = "oidc/signing"

type signingKeys struct {
	sec secrets.Store
	mu  sync.Mutex
	key *rsa.PrivateKey
	kid string
	old *rsa.PublicKey
	oid string
}

func (k *signingKeys) load(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.key != nil {
		return nil
	}
	m, err := k.sec.Get(ctx, signingPath)
	if errors.Is(err, secrets.ErrNotFound) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		m = map[string]string{"pem": encodeKey(priv), "kid": randomToken(9)}
		if err := k.sec.Put(ctx, signingPath, m); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	priv, err := decodeKey(m["pem"])
	if err != nil {
		return err
	}
	k.key, k.kid = priv, m["kid"]
	if m["previous_pem"] != "" {
		if old, err := decodeKey(m["previous_pem"]); err == nil {
			k.old, k.oid = &old.PublicKey, m["previous_kid"]
		}
	}
	return nil
}

// Rotate makes a new signing key; the previous one stays in the JWKS so tokens signed with it still verify.
func (k *signingKeys) Rotate(ctx context.Context) error {
	if err := k.load(ctx); err != nil {
		return err
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	m := map[string]string{"pem": encodeKey(priv), "kid": randomToken(9), "previous_pem": encodeKey(k.key), "previous_kid": k.kid}
	if err := k.sec.Put(ctx, signingPath, m); err != nil {
		return err
	}
	k.old, k.oid, k.key, k.kid = &k.key.PublicKey, k.kid, priv, m["kid"]
	return nil
}

func (k *signingKeys) Sign(ctx context.Context, claims any) (string, error) {
	if err := k.load(ctx); err != nil {
		return "", err
	}
	return oidcx.Sign(k.key, k.kid, claims)
}

func (k *signingKeys) JWKS(ctx context.Context) (map[string]any, error) {
	if err := k.load(ctx); err != nil {
		return nil, err
	}
	keys := []oidcx.JWK{oidcx.RSAJWK(k.kid, &k.key.PublicKey)}
	if k.old != nil {
		keys = append(keys, oidcx.RSAJWK(k.oid, k.old))
	}
	return map[string]any{"keys": keys}, nil
}

// Verify checks a token SPA signed (access tokens) and decodes its claims.
func (k *signingKeys) Verify(ctx context.Context, raw string, out any) error {
	if err := k.load(ctx); err != nil {
		return err
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return errors.New("malformed token")
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if b, err := base64.RawURLEncoding.DecodeString(parts[0]); err != nil || json.Unmarshal(b, &h) != nil {
		return errors.New("malformed token")
	}
	pub := &k.key.PublicKey
	if h.Kid != k.kid {
		if k.old == nil || h.Kid != k.oid {
			return errors.New("unknown key")
		}
		pub = k.old
	}
	if err := oidcx.VerifySignature(h.Alg, pub, parts[0]+"."+parts[1], parts[2]); err != nil {
		return err
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func encodeKey(k *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
}

func decodeKey(s string) (*rsa.PrivateKey, error) {
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		return nil, errors.New("signing key is damaged")
	}
	return x509.ParsePKCS1PrivateKey(b.Bytes)
}

// ---- signed, expiring values (authorize requests, provider state, password-change tickets)

const statePath = "oidc/state"

type stateKey struct {
	sec secrets.Store
	mu  sync.Mutex
	key []byte
}

func (s *stateKey) get(ctx context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key != nil {
		return s.key, nil
	}
	m, err := s.sec.Get(ctx, statePath)
	if errors.Is(err, secrets.ErrNotFound) {
		m = map[string]string{"key": randomToken(48)}
		if err := s.sec.Put(ctx, statePath, m); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	s.key = []byte(m["key"])
	return s.key, nil
}

// Seal signs v (with a purpose, so a value made for one use cannot serve another) for ttl.
func (s *stateKey) Seal(ctx context.Context, purpose string, v any, ttl time.Duration) (string, error) {
	key, err := s.get(ctx)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(struct {
		P string `json:"p"`
		E int64  `json:"e"`
		V any    `json:"v"`
	}{purpose, time.Now().Add(ttl).Unix(), v})
	if err != nil {
		return "", err
	}
	b := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(b))
	return b + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

var errState = errors.New("expired or changed")

// Open checks and decodes a value sealed for purpose.
func (s *stateKey) Open(ctx context.Context, purpose, token string, out any) error {
	key, err := s.get(ctx)
	if err != nil {
		return err
	}
	b, sig, ok := strings.Cut(token, ".")
	if !ok {
		return errState
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(b))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return errState
	}
	raw, err := base64.RawURLEncoding.DecodeString(b)
	if err != nil {
		return errState
	}
	var env struct {
		P string          `json:"p"`
		E int64           `json:"e"`
		V json.RawMessage `json:"v"`
	}
	if json.Unmarshal(raw, &env) != nil || env.P != purpose || env.E < time.Now().Unix() {
		return errState
	}
	return json.Unmarshal(env.V, out)
}
