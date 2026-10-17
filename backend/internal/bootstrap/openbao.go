package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The OpenBao of the compose file is set up by the wizard through its HTTP API: initialisation (with the static seal
// of openbao/config.hcl it unseals itself; with the Shamir seal the wizard unseals it with the one key), the KV v2
// mount, AppRole with Keystone's policy and role. The root token and the recovery (or unseal) key are shown once and
// not kept: until the wizard finishes they wait in <data>/openbao-init.json (0600), so that a step failing after the
// initialisation can be repeated; the wizard deletes the file at its end.

const (
	approleRole = "keystone"
	policyName  = "keystone"
)

func policyHCL(mount string) string {
	return fmt.Sprintf(`path "%[1]s/data/*" { capabilities = ["create", "read", "update", "delete"] }
path "%[1]s/metadata/*" { capabilities = ["read", "list", "delete"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
`, mount)
}

// Shown is what the wizard shows once after initialising OpenBao.
type Shown struct {
	RootToken   string `json:"root_token"`
	RecoveryKey string `json:"recovery_key"`
}

// BaoInit sets up a built-in OpenBao.
type BaoInit struct {
	Addr    string
	Mount   string
	Dir     string        // the data directory: approle/secret_id and openbao-init.json go there
	Wait    time.Duration // between checks of the node becoming active (default 1 s)
	Retries int           // checks before giving up (default 60)
	HTTP    *http.Client
}

func (b *BaoInit) PendingPath() string { return filepath.Join(b.Dir, "openbao-init.json") }

// SecretIDPath is where the AppRole secret_id is kept.
func SecretIDPath(dir string) string { return filepath.Join(dir, "approle", "secret_id") }

func (b *BaoInit) client() *http.Client {
	if b.HTTP != nil {
		return b.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (b *BaoInit) call(ctx context.Context, method, path, token string, body any, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(b.Addr, "/")+path, rd)
	if err != nil {
		return 0, err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := b.client().Do(req)
	if err != nil {
		return 0, fmt.Errorf("OpenBao at %s does not answer: %w", b.Addr, err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if out != nil && len(raw) > 0 {
		json.Unmarshal(raw, out) //nolint:errcheck
	}
	return res.StatusCode, nil
}

func (b *BaoInit) must(ctx context.Context, method, path, token string, body any, out any) error {
	code, err := b.call(ctx, method, path, token, body, out)
	if err != nil {
		return err
	}
	if code != http.StatusOK && code != http.StatusNoContent {
		return fmt.Errorf("OpenBao: %s %s answered %d", method, path, code)
	}
	return nil
}

// Status tells whether OpenBao answers and is initialised.
func (b *BaoInit) Status(ctx context.Context) (initialized bool, err error) {
	var v struct {
		Initialized bool `json:"initialized"`
	}
	if err := b.must(ctx, http.MethodGet, "/v1/sys/init", "", nil, &v); err != nil {
		return false, err
	}
	return v.Initialized, nil
}

// Run initialises OpenBao (unless it is, then rootToken or the pending file is needed), sets up the mount and
// AppRole and writes the secret_id. It returns what to show once (empty when OpenBao was initialised before) and the
// role_id.
func (b *BaoInit) Run(ctx context.Context, rootToken string) (Shown, string, error) {
	if b.Mount == "" {
		b.Mount = DefaultMount
	}
	initialized, err := b.Status(ctx)
	if err != nil {
		return Shown{}, "", err
	}
	var shown Shown
	var unseal string
	switch {
	case !initialized:
		var seal struct {
			Type string `json:"type"`
		}
		if err := b.must(ctx, http.MethodGet, "/v1/sys/seal-status", "", nil, &seal); err != nil {
			return shown, "", err
		}
		req := map[string]int{"recovery_shares": 1, "recovery_threshold": 1}
		if seal.Type == "shamir" {
			req = map[string]int{"secret_shares": 1, "secret_threshold": 1}
		}
		var init struct {
			RootToken       string   `json:"root_token"`
			KeysB64         []string `json:"keys_base64"`
			RecoveryKeysB64 []string `json:"recovery_keys_base64"`
		}
		if err := b.must(ctx, http.MethodPut, "/v1/sys/init", "", req, &init); err != nil {
			return shown, "", fmt.Errorf("initialising OpenBao: %w", err)
		}
		shown.RootToken = init.RootToken
		if len(init.RecoveryKeysB64) > 0 {
			shown.RecoveryKey = init.RecoveryKeysB64[0]
		} else if len(init.KeysB64) > 0 {
			shown.RecoveryKey, unseal = init.KeysB64[0], init.KeysB64[0]
		}
		raw, _ := json.Marshal(shown)
		if err := WritePrivate(b.PendingPath(), raw); err != nil {
			return shown, "", err
		}
	case rootToken != "":
		shown.RootToken = rootToken
	default:
		raw, err := os.ReadFile(b.PendingPath())
		if err != nil {
			return shown, "", errors.New("OpenBao is initialised already: enter its root token")
		}
		if err := json.Unmarshal(raw, &shown); err != nil {
			return shown, "", err
		}
	}
	token := shown.RootToken
	if unseal != "" {
		if err := b.must(ctx, http.MethodPut, "/v1/sys/unseal", "", map[string]string{"key": unseal}, nil); err != nil {
			return shown, "", err
		}
	}
	if err := b.active(ctx); err != nil {
		return shown, "", err
	}

	var mounts map[string]any
	if err := b.must(ctx, http.MethodGet, "/v1/sys/mounts", token, nil, &mounts); err != nil {
		return shown, "", fmt.Errorf("%w (is the root token right?)", err)
	}
	if !hasKey(mounts, b.Mount+"/") {
		if err := b.must(ctx, http.MethodPost, "/v1/sys/mounts/"+b.Mount, token, map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}, nil); err != nil {
			return shown, "", err
		}
	}
	var auths map[string]any
	if err := b.must(ctx, http.MethodGet, "/v1/sys/auth", token, nil, &auths); err != nil {
		return shown, "", err
	}
	if !hasKey(auths, "approle/") {
		if err := b.must(ctx, http.MethodPost, "/v1/sys/auth/approle", token, map[string]string{"type": "approle"}, nil); err != nil {
			return shown, "", err
		}
	}
	if err := b.must(ctx, http.MethodPut, "/v1/sys/policies/acl/"+policyName, token, map[string]string{"policy": policyHCL(b.Mount)}, nil); err != nil {
		return shown, "", err
	}
	if err := b.must(ctx, http.MethodPost, "/v1/auth/approle/role/"+approleRole, token, map[string]any{
		"token_policies": []string{policyName}, "token_ttl": "1h", "token_max_ttl": "24h", "secret_id_ttl": "0", "secret_id_num_uses": 0}, nil); err != nil {
		return shown, "", err
	}
	var role struct {
		Data struct {
			RoleID   string `json:"role_id"`
			SecretID string `json:"secret_id"`
		} `json:"data"`
	}
	if err := b.must(ctx, http.MethodGet, "/v1/auth/approle/role/"+approleRole+"/role-id", token, nil, &role); err != nil {
		return shown, "", err
	}
	roleID := role.Data.RoleID
	if err := b.must(ctx, http.MethodPost, "/v1/auth/approle/role/"+approleRole+"/secret-id", token, map[string]any{}, &role); err != nil {
		return shown, "", err
	}
	if roleID == "" || role.Data.SecretID == "" {
		return shown, "", errors.New("OpenBao gave no AppRole credentials")
	}
	if err := WritePrivate(SecretIDPath(b.Dir), []byte(role.Data.SecretID+"\n")); err != nil {
		return shown, "", err
	}
	return shown, roleID, nil
}

// active waits until the node is unsealed and active (raft elects itself a moment after the unseal).
func (b *BaoInit) active(ctx context.Context) error {
	wait, tries := b.Wait, b.Retries
	if wait == 0 {
		wait = time.Second
	}
	if tries == 0 {
		tries = 60
	}
	for i := 0; i < tries; i++ {
		if code, err := b.call(ctx, http.MethodGet, "/v1/sys/health", "", nil, nil); err == nil && code == http.StatusOK {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	return errors.New("OpenBao does not become active: check openbao/keys/unseal.key and the log of the openbao container")
}

// hasKey looks for a mount in the answer of sys/mounts or sys/auth (at the top or under "data").
func hasKey(m map[string]any, key string) bool {
	if _, ok := m[key]; ok {
		return true
	}
	if d, ok := m["data"].(map[string]any); ok {
		_, ok := d[key]
		return ok
	}
	return false
}

// ForgetPending deletes the root token and recovery key kept until the end of the wizard.
func ForgetPending(dir string) {
	os.Remove(filepath.Join(dir, "openbao-init.json")) //nolint:errcheck
}
