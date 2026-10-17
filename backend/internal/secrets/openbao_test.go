package secrets

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sbrw-evc/keystone/internal/bootstrap/baotest"
)

// AppRole: a login at the first call, renewal past half of the lifetime, a new login after OpenBao forgets the token.
func TestOpenBaoAppRole(t *testing.T) {
	bao := baotest.New()
	defer bao.Close()
	roleID, secretID := bao.SetUp("keystone")
	file := filepath.Join(t.TempDir(), "secret_id")
	os.WriteFile(file, []byte(secretID+"\n"), 0o600) //nolint:errcheck
	b := NewOpenBaoAppRole(bao.URL, "keystone", roleID, file)
	now := time.Now()
	b.now = func() time.Time { return now }
	ctx := context.Background()
	if err := Check(ctx, b); err != nil {
		t.Fatal(err)
	}
	if bao.Logins != 1 {
		t.Fatalf("logins %d", bao.Logins)
	}
	now = now.Add(40 * time.Minute) // past half of the hour: renewed, not a new login
	if err := b.Put(ctx, "a", map[string]string{"x": "1"}); err != nil {
		t.Fatal(err)
	}
	if bao.Logins != 1 {
		t.Fatalf("renewal logged in again: %d", bao.Logins)
	}
	b.mu.Lock()
	b.token = "forgotten-by-openbao"
	b.mu.Unlock()
	if v := Value(ctx, b, "a", "x"); v != "1" {
		t.Fatalf("after a refused token: %q", v)
	}
	if bao.Logins != 2 {
		t.Fatalf("logins %d", bao.Logins)
	}
}
