package totp

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1 (the key is "12345678901234567890", 8 digits).
func TestRFC6238Vectors(t *testing.T) {
	key := []byte("12345678901234567890")
	for _, v := range []struct {
		unix int64
		code string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		if got := hotp(key, uint64(v.unix/Period), 8); got != v.code {
			t.Errorf("T=%d: %s, want %s", v.unix, got, v.code)
		}
	}
}

// RFC 4226 appendix D (6 digits).
func TestRFC4226Vectors(t *testing.T) {
	key := []byte("12345678901234567890")
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for i, w := range want {
		if got := hotp(key, uint64(i), 6); got != w {
			t.Errorf("counter %d: %s, want %s", i, got, w)
		}
	}
}

func TestCheck(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	now := time.Unix(1111111109, 0)
	code, err := Code(secret, now)
	if err != nil || code != "081804" {
		t.Fatalf("code %q %v", code, err)
	}
	if step, ok := Check(secret, "081 804", now); !ok || step != 1111111109/30 {
		t.Fatalf("check: %d %v", step, ok)
	}
	if _, ok := Check(secret, code, now.Add(30*time.Second)); !ok {
		t.Fatal("the previous step must be accepted")
	}
	if _, ok := Check(secret, code, now.Add(95*time.Second)); ok {
		t.Fatal("a code three steps old was accepted")
	}
	if _, ok := Check(secret, "000000", now); ok {
		t.Fatal("a wrong code was accepted")
	}
	if _, ok := Check("not base32!", code, now); ok {
		t.Fatal("a broken secret was accepted")
	}
}

func TestSecretAndURI(t *testing.T) {
	s := NewSecret()
	if len(s) != 32 || s == NewSecret() {
		t.Fatalf("secret %q", s)
	}
	u := URI("Acme Corp", "jdoe", s)
	if !strings.HasPrefix(u, "otpauth://totp/Acme%20Corp:jdoe?") || !strings.Contains(u, "secret="+s) || !strings.Contains(u, "digits=6") || !strings.Contains(u, "period=30") {
		t.Fatalf("uri %s", u)
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes := NewRecoveryCodes(RecoveryCount)
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 11 || c[5] != '-' {
			t.Fatalf("code %q", c)
		}
		n, ok := NormalizeRecovery(strings.ToUpper(c))
		if !ok || len(n) != 10 || seen[n] {
			t.Fatalf("normalize %q: %q %v", c, n, ok)
		}
		seen[n] = true
	}
	if _, ok := NormalizeRecovery("123456"); ok {
		t.Fatal("a TOTP code is not a recovery code")
	}
	if !IsCode("123 456") || IsCode("12345a") {
		t.Fatal("IsCode")
	}
}
