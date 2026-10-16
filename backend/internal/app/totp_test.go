package app_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sbrw-evc/keystone/internal/totp"
)

func code(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	c, err := totp.Code(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type totpSetup struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
	QR     string `json:"qr"`
}

type signedInOut struct {
	User struct {
		Username      string `json:"username"`
		SessionMethod string `json:"session_method"`
		TOTP          bool   `json:"totp"`
	} `json:"user"`
	Next          string   `json:"next"`
	RecoveryCodes []string `json:"recovery_codes"`
}

func TestTOTP(t *testing.T) {
	h := newHarness(t)
	admin := h.adminBrowser()
	const pw = "Correct-Horse-9!"

	var state struct {
		Enabled   bool `json:"enabled"`
		Available bool `json:"available"`
		Required  bool `json:"required"`
		Left      int  `json:"recovery_codes_left"`
	}
	if code := h.call(admin, "GET", "/api/v1/me/totp", nil, &state); code != 200 || state.Enabled || !state.Available {
		t.Fatalf("state: %d %+v", code, state)
	}

	// set-up: QR code and secret, confirmed with a code, recovery codes once
	var s totpSetup
	if c := h.call(admin, "POST", "/api/v1/me/totp/setup", map[string]any{}, &s); c != 200 || len(s.Secret) != 32 ||
		!strings.HasPrefix(s.QR, "data:image/png;base64,") || !strings.HasPrefix(s.URI, "otpauth://totp/Keystone:admin?") {
		t.Fatalf("setup: %d %+v", c, s)
	}
	var e apiErr
	if c := h.call(admin, "POST", "/api/v1/me/totp/setup/confirm", map[string]string{"code": "12345"}, &e); c != http.StatusUnauthorized || e.Code != "wrong_code" {
		t.Fatalf("wrong code: %d %+v", c, e)
	}
	now := time.Now()
	var conf struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if c := h.call(admin, "POST", "/api/v1/me/totp/setup/confirm", map[string]string{"code": code(t, s.Secret, now)}, &conf); c != 200 || len(conf.RecoveryCodes) != 10 {
		t.Fatalf("confirm: %d %+v", c, conf)
	}
	if c := h.call(admin, "GET", "/api/v1/me/totp", nil, &state); c != 200 || !state.Enabled || state.Left != 10 {
		t.Fatalf("state after setup: %+v", state)
	}

	// sign-in: the password, then the code; a used code does not work twice
	signIn := func() (*http.Client, string) {
		b := h.browser()
		var e apiErr
		if c := h.call(b, "POST", "/api/v1/auth/password", map[string]string{"username": "admin", "password": pw}, &e); c != http.StatusConflict || e.Code != "totp_required" {
			t.Fatalf("password step: %d %+v", c, e)
		}
		return b, e.Extra["ticket"].(string)
	}
	b, ticket := signIn()
	if c := h.call(b, "GET", "/api/v1/me", nil, nil); c != http.StatusUnauthorized {
		t.Fatalf("a session before the code: %d", c)
	}
	if c := h.call(b, "POST", "/api/v1/auth/totp", map[string]string{"ticket": ticket, "code": code(t, s.Secret, now)}, &e); c != http.StatusUnauthorized || e.Code != "wrong_code" {
		t.Fatalf("a replayed code: %d %+v", c, e)
	}
	var out signedInOut
	if c := h.call(b, "POST", "/api/v1/auth/totp", map[string]string{"ticket": ticket, "code": code(t, s.Secret, now.Add(30*time.Second))}, &out); c != 200 || out.User.Username != "admin" || !out.User.TOTP {
		t.Fatalf("code step: %d %+v", c, out)
	}
	var sessions []struct {
		Current bool `json:"current"`
		MFA     bool `json:"mfa"`
	}
	h.call(b, "GET", "/api/v1/me/sessions", nil, &sessions)
	for _, x := range sessions {
		if x.Current && !x.MFA {
			t.Fatalf("the session is not two-factor: %+v", sessions)
		}
	}

	// a recovery code works once
	b, ticket = signIn()
	if c := h.call(b, "POST", "/api/v1/auth/totp", map[string]string{"ticket": ticket, "code": strings.ToUpper(conf.RecoveryCodes[0])}, &out); c != 200 {
		t.Fatalf("recovery code: %d", c)
	}
	b, ticket = signIn()
	if c := h.call(b, "POST", "/api/v1/auth/totp", map[string]string{"ticket": ticket, "code": conf.RecoveryCodes[0]}, &e); c != http.StatusUnauthorized {
		t.Fatalf("a used recovery code: %d %+v", c, e)
	}
	if c := h.call(b, "POST", "/api/v1/auth/totp", map[string]string{"ticket": "forged", "code": conf.RecoveryCodes[1]}, &e); c != http.StatusBadRequest || e.Code != "ticket_expired" {
		t.Fatalf("a forged ticket: %d %+v", c, e)
	}

	// turning it off needs a current code (here a recovery code)
	if c := h.call(admin, "POST", "/api/v1/me/totp/disable", map[string]string{"code": "000000"}, &e); c != http.StatusUnauthorized {
		t.Fatalf("disable with a wrong code: %d", c)
	}
	if c := h.call(admin, "POST", "/api/v1/me/totp/disable", map[string]string{"code": conf.RecoveryCodes[1]}, nil); c != 200 {
		t.Fatalf("disable: %d", c)
	}
	var signed signedInOut
	if c := h.call(h.browser(), "POST", "/api/v1/auth/password", map[string]string{"username": "admin", "password": pw}, &signed); c != 200 || signed.User.TOTP {
		t.Fatalf("sign-in without a second factor: %d %+v", c, signed)
	}

	// the policy requires a second factor of administrators: set up during the sign-in
	pol := map[string]any{"min_length": 12, "require_digits": true, "min_digits": 1, "require_special": true, "min_special": 1,
		"require_mixed_case": true, "letters": "latin", "history_count": 3, "block_common": true, "lockout_attempts": 3, "lockout_minutes": 5,
		"second_factor": "admins"}
	if c := h.call(admin, "PUT", "/api/v1/settings/password-policy", pol, nil); c != 200 {
		t.Fatalf("policy: %d", c)
	}
	pol["second_factor"] = "sometimes"
	if c := h.call(admin, "PUT", "/api/v1/settings/password-policy", pol, &e); c != http.StatusBadRequest || e.Code != "invalid_policy" {
		t.Fatalf("a wrong second_factor: %d", c)
	}
	b = h.browser()
	if c := h.call(b, "POST", "/api/v1/auth/password", map[string]string{"username": "admin", "password": pw}, &e); c != http.StatusConflict || e.Code != "totp_setup_required" {
		t.Fatalf("setup required: %d %+v", c, e)
	}
	ticket = e.Extra["ticket"].(string)
	if c := h.call(b, "POST", "/api/v1/auth/totp/setup", map[string]string{"ticket": ticket}, &s); c != 200 || s.Secret == "" {
		t.Fatalf("setup during sign-in: %d", c)
	}
	if c := h.call(b, "POST", "/api/v1/auth/totp/setup/confirm", map[string]string{"ticket": ticket, "code": code(t, s.Secret, time.Now())}, &out); c != 200 ||
		len(out.RecoveryCodes) != 10 || !out.User.TOTP || out.Next != "/" {
		t.Fatalf("confirm during sign-in: %d %+v", c, out)
	}
	if c := h.call(b, "POST", "/api/v1/me/totp/disable", map[string]string{"code": out.RecoveryCodes[0]}, &e); c != http.StatusConflict || e.Code != "totp_required_by_policy" {
		t.Fatalf("disable under the policy: %d %+v", c, e)
	}

	// wrong codes lock the account like wrong passwords (3 in this policy)
	b, ticket = signIn()
	for i := 0; i < 2; i++ {
		if c := h.call(b, "POST", "/api/v1/auth/totp", map[string]string{"ticket": ticket, "code": "000000"}, &e); c != http.StatusUnauthorized {
			t.Fatalf("wrong code %d: %d %+v", i, c, e)
		}
	}
	if c := h.call(b, "POST", "/api/v1/auth/totp", map[string]string{"ticket": ticket, "code": "000000"}, &e); c != http.StatusForbidden || e.Code != "locked" {
		t.Fatalf("lockout: %d %+v", c, e)
	}
	if c := h.call(b, "POST", "/api/v1/auth/totp", map[string]string{"ticket": ticket, "code": out.RecoveryCodes[1]}, &e); c != http.StatusForbidden || e.Code != "locked" {
		t.Fatalf("a locked account took a code: %d %+v", c, e)
	}

	// the administrator removes a lost authenticator app
	var me struct {
		ID string `json:"id"`
	}
	h.call(admin, "GET", "/api/v1/me", nil, &me)
	if c := h.call(admin, "DELETE", "/api/v1/users/"+me.ID+"/totp", nil, nil); c != http.StatusNoContent {
		t.Fatalf("reset: %d", c)
	}
	if c := h.call(admin, "DELETE", "/api/v1/users/"+me.ID+"/totp", nil, &e); c != http.StatusConflict {
		t.Fatalf("second reset: %d", c)
	}

	var log []struct {
		Action string `json:"action"`
	}
	h.call(admin, "GET", "/api/v1/audit?q=totp", nil, &log)
	seen := map[string]bool{}
	for _, l := range log {
		seen[l.Action] = true
	}
	for _, want := range []string{"totp.enabled", "totp.disabled", "totp.failed", "totp.recovery_used", "user.totp_reset"} {
		if !seen[want] {
			t.Errorf("no %s in the audit log: %v", want, seen)
		}
	}
}
