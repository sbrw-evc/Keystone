package app_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func (h *harness) discoveryIssuer(header map[string]string) string {
	h.t.Helper()
	req, _ := http.NewRequest("GET", h.url+"/.well-known/openid-configuration", nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	var d struct {
		Issuer string `json:"issuer"`
	}
	json.NewDecoder(res.Body).Decode(&d) //nolint:errcheck
	return d.Issuer
}

// The public address, the trusted proxies and the session lifetime come from the settings and apply at once.
func TestGeneralSettings(t *testing.T) {
	h := newHarness(t)
	admin := h.adminBrowser()
	put := func(general map[string]any) (int, apiErr) {
		var e apiErr
		var cur struct {
			General  map[string]any `json:"general"`
			Passkeys map[string]any `json:"passkeys"`
		}
		h.call(admin, "GET", "/api/v1/settings/general", nil, &cur)
		for k, v := range general {
			cur.General[k] = v
		}
		code := h.call(admin, "PUT", "/api/v1/settings/general", map[string]any{"general": cur.General, "passkeys": cur.Passkeys}, &e)
		return code, e
	}
	if got := h.discoveryIssuer(nil); got != h.url {
		t.Fatalf("issuer %q", got)
	}
	if code, e := put(map[string]any{"public_url": "ftp://x"}); code != http.StatusBadRequest || e.Code != "invalid_public_url" {
		t.Fatalf("a bad address: %d %+v", code, e)
	}
	if code, e := put(map[string]any{"trusted_proxies": []string{"10.0.0.0/33"}}); code != http.StatusBadRequest || e.Code != "invalid_proxy" {
		t.Fatalf("a bad network: %d %+v", code, e)
	}

	// without a public address the issuer follows the request; X-Forwarded-Host only from a trusted proxy
	if code, e := put(map[string]any{"public_url": ""}); code != http.StatusOK {
		t.Fatalf("clear the address: %d %+v", code, e)
	}
	fwd := map[string]string{"X-Forwarded-Host": "id.example.net", "X-Forwarded-Proto": "https"}
	if got := h.discoveryIssuer(fwd); got != "https://"+strings.TrimPrefix(h.url, "http://") {
		t.Fatalf("an untrusted proxy was believed: %q", got)
	}
	var steps struct {
		Steps []struct {
			ID   string `json:"id"`
			Done bool   `json:"done"`
		} `json:"steps"`
	}
	h.call(admin, "GET", "/api/v1/onboarding", nil, &steps)
	if steps.Steps[0].ID != "public_url" || steps.Steps[0].Done {
		t.Fatalf("first steps: %+v", steps.Steps)
	}
	if code, e := put(map[string]any{"trusted_proxies": []string{"127.0.0.1", "10.0.0.0/8"}, "session_hours": 2}); code != http.StatusOK {
		t.Fatalf("trust the proxy: %d %+v", code, e)
	}
	if got := h.discoveryIssuer(fwd); got != "https://id.example.net" {
		t.Fatalf("the trusted proxy was not believed: %q", got)
	}

	// the session lifetime
	c := h.browser()
	req, _ := http.NewRequest("POST", h.url+"/api/v1/auth/password", jsonBody(map[string]string{"username": "admin", "password": "Correct-Horse-9!"}))
	req.Header.Set("X-Requested-With", "spa")
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	var expires time.Time
	for _, ck := range res.Cookies() {
		if ck.Name == "spa_session" {
			expires = ck.Expires
		}
	}
	if d := time.Until(expires); d < 110*time.Minute || d > 130*time.Minute {
		t.Fatalf("session lasts %v, want 2h", d)
	}

	// a public address: the issuer at once, and the first step is done
	if code, e := put(map[string]any{"public_url": "https://id.example.com/"}); code != http.StatusOK {
		t.Fatalf("set the address: %d %+v", code, e)
	}
	if got := h.discoveryIssuer(fwd); got != "https://id.example.com" {
		t.Fatalf("issuer %q", got)
	}
}

func jsonBody(v any) *bytes.Reader {
	b, _ := json.Marshal(v)
	return bytes.NewReader(b)
}
