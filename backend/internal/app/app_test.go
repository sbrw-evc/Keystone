package app_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sbrw-evc/keystone/internal/app"
	"github.com/sbrw-evc/keystone/internal/directory/directorytest"
	"github.com/sbrw-evc/keystone/internal/oidcx"
	"github.com/sbrw-evc/keystone/internal/passkey/passkeytest"
	"github.com/sbrw-evc/keystone/internal/secrets"
	"github.com/sbrw-evc/keystone/internal/store"
)

// testDB makes a fresh database on SPA_TEST_POSTGRES (a server URL with a database the test may create others from).
func testDB(t *testing.T) string {
	base := os.Getenv("SPA_TEST_POSTGRES")
	if base == "" {
		t.Skip("SPA_TEST_POSTGRES is not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	rand.Read(b) //nolint:errcheck
	name := "spa_test_" + hex.EncodeToString(b)
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)") //nolint:errcheck
		conn.Close(context.Background())
	})
	u, _ := url.Parse(base)
	u.Path = "/" + name
	return u.String()
}

type harness struct {
	t   *testing.T
	srv *httptest.Server
	st  *store.Store
	a   *app.App
	sec *secrets.Memory
	url string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, testDB(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	h := &harness{t: t, st: st}
	var a *app.App
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { a.Handler().ServeHTTP(w, r) }))
	t.Cleanup(h.srv.Close)
	// localhost: passkeys need https or localhost
	h.url = strings.Replace(h.srv.URL, "127.0.0.1", "localhost", 1)
	h.sec = secrets.NewMemory()
	a = app.New(app.Config{}, st, h.sec)
	h.a = a
	if _, err := a.UpdateGeneral(ctx, func(g *app.General) { g.PublicURL = h.url }); err != nil {
		t.Fatal(err)
	}
	if err := a.Bootstrap(ctx, "admin", "Initial-Passw0rd!"); err != nil {
		t.Fatal(err)
	}
	return h
}

// browser is a client with cookies that does not follow redirects.
func (h *harness) browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (h *harness) call(c *http.Client, method, path string, body any, out any) int {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, h.url+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "spa")
	req.Header.Set("Origin", h.url)
	res, err := c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			h.t.Fatalf("%s %s: %v: %s", method, path, err, raw)
		}
	}
	return res.StatusCode
}

type apiErr struct {
	Code       string         `json:"code"`
	Message    string         `json:"message"`
	Violations []string       `json:"violations"`
	Extra      map[string]any `json:"extra"`
}

// adminBrowser signs the bootstrap administrator in (changing the initial password).
func (h *harness) adminBrowser() *http.Client {
	c := h.browser()
	var e apiErr
	if code := h.call(c, "POST", "/api/v1/auth/password", map[string]string{"username": "admin", "password": "Initial-Passw0rd!"}, &e); code != http.StatusConflict || e.Code != "password_change_required" {
		h.t.Fatalf("first sign-in: %d %+v", code, e)
	}
	ticket := e.Extra["ticket"].(string)
	var weak apiErr
	if code := h.call(c, "POST", "/api/v1/auth/password/change", map[string]string{"ticket": ticket, "current": "Initial-Passw0rd!", "new": "password1"}, &weak); code != http.StatusBadRequest || len(weak.Violations) == 0 {
		h.t.Fatalf("weak password accepted: %d %+v", code, weak)
	}
	var res map[string]any
	if code := h.call(c, "POST", "/api/v1/auth/password/change", map[string]string{"ticket": ticket, "current": "Initial-Passw0rd!", "new": "Correct-Horse-9!"}, &res); code != http.StatusOK {
		h.t.Fatalf("password change: %d %v", code, res)
	}
	return c
}

func pkce() (verifier, challenge string) {
	verifier = oidcx.Random()
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestApplicationSignInAndFederation(t *testing.T) {
	h := newHarness(t)
	admin := h.adminBrowser()

	// a person, a group and an application that gives the group the operator role
	var user map[string]any
	if code := h.call(admin, "POST", "/api/v1/users", map[string]any{"username": "jdoe", "name": "John Doe", "email": "jdoe@example.com", "password": "Another-Secret-7"}, &user); code != http.StatusCreated {
		t.Fatalf("create user: %d %v", code, user)
	}
	var group map[string]any
	if code := h.call(admin, "POST", "/api/v1/groups", map[string]any{"name": "NOC", "members": []string{user["id"].(string)}}, &group); code != http.StatusCreated {
		t.Fatalf("create group: %d %v", code, group)
	}
	appURL := "https://nc.example.com"
	var conn app.Connection
	if code := h.call(admin, "POST", "/api/v1/applications", map[string]any{"type": "network-control", "base_url": appURL,
		"assignments": []map[string]string{{"subject_type": "group", "subject_id": group["id"].(string), "role": "operator"}}}, &conn); code != http.StatusCreated {
		t.Fatalf("connect app: %d", code)
	}
	if !strings.HasPrefix(conn.Key, "spa1.") {
		t.Fatalf("key %q", conn.Key)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(conn.Key, "spa1."))
	var key struct{ Issuer, ClientID, ClientSecret, Token string }
	json.Unmarshal(raw, &struct { //nolint:errcheck
		Issuer       *string `json:"issuer"`
		ClientID     *string `json:"client_id"`
		ClientSecret *string `json:"client_secret"`
		Token        *string `json:"token"`
	}{&key.Issuer, &key.ClientID, &key.ClientSecret, &key.Token})
	if key.Issuer != h.url || key.Token == "" {
		t.Fatalf("key content %+v", key)
	}

	// the application sends the person to Keystone; without a session the sign-in page takes the sealed request
	redirect := appURL + "/api/auth/spa/callback"
	verifier, challenge := pkce()
	q := url.Values{"client_id": {key.ClientID}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"openid profile email groups roles"},
		"state": {"st-1"}, "nonce": {"n-1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	person := h.browser()
	res, err := person.Get(h.url + "/oauth2/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	loc, _ := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusFound || loc.Path != "/signin" || loc.Query().Get("request") == "" {
		t.Fatalf("authorize: %d %s", res.StatusCode, loc)
	}
	var signed struct {
		Next string `json:"next"`
	}
	if code := h.call(person, "POST", "/api/v1/auth/password", map[string]string{"username": "jdoe", "password": "Another-Secret-7", "request": loc.Query().Get("request")}, &signed); code != http.StatusConflict {
		t.Fatalf("a new person must change the password set by the administrator: %d", code)
	}
	var e apiErr
	h.call(person, "POST", "/api/v1/auth/password", map[string]string{"username": "jdoe", "password": "Another-Secret-7", "request": loc.Query().Get("request")}, &e)
	if code := h.call(person, "POST", "/api/v1/auth/password/change", map[string]string{"ticket": e.Extra["ticket"].(string), "current": "Another-Secret-7", "new": "Brand-New-Secret-8"}, &signed); code != http.StatusOK {
		t.Fatalf("change: %d", code)
	}
	back, _ := url.Parse(signed.Next)
	if !strings.HasPrefix(signed.Next, redirect) || back.Query().Get("state") != "st-1" || back.Query().Get("code") == "" {
		t.Fatalf("next %q", signed.Next)
	}

	// the application redeems the code
	m, err := oidcx.Discover(context.Background(), h.url)
	if err != nil {
		t.Fatal(err)
	}
	client := oidcx.Client{Issuer: h.url, ClientID: key.ClientID, Secret: key.ClientSecret, RedirectURI: redirect}
	tok, err := oidcx.Exchange(context.Background(), client, m, back.Query().Get("code"), oidcx.Request{Verifier: "wrong-verifier"})
	if err == nil {
		t.Fatal("a wrong PKCE verifier was accepted")
	}
	// a code is single use, so get a new one with the Keystone session (no password this time)
	res, _ = person.Get(h.url + "/oauth2/authorize?" + q.Encode())
	back, _ = url.Parse(res.Header.Get("Location"))
	if back.Query().Get("code") == "" {
		t.Fatalf("SSO with a session: %s", back)
	}
	tok, err = oidcx.Exchange(context.Background(), client, m, back.Query().Get("code"), oidcx.Request{Verifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := oidcx.Verify(context.Background(), m, key.ClientID, tok.IDToken, "n-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if claims.String("preferred_username") != "jdoe" || strings.Join(claims.Strings("roles"), ",") != "operator" ||
		strings.Join(claims.Strings("groups"), ",") != "NOC" || strings.Join(claims.Strings("amr"), ",") != "pwd" {
		t.Fatalf("claims %v", claims)
	}

	// the federation API
	fed := func(method, path string, body any, etag string) (*http.Response, []byte) {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, h.url+path, rd)
		req.Header.Set("Authorization", "Bearer "+key.Token)
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res, b
	}
	res, body := fed("GET", "/api/spa/v1/users", nil, "")
	var users struct {
		Users []app.FederationUser `json:"users"`
	}
	json.Unmarshal(body, &users) //nolint:errcheck
	if res.StatusCode != 200 || len(users.Users) != 1 || users.Users[0].Username != "jdoe" || users.Users[0].Roles[0] != "operator" {
		t.Fatalf("users: %d %s", res.StatusCode, body)
	}
	if res2, _ := fed("GET", "/api/spa/v1/users", nil, res.Header.Get("ETag")); res2.StatusCode != http.StatusNotModified {
		t.Fatalf("ETag: %d", res2.StatusCode)
	}
	// the application publishes a catalogue without "operator": the role is no longer given out
	if res, body := fed("PUT", "/api/spa/v1/roles", map[string]any{"roles": []map[string]string{{"id": "admin", "name": "Administrator"}, {"id": "viewer", "name": "Viewer"}}}, ""); res.StatusCode != 200 {
		t.Fatalf("roles: %d %s", res.StatusCode, body)
	}
	res, body = fed("GET", "/api/spa/v1/users", nil, "")
	json.Unmarshal(body, &users) //nolint:errcheck
	if len(users.Users) != 0 {
		t.Fatalf("a role outside the catalogue was given out: %s", body)
	}
	res, _ = person.Get(h.url + "/oauth2/authorize?" + q.Encode())
	back, _ = url.Parse(res.Header.Get("Location"))
	if back.Query().Get("error") != "access_denied" {
		t.Fatalf("no role must be access_denied: %s", back)
	}
	if res, _ := (&http.Client{}).Do(mustReq("GET", h.url+"/api/spa/v1/config", "Bearer wrong")); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a wrong token: %d", res.StatusCode)
	}
}

func mustReq(method, u, auth string) *http.Request {
	r, _ := http.NewRequest(method, u, nil)
	r.Header.Set("Authorization", auth)
	return r
}

func TestPolicyLockoutAndHistory(t *testing.T) {
	h := newHarness(t)
	admin := h.adminBrowser()
	var pol map[string]any
	if code := h.call(admin, "PUT", "/api/v1/settings/password-policy", map[string]any{"min_length": 12, "require_digits": true, "min_digits": 1,
		"require_special": true, "min_special": 1, "require_mixed_case": true, "letters": "latin", "history_count": 3, "block_common": true,
		"lockout_attempts": 3, "lockout_minutes": 5}, &pol); code != 200 {
		t.Fatalf("policy: %d %v", code, pol)
	}
	// history: the administrator cannot go back to the previous password
	var e apiErr
	if code := h.call(admin, "POST", "/api/v1/auth/password/change", map[string]string{"current": "Correct-Horse-9!", "new": "Second-Secret-1"}, nil); code != 200 {
		t.Fatalf("change: %d", code)
	}
	if code := h.call(admin, "POST", "/api/v1/auth/password/change", map[string]string{"current": "Second-Secret-1", "new": "Correct-Horse-9!"}, &e); code != 400 || e.Violations[0] != "history" {
		t.Fatalf("history: %d %+v", code, e)
	}
	// lockout after three wrong passwords
	b := h.browser()
	for i := 0; i < 3; i++ {
		h.call(b, "POST", "/api/v1/auth/password", map[string]string{"username": "admin", "password": "wrong"}, nil)
	}
	if code := h.call(b, "POST", "/api/v1/auth/password", map[string]string{"username": "admin", "password": "Second-Secret-1"}, &e); code != http.StatusForbidden || e.Code != "locked" {
		t.Fatalf("lockout: %d %+v", code, e)
	}
	// CSRF: no header, no change
	req, _ := http.NewRequest("POST", h.url+"/api/v1/auth/password", strings.NewReader(`{}`))
	if res, _ := http.DefaultClient.Do(req); res.StatusCode != http.StatusForbidden {
		t.Fatalf("csrf: %d", res.StatusCode)
	}
}

func TestPasskeys(t *testing.T) {
	h := newHarness(t)
	admin := h.adminBrowser()
	auth := passkeytest.New(h.url, "localhost")
	var started struct {
		Ceremony string `json:"ceremony"`
		Options  any    `json:"options"`
	}
	if code := h.call(admin, "POST", "/api/v1/me/passkeys/begin", map[string]any{}, &started); code != 200 {
		t.Fatalf("begin: %d", code)
	}
	var pk map[string]any
	if code := h.call(admin, "POST", "/api/v1/me/passkeys/finish", map[string]any{"ceremony": started.Ceremony, "credential": auth.Create(started.Options), "name": "Laptop"}, &pk); code != http.StatusCreated {
		t.Fatalf("finish: %d %v", code, pk)
	}
	b := h.browser()
	if code := h.call(b, "POST", "/api/v1/auth/passkey/begin", map[string]any{}, &started); code != 200 {
		t.Fatalf("login begin: %d", code)
	}
	var signed struct {
		User map[string]any `json:"user"`
	}
	if code := h.call(b, "POST", "/api/v1/auth/passkey/finish", map[string]any{"ceremony": started.Ceremony, "credential": auth.Get(started.Options)}, &signed); code != 200 {
		t.Fatalf("login finish: %d", code)
	}
	if signed.User["username"] != "admin" || signed.User["session_method"] != "passkey" {
		t.Fatalf("signed in as %v", signed.User)
	}

	// a passkey counts as two factors: a policy that requires a second factor asks for no code after it
	if code := h.call(admin, "PUT", "/api/v1/settings/password-policy", map[string]any{"min_length": 12, "letters": "any", "second_factor": "everyone"}, nil); code != 200 {
		t.Fatalf("policy: %d", code)
	}
	b = h.browser()
	h.call(b, "POST", "/api/v1/auth/passkey/begin", map[string]any{}, &started)
	if code := h.call(b, "POST", "/api/v1/auth/passkey/finish", map[string]any{"ceremony": started.Ceremony, "credential": auth.Get(started.Options)}, &signed); code != 200 {
		t.Fatalf("passkey under a second-factor policy: %d", code)
	}
}

func TestDirectorySignInAndGroupRoles(t *testing.T) {
	h := newHarness(t)
	admin := h.adminBrowser()
	const base, svc, noc = "dc=example,dc=org", "cn=spa,ou=services,dc=example,dc=org", "cn=noc,ou=groups,dc=example,dc=org"
	ldapSrv := directorytest.Start(t,
		directorytest.Entry{DN: base},
		directorytest.Entry{DN: svc, Password: "svc-secret-1"},
		directorytest.Entry{DN: "uid=anna,ou=people,dc=example,dc=org", Password: "anna-pass-1", Attrs: map[string][]string{
			"objectClass": {"inetOrgPerson"}, "uid": {"anna"}, "cn": {"Anna Ivanova"}, "mail": {"anna@example.org"}}},
		directorytest.Entry{DN: noc, Attrs: map[string][]string{"objectClass": {"groupOfNames"}, "cn": {"noc"}, "member": {"uid=anna,ou=people,dc=example,dc=org"}}},
	)
	var res map[string]any
	if code := h.call(admin, "PUT", "/api/v1/settings/ldap", map[string]any{"config": map[string]any{"enabled": true, "kind": "openldap", "url": ldapSrv.URL,
		"bind_dn": svc, "base_dn": base}, "bind_password": "svc-secret-1"}, &res); code != 200 {
		t.Fatalf("ldap settings: %d %v", code, res)
	}
	// the directory group gets a role before anyone from it has signed in
	var group map[string]any
	if code := h.call(admin, "POST", "/api/v1/groups", map[string]any{"name": "NOC", "source": "ldap", "external_id": "CN=NOC,OU=Groups,DC=example,DC=org"}, &group); code != http.StatusCreated {
		t.Fatalf("directory group: %d %v", code, group)
	}
	var conn app.Connection
	if code := h.call(admin, "POST", "/api/v1/applications", map[string]any{"type": "inventory-db", "base_url": "https://inventory.example.com",
		"assignments": []map[string]string{{"subject_type": "group", "subject_id": group["id"].(string), "role": "editor"}}}, &conn); code != http.StatusCreated {
		t.Fatalf("connect: %d", code)
	}
	// "inventory-db" is the type ID from before Inventory DB became Ledger: still accepted, stored as the new one
	if conn.Application.Type != "ledger" || conn.Application.Name != "Ledger" {
		t.Fatalf("legacy type: %q %q", conn.Application.Type, conn.Application.Name)
	}
	b := h.browser()
	var signed struct {
		User struct {
			Source       string `json:"source"`
			Groups       []string
			Applications []struct {
				Name  string   `json:"name"`
				Roles []string `json:"roles"`
			} `json:"applications"`
		} `json:"user"`
	}
	if code := h.call(b, "POST", "/api/v1/auth/password", map[string]string{"username": "anna", "password": "anna-pass-1"}, &signed); code != 200 {
		t.Fatalf("directory sign-in: %d", code)
	}
	if signed.User.Source != "ldap" || len(signed.User.Applications) != 1 || signed.User.Applications[0].Roles[0] != "editor" {
		t.Fatalf("anna = %+v", signed.User)
	}
	var e apiErr
	if code := h.call(h.browser(), "POST", "/api/v1/auth/password", map[string]string{"username": "anna", "password": "wrong"}, &e); code != http.StatusUnauthorized {
		t.Fatalf("wrong directory password: %d %+v", code, e)
	}

	// a directory account sets up the second factor too when the policy requires it of everyone
	if code := h.call(admin, "PUT", "/api/v1/settings/password-policy", map[string]any{"min_length": 12, "letters": "any", "second_factor": "everyone"}, nil); code != 200 {
		t.Fatalf("policy: %d", code)
	}
	if code := h.call(h.browser(), "POST", "/api/v1/auth/password", map[string]string{"username": "anna", "password": "anna-pass-1"}, &e); code != http.StatusConflict || e.Code != "totp_setup_required" {
		t.Fatalf("directory sign-in under the policy: %d %+v", code, e)
	}
}
