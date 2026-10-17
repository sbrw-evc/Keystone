package app_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/sbrw-evc/keystone/internal/app"
	"github.com/sbrw-evc/keystone/internal/policy"
)

// argon2id is a hash as Network Control (argon2-cffi) writes it.
func argon2id(password string) string {
	salt := []byte("network-control!")
	key := argon2.IDKey([]byte(password), salt, 3, 65536, 4, 32)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s", enc.EncodeToString(salt), enc.EncodeToString(key))
}

func (h *harness) fedJSON(token, method, path string, body any, out any) int {
	h.t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, h.url+path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			h.t.Fatalf("%s: %v: %s", path, err, b)
		}
	}
	return res.StatusCode
}

type importAnswer struct {
	Imported []struct {
		Username string `json:"username"`
		ID       string `json:"id"`
	} `json:"imported"`
	Conflicts []struct {
		Username string `json:"username"`
		Reason   string `json:"reason"`
	} `json:"conflicts"`
	Rejected []struct {
		Username string `json:"username"`
		Reason   string `json:"reason"`
	} `json:"rejected"`
	Error string `json:"error"`
}

func TestUserImport(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	admin := h.adminBrowser()
	var taken map[string]any
	if code := h.call(admin, "POST", "/api/v1/users", map[string]any{"username": "taken", "email": "taken@example.com", "password": "Another-Secret-7"}, &taken); code != http.StatusCreated {
		t.Fatalf("create user: %d", code)
	}
	var conn app.Connection
	if code := h.call(admin, "POST", "/api/v1/applications", map[string]any{"type": "network-control", "base_url": "https://nc.example.com"}, &conn); code != http.StatusCreated {
		t.Fatalf("connect: %d", code)
	}
	_, _, token := connectionKey(t, conn.Key)
	if code := h.fedJSON(token, "PUT", "/api/spa/v1/roles", map[string]any{"roles": []map[string]string{{"id": "admin"}, {"id": "operator"}, {"id": "viewer"}}}, nil); code != http.StatusOK {
		t.Fatalf("publish roles: %d", code)
	}
	pbkdf2, _ := policy.HashPassword("Pbkdf2-Passw0rd!")
	body := map[string]any{"users": []map[string]any{
		{"username": "ann", "name": "Ann", "email": "ann@example.com", "role": "operator", "password_hash": argon2id("Argon-Passw0rd!")},
		{"username": "bob", "name": "Bob", "email": "", "role": "viewer", "password_hash": pbkdf2},
		{"username": "carl", "name": "Carl", "role": "admin", "password_hash": nil},
		{"username": "TAKEN", "role": "viewer", "password_hash": nil},
		{"username": "dora", "email": "Taken@Example.com", "role": "viewer", "password_hash": nil},
		{"username": "ann", "role": "viewer", "password_hash": nil},
		{"username": "bad name", "role": "viewer"},
		{"username": "eve", "role": "superuser"},
		{"username": "fay", "role": "viewer", "password_hash": "md5$abc"},
		{"username": "gus", "role": "viewer", "password_hash": "$argon2id$v=19$m=999999999,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"},
	}}

	// closed: nobody allowed it
	var cfg map[string]any
	h.fedJSON(token, "GET", "/api/spa/v1/config", nil, &cfg)
	if cfg["user_import"] != false {
		t.Fatalf("config: %v", cfg)
	}
	var ans importAnswer
	if code := h.fedJSON(token, "POST", "/api/spa/v1/users/import", body, &ans); code != http.StatusForbidden || ans.Error != "import_not_allowed" {
		t.Fatalf("closed window: %d %+v", code, ans)
	}
	if code := h.fedJSON("spat_wrong", "POST", "/api/spa/v1/users/import", body, nil); code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", code)
	}

	// the administrator opens the window
	var view map[string]any
	if code := h.call(admin, "POST", "/api/v1/applications/"+conn.Application.ID+"/user-import", map[string]bool{"allow": true}, &view); code != http.StatusOK || view["user_import_until"] == nil {
		t.Fatalf("open: %d %v", code, view)
	}
	h.fedJSON(token, "GET", "/api/spa/v1/config", nil, &cfg)
	if cfg["user_import"] != true {
		t.Fatalf("config: %v", cfg)
	}
	tooMany := make([]map[string]any, 1001)
	for i := range tooMany {
		tooMany[i] = map[string]any{"username": fmt.Sprintf("u%d", i), "role": "viewer"}
	}
	if code := h.fedJSON(token, "POST", "/api/spa/v1/users/import", map[string]any{"users": tooMany}, &ans); code != http.StatusBadRequest || ans.Error != "too_many_users" {
		t.Fatalf("too many: %d %+v", code, ans)
	}

	// nobody importable: the window stays open
	ans = importAnswer{}
	if code := h.fedJSON(token, "POST", "/api/spa/v1/users/import", map[string]any{"users": []map[string]any{{"username": "taken", "role": "viewer"}}}, &ans); code != http.StatusOK ||
		len(ans.Imported) != 0 || len(ans.Conflicts) != 1 || ans.Rejected == nil {
		t.Fatalf("only conflicts: %d %+v", code, ans)
	}

	ans = importAnswer{}
	if code := h.fedJSON(token, "POST", "/api/spa/v1/users/import", body, &ans); code != http.StatusOK {
		t.Fatalf("import: %d %+v", code, ans)
	}
	got := func(list any) string {
		b, _ := json.Marshal(list)
		return string(b)
	}
	names := []string{}
	for _, u := range ans.Imported {
		names = append(names, u.Username)
	}
	if strings.Join(names, ",") != "ann,bob,carl" {
		t.Fatalf("imported %s", got(ans.Imported))
	}
	if got(ans.Conflicts) != `[{"username":"TAKEN","reason":"username_taken"},{"username":"dora","reason":"email_taken"},{"username":"ann","reason":"username_taken"}]` {
		t.Fatalf("conflicts %s", got(ans.Conflicts))
	}
	if got(ans.Rejected) != `[{"username":"bad name","reason":"invalid_username"},{"username":"eve","reason":"invalid_role"},{"username":"fay","reason":"invalid_hash"},{"username":"gus","reason":"invalid_hash"}]` {
		t.Fatalf("rejected %s", got(ans.Rejected))
	}

	// the window closed after the import
	if code := h.fedJSON(token, "POST", "/api/spa/v1/users/import", body, &ans); code != http.StatusForbidden {
		t.Fatalf("second import: %d", code)
	}

	// the existing person is untouched; the new ones have their roles in the application
	var users []map[string]any
	h.call(admin, "GET", "/api/v1/users", nil, &users)
	byName := map[string]map[string]any{}
	for _, u := range users {
		byName[u["username"].(string)] = u
	}
	if byName["taken"]["email"] != "taken@example.com" {
		t.Fatalf("the existing person changed: %v", byName["taken"])
	}
	roles := func(name string) string {
		r, _ := byName[name]["app_roles"].(map[string]any)
		return got(r[conn.Application.ID])
	}
	if roles("ann") != `["operator"]` || roles("bob") != `["viewer"]` || roles("carl") != `["admin"]` {
		t.Fatalf("roles: ann %s bob %s carl %s", roles("ann"), roles("bob"), roles("carl"))
	}
	if byName["carl"]["must_change"] != true || byName["ann"]["must_change"] != false {
		t.Fatalf("must_change: %v %v", byName["carl"], byName["ann"])
	}

	// both hash formats sign in; the Argon2id hash is replaced with Keystone's own
	for _, c := range [][2]string{{"ann", "Argon-Passw0rd!"}, {"bob", "Pbkdf2-Passw0rd!"}} {
		var res map[string]any
		if code := h.call(h.browser(), "POST", "/api/v1/auth/password", map[string]string{"username": c[0], "password": c[1]}, &res); code != http.StatusOK {
			t.Fatalf("sign-in of %s: %d %v", c[0], code, res)
		}
	}
	pw, _ := h.sec.Get(ctx, "users/"+byName["ann"]["id"].(string)+"/password")
	if !strings.HasPrefix(pw["hash"], "pbkdf2-sha256$") || !policy.CheckPassword(pw["hash"], "Argon-Passw0rd!") {
		t.Fatalf("not rehashed: %v", pw)
	}
	if code := h.call(h.browser(), "POST", "/api/v1/auth/password", map[string]string{"username": "carl", "password": ""}, nil); code == http.StatusOK {
		t.Fatal("a person without a password signed in")
	}
	if strings.Contains(h.dumpDB(), "argon2") {
		t.Fatal("a hash went into the database")
	}

	// the window expires on its own
	h.call(admin, "POST", "/api/v1/applications/"+conn.Application.ID+"/user-import", map[string]bool{"allow": true}, nil)
	h.st.DB.Exec(ctx, `UPDATE applications SET user_import_until = now() - interval '1 minute' WHERE id = $1`, conn.Application.ID) //nolint:errcheck
	if code := h.fedJSON(token, "POST", "/api/spa/v1/users/import", map[string]any{"users": []map[string]any{{"username": "zed", "role": "viewer"}}}, &ans); code != http.StatusForbidden {
		t.Fatalf("expired window: %d", code)
	}

	var audit []map[string]any
	h.call(admin, "GET", "/api/v1/audit?q=application.users_imported", nil, &audit)
	if len(audit) != 2 { // the request with conflicts only, and the import
		t.Fatalf("audit %v", audit)
	}
}
