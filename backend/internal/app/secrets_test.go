package app_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/sbrw-evc/keystone/internal/app"
	"github.com/sbrw-evc/keystone/internal/policy"
	"github.com/sbrw-evc/keystone/internal/secrets"
)

// dumpDB is every row of every table of the database as JSON text.
func (h *harness) dumpDB() string {
	h.t.Helper()
	ctx := context.Background()
	tables := []string{}
	rows, err := h.st.DB.Query(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'`)
	if err != nil {
		h.t.Fatal(err)
	}
	for rows.Next() {
		var t string
		rows.Scan(&t) //nolint:errcheck
		tables = append(tables, t)
	}
	rows.Close()
	var b strings.Builder
	for _, t := range tables {
		rows, err := h.st.DB.Query(ctx, `SELECT row_to_json(x)::text FROM "`+t+`" x`)
		if err != nil {
			h.t.Fatal(err)
		}
		for rows.Next() {
			var s string
			rows.Scan(&s) //nolint:errcheck
			b.WriteString(t + ": " + s + "\n")
		}
		rows.Close()
	}
	return b.String()
}

func (h *harness) hasColumn(table, column string) bool {
	var ok bool
	h.st.DB.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema()
		AND table_name = $1 AND column_name = $2)`, table, column).Scan(&ok) //nolint:errcheck
	return ok
}

func connectionKey(t *testing.T, key string) (clientID, secret, token string) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(key, "spa1."))
	if err != nil {
		t.Fatal(err)
	}
	var k map[string]string
	json.Unmarshal(raw, &k) //nolint:errcheck
	return k["client_id"], k["client_secret"], k["token"]
}

func (h *harness) fedStatus(token, method, path string) int {
	req, _ := http.NewRequest(method, h.url+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

// Passwords, their history, authenticator apps, recovery codes and the credentials of applications are only in the
// secret store; the database has nothing of them.
func TestNoSecretsInDatabase(t *testing.T) {
	h := newHarness(t)
	admin := h.adminBrowser() // changes the password: the first one goes into the history
	var user map[string]any
	if code := h.call(admin, "POST", "/api/v1/users", map[string]any{"username": "jdoe", "password": "Another-Secret-7"}, &user); code != http.StatusCreated {
		t.Fatalf("create user: %d %v", code, user)
	}
	var conn app.Connection
	if code := h.call(admin, "POST", "/api/v1/applications", map[string]any{"type": "network-control", "base_url": "https://nc.example.com"}, &conn); code != http.StatusCreated {
		t.Fatalf("connect: %d", code)
	}
	_, secret, token := connectionKey(t, conn.Key)
	if code := h.fedStatus(token, "GET", "/api/spa/v1/config"); code != http.StatusOK {
		t.Fatalf("federation with the new token: %d", code)
	}

	dump := h.dumpDB()
	for _, bad := range []string{"pbkdf2-sha256$", "argon2", secret, token} {
		if strings.Contains(dump, bad) {
			t.Fatalf("the database holds %q:\n%s", bad, dump)
		}
	}
	creds, err := h.sec.Get(context.Background(), "apps/"+conn.Application.ID+"/credentials")
	if err != nil || creds["token_hash"] == "" || strings.Contains(dump, creds["token_hash"]) || strings.Contains(dump, creds["secret_hash"]) {
		t.Fatalf("application credentials: %v %v", creds, err)
	}
	pw, err := h.sec.Get(context.Background(), "users/"+user["id"].(string)+"/password")
	if err != nil || !strings.HasPrefix(pw["hash"], "pbkdf2-sha256$") {
		t.Fatalf("password in the secret store: %v %v", pw, err)
	}
	var admins []map[string]any
	h.call(admin, "GET", "/api/v1/users", nil, &admins)
	for _, u := range admins {
		if u["username"] == "admin" {
			p, _ := h.sec.Get(context.Background(), "users/"+u["id"].(string)+"/password")
			var hist []string
			json.Unmarshal([]byte(p["history"]), &hist) //nolint:errcheck
			if len(hist) != 1 {
				t.Fatalf("password history %v", p)
			}
		}
	}

	// a new key: the old token stops working, its index goes
	var again app.Connection
	if code := h.call(admin, "POST", "/api/v1/applications/"+conn.Application.ID+"/key", nil, &again); code != http.StatusOK {
		t.Fatalf("new key: %d", code)
	}
	if code := h.fedStatus(token, "GET", "/api/spa/v1/config"); code != http.StatusUnauthorized {
		t.Fatalf("the old token still works: %d", code)
	}
	if _, err := h.sec.Get(context.Background(), "apptokens/"+creds["token_hash"]); err == nil {
		t.Fatal("the index of the old token is left")
	}
	_, _, token2 := connectionKey(t, again.Key)
	if code := h.fedStatus(token2, "GET", "/api/spa/v1/config"); code != http.StatusOK {
		t.Fatalf("the new token: %d", code)
	}
	// removing the application and the person removes their secrets
	h.call(admin, "DELETE", "/api/v1/applications/"+conn.Application.ID, nil, nil)
	h.call(admin, "DELETE", "/api/v1/users/"+user["id"].(string), nil, nil)
	for _, p := range h.sec.Paths() {
		if strings.Contains(p, conn.Application.ID) || strings.Contains(p, user["id"].(string)) || strings.HasPrefix(p, "apptokens/") {
			t.Fatalf("left in the secret store: %s", p)
		}
	}
}

// An installation from before: password hashes and recovery codes in the database, client secret and token hashes in
// the applications table, secrets sealed with the master key. MigrateSecrets moves them and drops the columns.
func TestMigrateSecrets(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	admin := h.adminBrowser()
	var conn app.Connection
	if code := h.call(admin, "POST", "/api/v1/applications", map[string]any{"type": "network-control", "base_url": "https://nc.example.com"}, &conn); code != http.StatusCreated {
		t.Fatalf("connect: %d", code)
	}
	clientID, _, token := connectionKey(t, conn.Key)

	// make the database look like before: the hashes back in their columns, out of the secret store
	creds, _ := h.sec.Get(ctx, "apps/"+conn.Application.ID+"/credentials")
	h.sec.Delete(ctx, "apps/"+conn.Application.ID+"/credentials") //nolint:errcheck
	h.sec.Delete(ctx, "apptokens/"+creds["token_hash"])           //nolint:errcheck
	if _, err := h.st.DB.Exec(ctx, `UPDATE applications SET secret_hash = $2, token_hash = $3 WHERE id = $1`,
		conn.Application.ID, creds["secret_hash"], creds["token_hash"]); err != nil {
		t.Fatal(err)
	}
	if code := h.fedStatus(token, "GET", "/api/spa/v1/config"); code != http.StatusUnauthorized {
		t.Fatalf("before the move the token is unknown to the secret store: %d", code)
	}
	old, _ := policy.HashPassword("Legacy-Passw0rd!")
	older, _ := policy.HashPassword("Older-Passw0rd!")
	if _, err := h.st.DB.Exec(ctx, `INSERT INTO users (id, username, source, password_hash, password_changed_at) VALUES ('usr_legacy', 'legacy', 'local', $1, now())`, old); err != nil {
		t.Fatal(err)
	}
	if _, err := h.st.DB.Exec(ctx, `INSERT INTO password_history (user_id, password_hash) VALUES ('usr_legacy', $1)`, older); err != nil {
		t.Fatal(err)
	}
	if _, err := h.st.DB.Exec(ctx, `INSERT INTO totp (user_id, last_step) VALUES ('usr_legacy', 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.st.DB.Exec(ctx, `INSERT INTO recovery_codes (user_id, code_hash) VALUES ('usr_legacy', 'h1'), ('usr_legacy', 'h2')`); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	rand.Read(key) //nolint:errcheck
	sealed, err := secrets.NewSealed(h.st, key)
	if err != nil {
		t.Fatal(err)
	}
	sealed.Put(ctx, "directory/ldap", map[string]string{"bind_password": "ldap-secret"}) //nolint:errcheck
	sealed.Put(ctx, "totp/usr_legacy", map[string]string{"secret": "JBSWY3DPEHPK3PXP"})  //nolint:errcheck

	if err := h.a.MigrateSecrets(ctx, sealed); err != nil {
		t.Fatal(err)
	}
	if err := h.a.MigrateSecrets(ctx, sealed); err != nil { // again: nothing left to do
		t.Fatalf("second run: %v", err)
	}

	for _, c := range [][2]string{{"users", "password_hash"}, {"applications", "secret_hash"}, {"applications", "token_hash"}} {
		if h.hasColumn(c[0], c[1]) {
			t.Fatalf("%s.%s is still there", c[0], c[1])
		}
	}
	dump := h.dumpDB()
	for _, bad := range []string{"pbkdf2-sha256$", creds["token_hash"], creds["secret_hash"], "\nrecovery_codes:", "\npassword_history:", "\nsecrets:"} {
		if strings.Contains(dump, bad) {
			t.Fatalf("the database still holds %q:\n%s", bad, dump)
		}
	}
	if v := secrets.Value(ctx, h.sec, "directory/ldap", "bind_password"); v != "ldap-secret" {
		t.Fatalf("the sealed secret did not move: %q", v)
	}
	tp, _ := h.sec.Get(ctx, "users/usr_legacy/totp")
	if tp["secret"] != "JBSWY3DPEHPK3PXP" || tp["recovery"] != `["h1","h2"]` {
		t.Fatalf("authenticator app: %v", tp)
	}
	if _, err := h.sec.Get(ctx, "totp/usr_legacy"); err == nil {
		t.Fatal("the old path of the authenticator app is left")
	}
	pw, _ := h.sec.Get(ctx, "users/usr_legacy/password")
	if pw["hash"] != old || pw["history"] != `["`+older+`"]` {
		t.Fatalf("password: %v", pw)
	}
	if code := h.fedStatus(token, "GET", "/api/spa/v1/config"); code != http.StatusOK {
		t.Fatalf("the token after the move: %d", code)
	}
	_ = clientID
	var audit []map[string]any
	h.call(admin, "GET", "/api/v1/audit?q=secrets.migrated", nil, &audit)
	if len(audit) == 0 {
		t.Fatal("the move is not in the audit log")
	}
	// the person signs in with the password from before (the authenticator app is asked for next)
	var e apiErr
	if code := h.call(h.browser(), "POST", "/api/v1/auth/password", map[string]string{"username": "legacy", "password": "Legacy-Passw0rd!"}, &e); code != http.StatusConflict || e.Code != "totp_required" {
		t.Fatalf("sign-in with the moved password: %d %+v", code, e)
	}
}
