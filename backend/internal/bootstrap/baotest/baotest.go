// Package baotest is an OpenBao in memory for tests: initialisation with the static seal, KV v2 mounts, AppRole
// login and token renewal — the part of the HTTP API Keystone uses.
package baotest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

type Server struct {
	*httptest.Server

	mu          sync.Mutex
	initialized bool
	root        string
	mounts      map[string]bool
	approle     bool
	roleID      string
	secretID    string
	tokens      map[string]bool
	kv          map[string]map[string]any
	Logins      int
}

func New() *Server {
	s := &Server{mounts: map[string]bool{}, tokens: map[string]bool{}, kv: map[string]map[string]any{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Credentials are the AppRole role_id and secret_id (after the setup), and the root token.
func (s *Server) Credentials() (roleID, secretID, root string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.roleID, s.secretID, s.root
}

// SetUp makes the server as if initialised with an AppRole and a mount (an external OpenBao).
func (s *Server) SetUp(mount string) (roleID, secretID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initialized, s.root, s.approle = true, "root-token", true
	s.mounts[mount] = true
	s.roleID, s.secretID = "role-1", "secret-1"
	return s.roleID, s.secretID
}

// Secret reads a KV v2 secret ("<mount>/<path>").
func (s *Server) Secret(path string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kv[path]
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		json.NewEncoder(w).Encode(v) //nolint:errcheck
	}
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/v1/")
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
	token := r.Header.Get("X-Vault-Token")
	isRoot := s.root != "" && token == s.root
	switch {
	case p == "sys/init" && r.Method == http.MethodGet:
		reply(w, 200, map[string]bool{"initialized": s.initialized})
	case p == "sys/seal-status":
		reply(w, 200, map[string]any{"type": "static", "initialized": s.initialized, "sealed": false})
	case p == "sys/init" && r.Method == http.MethodPut:
		if s.initialized {
			reply(w, 400, map[string]any{"errors": []string{"already initialized"}})
			return
		}
		s.initialized, s.root = true, "root-token"
		reply(w, 200, map[string]any{"root_token": s.root, "recovery_keys_base64": []string{"recovery-key"}})
	case p == "sys/health":
		if !s.initialized {
			reply(w, 501, nil)
			return
		}
		reply(w, 200, map[string]bool{"initialized": true})
	case p == "sys/mounts" && isRoot:
		out := map[string]any{}
		for m := range s.mounts {
			out[m+"/"] = map[string]string{"type": "kv"}
		}
		reply(w, 200, map[string]any{"data": out})
	case strings.HasPrefix(p, "sys/mounts/") && isRoot:
		s.mounts[strings.TrimPrefix(p, "sys/mounts/")] = true
		reply(w, 204, nil)
	case p == "sys/auth" && isRoot:
		out := map[string]any{}
		if s.approle {
			out["approle/"] = map[string]string{"type": "approle"}
		}
		reply(w, 200, out)
	case p == "sys/auth/approle" && isRoot:
		s.approle = true
		reply(w, 204, nil)
	case strings.HasPrefix(p, "sys/policies/acl/") && isRoot:
		reply(w, 204, nil)
	case p == "auth/approle/role/keystone" && isRoot:
		reply(w, 204, nil)
	case p == "auth/approle/role/keystone/role-id" && isRoot:
		s.roleID = "role-keystone"
		reply(w, 200, map[string]any{"data": map[string]string{"role_id": s.roleID}})
	case p == "auth/approle/role/keystone/secret-id" && isRoot:
		s.secretID = "secret-keystone"
		reply(w, 200, map[string]any{"data": map[string]string{"secret_id": s.secretID}})
	case p == "auth/approle/login":
		if !s.approle || body["role_id"] != s.roleID || body["secret_id"] != s.secretID {
			reply(w, 400, map[string]any{"errors": []string{"invalid role or secret ID"}})
			return
		}
		s.Logins++
		t := "tok-" + strings.Repeat("x", s.Logins)
		s.tokens[t] = true
		reply(w, 200, map[string]any{"auth": map[string]any{"client_token": t, "lease_duration": 3600, "renewable": true}})
	case p == "auth/token/renew-self":
		if !s.tokens[token] {
			reply(w, 403, nil)
			return
		}
		reply(w, 200, map[string]any{"auth": map[string]any{"client_token": token, "lease_duration": 3600}})
	default:
		// KV v2: <mount>/data/<path>, <mount>/metadata/<path>
		parts := strings.SplitN(p, "/", 3)
		if len(parts) != 3 || !s.mounts[parts[0]] {
			reply(w, 404, nil)
			return
		}
		if !s.tokens[token] && !isRoot {
			reply(w, 403, nil)
			return
		}
		key := parts[0] + "/" + parts[2]
		switch {
		case parts[1] == "data" && r.Method == http.MethodGet:
			v, ok := s.kv[key]
			if !ok {
				reply(w, 404, nil)
				return
			}
			reply(w, 200, map[string]any{"data": map[string]any{"data": v}})
		case parts[1] == "data" && (r.Method == http.MethodPost || r.Method == http.MethodPut):
			d, _ := body["data"].(map[string]any)
			s.kv[key] = d
			reply(w, 200, map[string]any{"data": map[string]any{"version": 1}})
		case parts[1] == "metadata" && r.Method == http.MethodDelete:
			delete(s.kv, key)
			reply(w, 204, nil)
		default:
			reply(w, 405, nil)
		}
	}
}
