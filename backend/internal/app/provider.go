package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sbrw-evc/keystone/internal/store"
)

const (
	codeTTL    = 60 * time.Second
	idTokenTTL = 5 * time.Minute
	accessTTL  = 10 * time.Minute
)

// authzRequest is a checked /oauth2/authorize request, sealed while the person signs in.
type authzRequest struct {
	ClientID    string `json:"c"`
	RedirectURI string `json:"r"`
	State       string `json:"s"`
	Nonce       string `json:"n"`
	Challenge   string `json:"x"`
	Scope       string `json:"o"`
}

func (a *App) discovery(w http.ResponseWriter, r *http.Request) {
	iss := a.Issuer(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/oauth2/authorize",
		"token_endpoint":                        iss + "/oauth2/token",
		"userinfo_endpoint":                     iss + "/oauth2/userinfo",
		"jwks_uri":                              iss + "/oauth2/jwks",
		"end_session_endpoint":                  iss + "/oauth2/logout",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups", "roles"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported": []string{"sub", "name", "preferred_username", "email", "email_verified", "groups", "roles", "amr",
			"auth_time", "sid", "spa_admin"},
	})
}

func (a *App) jwks(w http.ResponseWriter, r *http.Request) {
	k, err := a.keys.JWKS(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "application/json")
	writeJSONCached(w, k)
}

// authorize checks the request; with a valid Keystone session the code goes back at once, otherwise the sign-in page
// takes over with the sealed request.
func (a *App) authorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	app, err := a.st.ApplicationByClientID(ctx, q.Get("client_id"))
	if err != nil {
		writeError(w, fail(http.StatusBadRequest, "invalid_client", "Unknown application"))
		return
	}
	redirect := q.Get("redirect_uri")
	if !contains(app.RedirectURIs, redirect) || redirect == "" {
		writeError(w, fail(http.StatusBadRequest, "invalid_redirect", "The redirect address is not registered for this application"))
		return
	}
	bad := func(code, desc string) {
		http.Redirect(w, r, errorRedirect(redirect, q.Get("state"), code, desc, a.Issuer(r)), http.StatusFound)
	}
	if q.Get("response_type") != "code" {
		bad("unsupported_response_type", "only the authorization code flow is supported")
		return
	}
	if !strings.Contains(" "+q.Get("scope")+" ", " openid ") {
		bad("invalid_scope", "the openid scope is required")
		return
	}
	if q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) < 43 {
		bad("invalid_request", "PKCE with S256 is required")
		return
	}
	if q.Get("nonce") == "" || q.Get("state") == "" {
		bad("invalid_request", "state and nonce are required")
		return
	}
	req := authzRequest{ClientID: app.ClientID, RedirectURI: redirect, State: q.Get("state"), Nonce: q.Get("nonce"),
		Challenge: q.Get("code_challenge"), Scope: q.Get("scope")}
	if p := current(r); p != nil && q.Get("prompt") != "login" {
		next, err := a.finishAuthorize(ctx, a.Issuer(r), p.User, p.Session, req)
		if err != nil {
			writeError(w, err)
			return
		}
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	if q.Get("prompt") == "none" {
		bad("login_required", "the person is not signed in to Keystone")
		return
	}
	sealed, err := a.state.Seal(ctx, "authz", req, 30*time.Minute)
	if err != nil {
		writeError(w, err)
		return
	}
	v := url.Values{"request": {sealed}, "app": {app.Name}}
	if h := q.Get("idp_hint"); h != "" {
		v.Set("method", h)
	}
	if h := q.Get("login_hint"); h != "" {
		v.Set("login_hint", h)
	}
	http.Redirect(w, r, "/signin?"+v.Encode(), http.StatusFound)
}

func errorRedirect(redirect, state, code, desc, iss string) string {
	v := url.Values{"error": {code}, "error_description": {desc}, "iss": {iss}}
	if state != "" {
		v.Set("state", state)
	}
	return redirect + sep(redirect) + v.Encode()
}

func sep(u string) string {
	if strings.Contains(u, "?") {
		return "&"
	}
	return "?"
}

// finishAuthorize gives the application a code for a signed-in person who has a role in it.
func (a *App) finishAuthorize(ctx context.Context, iss string, u store.User, s store.Session, req authzRequest) (string, error) {
	app, err := a.st.ApplicationByClientID(ctx, req.ClientID)
	if err != nil {
		return "", fail(http.StatusBadRequest, "invalid_client", "The application was removed from Keystone")
	}
	roles, err := a.rolesIn(ctx, app, u.ID)
	if err != nil {
		return "", err
	}
	if len(roles) == 0 {
		a.st.Audit(ctx, u.Username, "oauth.denied", app.Name, "", nil)
		return errorRedirect(req.RedirectURI, req.State, "access_denied", u.Username+" has no role in "+app.Name, iss), nil
	}
	code := randomToken(32)
	if err := a.st.PutCode(ctx, store.Code{Hash: hashToken(code), AppID: app.ID, UserID: u.ID, SessionID: s.ID,
		RedirectURI: req.RedirectURI, Nonce: req.Nonce, Challenge: req.Challenge, Scope: req.Scope, ExpiresAt: a.now().Add(codeTTL)}); err != nil {
		return "", err
	}
	v := url.Values{"code": {code}, "state": {req.State}, "iss": {iss}}
	return req.RedirectURI + sep(req.RedirectURI) + v.Encode(), nil
}

// rolesIn are the person's roles in the application that its catalogue knows.
func (a *App) rolesIn(ctx context.Context, app store.Application, userID string) ([]string, error) {
	all, err := a.st.UserAppRoles(ctx, userID)
	if err != nil {
		return nil, err
	}
	return knownRoles(app, all[app.ID]), nil
}

func knownRoles(app store.Application, roles []string) []string {
	out := []string{}
	for _, r := range roles {
		for _, c := range app.Roles {
			if c.ID == r {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

type tokenErr struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func tokenFail(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, tokenErr{code, desc})
}

// clientOf authenticates an application by its client ID and secret (basic or post).
func (a *App) clientOf(ctx context.Context, r *http.Request) (store.Application, bool) {
	id, secret, ok := r.BasicAuth()
	if ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	app, err := a.st.ApplicationByClientID(ctx, id)
	if err != nil || secret == "" {
		return app, false
	}
	return app, subtle.ConstantTimeCompare([]byte(a.secretHash(ctx, secret)), []byte(app.SecretHash)) == 1
}

func (a *App) token(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		tokenFail(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	app, ok := a.clientOf(ctx, r)
	if !ok {
		tokenFail(w, http.StatusUnauthorized, "invalid_client", "")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		tokenFail(w, http.StatusBadRequest, "unsupported_grant_type", "")
		return
	}
	c, err := a.st.TakeCode(ctx, hashToken(r.PostForm.Get("code")))
	if err != nil || c.AppID != app.ID || c.ExpiresAt.Before(a.now()) || c.RedirectURI != r.PostForm.Get("redirect_uri") {
		tokenFail(w, http.StatusBadRequest, "invalid_grant", "the code is unknown, expired or for another application")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != c.Challenge {
		tokenFail(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	u, err := a.st.UserByID(ctx, c.UserID)
	if err != nil || u.Disabled {
		tokenFail(w, http.StatusBadRequest, "invalid_grant", "the account is disabled")
		return
	}
	s, err := a.st.SessionByID(ctx, c.SessionID)
	if err != nil {
		tokenFail(w, http.StatusBadRequest, "invalid_grant", "the Keystone session has ended")
		return
	}
	claims, err := a.claims(ctx, app, u, &s, c.Scope)
	if err != nil {
		writeError(w, err)
		return
	}
	if len(claims["roles"].([]string)) == 0 {
		tokenFail(w, http.StatusBadRequest, "invalid_grant", "no role in the application")
		return
	}
	iss := a.Issuer(r)
	now := a.now()
	idc := map[string]any{"iss": iss, "aud": app.ClientID, "iat": now.Unix(), "exp": now.Add(idTokenTTL).Unix(), "nonce": c.Nonce}
	for k, v := range claims {
		idc[k] = v
	}
	id, err := a.keys.Sign(ctx, idc)
	if err != nil {
		writeError(w, err)
		return
	}
	access, err := a.keys.Sign(ctx, map[string]any{"iss": iss, "aud": app.ClientID, "sub": u.ID, "iat": now.Unix(),
		"exp": now.Add(accessTTL).Unix(), "scope": c.Scope, "typ": "at+jwt", "sid": s.ID[:16]})
	if err != nil {
		writeError(w, err)
		return
	}
	a.st.Audit(ctx, u.Username, "oauth.token", app.Name, a.clientIP(r), map[string]any{"roles": claims["roles"]})
	writeJSON(w, http.StatusOK, map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": int(accessTTL.Seconds()),
		"id_token": id, "scope": c.Scope})
}

// claims describe a person to an application.
func (a *App) claims(ctx context.Context, app store.Application, u store.User, s *store.Session, scope string) (map[string]any, error) {
	roles, err := a.rolesIn(ctx, app, u.ID)
	if err != nil {
		return nil, err
	}
	groups, err := a.st.UserGroups(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	c := map[string]any{"sub": u.ID, "preferred_username": u.Username, "name": displayName(u), "roles": roles,
		"groups": groups, "spa_admin": u.SPARole == "admin"}
	if u.Email != "" {
		c["email"] = u.Email
		c["email_verified"] = u.Source != "local"
	}
	if s != nil {
		c["sid"] = s.ID[:16]
		c["auth_time"] = s.CreatedAt.Unix()
		c["amr"] = amrOf(s.Method, s.MFA)
	}
	_ = scope
	return c, nil
}

func amrOf(method string, mfa bool) []string {
	var out []string
	switch method {
	case "pwd":
		out = []string{"pwd"}
	case "passkey":
		out = []string{"hwk", "user"}
	case "ldap":
		out = []string{"pwd", "fed"}
	default:
		out = []string{"fed"}
	}
	if mfa {
		if method == "pwd" || method == "ldap" {
			out = append(out, "otp") // the code of an authenticator app after the password
		}
		out = append(out, "mfa")
	}
	return out
}

func (a *App) userinfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	var at struct {
		Iss string `json:"iss"`
		Aud string `json:"aud"`
		Sub string `json:"sub"`
		Exp int64  `json:"exp"`
		Typ string `json:"typ"`
	}
	if !ok || a.keys.Verify(ctx, strings.TrimSpace(raw), &at) != nil || at.Typ != "at+jwt" || at.Exp < a.now().Unix() || at.Iss != a.Issuer(r) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		tokenFail(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}
	app, err := a.st.ApplicationByClientID(ctx, at.Aud)
	if err != nil {
		tokenFail(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}
	u, err := a.st.UserByID(ctx, at.Sub)
	if err != nil || u.Disabled {
		tokenFail(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}
	c, err := a.claims(ctx, app, u, nil, "")
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// logout ends the Keystone session and returns to the application when its address is registered.
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	a.endSession(w, r)
	target := "/signin?signed_out=1"
	if back := r.URL.Query().Get("post_logout_redirect_uri"); back != "" {
		apps, _ := a.st.Applications(ctx)
		for _, app := range apps {
			if (r.URL.Query().Get("client_id") == "" || app.ClientID == r.URL.Query().Get("client_id")) &&
				(contains(app.LogoutURIs, back) || strings.TrimRight(back, "/") == strings.TrimRight(app.BaseURL, "/")) {
				target = back
				break
			}
		}
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// secretHash is the keyed hash Keystone keeps of client secrets and federation tokens.
func (a *App) secretHash(ctx context.Context, v string) string {
	key, err := a.state.get(ctx)
	if err != nil {
		return ""
	}
	return hmacHex(key, v)
}

var errNoApp = errors.New("no application")
