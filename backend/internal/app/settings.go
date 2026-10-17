package app

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sbrw-evc/keystone/internal/directory"
	"github.com/sbrw-evc/keystone/internal/entra"
	"github.com/sbrw-evc/keystone/internal/oidcx"
	"github.com/sbrw-evc/keystone/internal/policy"
)

// Settings keys and secret paths.
const (
	keyPolicy    = "password_policy"
	keyPasskeys  = "passkeys"
	keyLDAP      = "ldap"
	keyEntra     = "entra"
	keyProviders = "providers"
	keyGeneral   = "general"

	secretLDAP  = "directory/ldap"
	secretEntra = "directory/entra"
)

func secretProvider(kind string) string { return "providers/" + kind }

// General: how Keystone presents itself and where it is.
type General struct {
	// Organization is shown on the sign-in page.
	Organization string `json:"organization"`
	// AllowLocal: local accounts (username + password) may sign in. Turn off when everyone comes from a directory.
	AllowLocal bool `json:"allow_local"`
	// PublicURL is the address of Keystone and its OpenID Connect issuer, e.g. https://keystone.example.com; empty:
	// the address of the request.
	PublicURL string `json:"public_url"`
	// TrustedProxies are the networks (or addresses) of reverse proxies whose X-Forwarded-For / -Host are believed.
	TrustedProxies []string `json:"trusted_proxies"`
	// SessionHours is how long a Keystone session lasts.
	SessionHours int `json:"session_hours"`
}

// generalTTL: other replicas see a change of the general settings within this time.
const generalTTL = 5 * time.Second

func (g *General) defaults() {
	if g.SessionHours <= 0 {
		g.SessionHours = 12
	}
	if g.TrustedProxies == nil {
		g.TrustedProxies = []string{}
	}
}

// normalizePublicURL checks a public address: http(s), a host, no query; the trailing slash goes.
func normalizePublicURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fail(http.StatusBadRequest, "invalid_public_url", "Enter the address of Keystone, such as https://keystone.example.com")
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/"), nil
}

// parseNetworks turns addresses and networks (10.0.0.0/8, 192.168.0.100) into networks.
func parseNetworks(list []string) ([]*net.IPNet, []string, error) {
	nets := []*net.IPNet{}
	clean := []string{}
	for _, n := range list {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		c := n
		if !strings.Contains(c, "/") {
			if strings.Contains(c, ":") {
				c += "/128"
			} else {
				c += "/32"
			}
		}
		_, ipn, err := net.ParseCIDR(c)
		if err != nil {
			return nil, nil, fail(http.StatusBadRequest, "invalid_proxy", "Not an address or a network: "+n)
		}
		nets = append(nets, ipn)
		clean = append(clean, n)
	}
	return nets, clean, nil
}

// normalize checks the general settings.
func (g General) normalize() (General, error) {
	g.Organization = strings.TrimSpace(g.Organization)
	var err error
	if g.PublicURL, err = normalizePublicURL(g.PublicURL); err != nil {
		return g, err
	}
	if _, g.TrustedProxies, err = parseNetworks(g.TrustedProxies); err != nil {
		return g, err
	}
	if g.SessionHours < 0 || g.SessionHours > 24*30 {
		return g, fail(http.StatusBadRequest, "invalid_session_hours", "A session lasts from 1 to 720 hours")
	}
	g.defaults()
	return g, nil
}

// general reads the general settings, kept for generalTTL (every request needs them: the issuer, the proxies).
func (a *App) general(ctx context.Context) General {
	a.genMu.Lock()
	if !a.genAt.IsZero() && time.Since(a.genAt) < generalTTL {
		g := a.gen
		a.genMu.Unlock()
		return g
	}
	a.genMu.Unlock()
	g := General{AllowLocal: true}
	if _, err := a.st.Setting(ctx, keyGeneral, &g); err != nil {
		a.genMu.Lock()
		defer a.genMu.Unlock()
		if !a.genAt.IsZero() {
			return a.gen // the database is away for a moment: the last known settings
		}
		g.defaults()
		return g
	}
	g.defaults()
	nets, _, _ := parseNetworks(g.TrustedProxies)
	a.genMu.Lock()
	a.gen, a.gennet, a.genAt = g, nets, time.Now()
	a.genMu.Unlock()
	return g
}

// UpdateGeneral changes the general settings (the setup wizard, the import of the settings of an older version).
func (a *App) UpdateGeneral(ctx context.Context, change func(*General)) (General, error) {
	a.genMu.Lock()
	a.genAt = time.Time{}
	a.genMu.Unlock()
	g := a.general(ctx)
	g.TrustedProxies = append([]string{}, g.TrustedProxies...)
	change(&g)
	g, err := g.normalize()
	if err != nil {
		return g, err
	}
	if err := a.st.PutSetting(ctx, keyGeneral, g); err != nil {
		return g, err
	}
	a.genMu.Lock()
	a.genAt = time.Time{}
	a.genMu.Unlock()
	return g, nil
}

type PasskeySettings struct {
	Enabled bool `json:"enabled"`
	// RPID: the passkey domain; empty = the host name of Keystone. A parent domain lets passkeys survive a move of Keystone
	// between its subdomains.
	RPID string `json:"rp_id"`
}

// Provider: Google, Apple or an OpenID Connect provider.
type Provider struct {
	Enabled        bool     `json:"enabled"`
	Title          string   `json:"title"`
	Issuer         string   `json:"issuer"`
	ClientID       string   `json:"client_id"`
	TeamID         string   `json:"team_id"`
	KeyID          string   `json:"key_id"`
	AllowedDomains []string `json:"allowed_domains"`
	// ExistingOnly: only people who already have a Keystone account (matched by verified e-mail) may sign in.
	ExistingOnly bool   `json:"existing_only"`
	Scopes       string `json:"scopes"`
	GroupsClaim  string `json:"groups_claim"`
}

type Providers struct {
	Google Provider `json:"google"`
	Apple  Provider `json:"apple"`
	OIDC   Provider `json:"oidc"`
}

const (
	GoogleIssuer = "https://accounts.google.com"
	AppleIssuer  = "https://appleid.apple.com"
)

var providerKinds = []string{"google", "apple", "oidc"}

func (p *Providers) get(kind string) *Provider {
	switch kind {
	case "google":
		return &p.Google
	case "apple":
		return &p.Apple
	case "oidc":
		return &p.OIDC
	}
	return nil
}

func providerTitle(kind string, p Provider) string {
	switch kind {
	case "google":
		return "Google"
	case "apple":
		return "Apple"
	}
	if p.Title != "" {
		return p.Title
	}
	return "OpenID Connect"
}

func (a *App) policy(ctx context.Context) policy.PasswordPolicy {
	p := policy.DefaultPasswordPolicy()
	a.st.Setting(ctx, keyPolicy, &p) //nolint:errcheck
	return p
}

func (a *App) passkeys(ctx context.Context) PasskeySettings {
	p := PasskeySettings{Enabled: true}
	a.st.Setting(ctx, keyPasskeys, &p) //nolint:errcheck
	return p
}

func (a *App) ldap(ctx context.Context) directory.Config {
	c := directory.Defaults(directory.KindAD)
	a.st.Setting(ctx, keyLDAP, &c) //nolint:errcheck
	return c
}

func (a *App) entra(ctx context.Context, r *http.Request) entra.Config {
	var c entra.Config
	a.st.Setting(ctx, keyEntra, &c) //nolint:errcheck
	c.RedirectURL = a.Issuer(r) + "/api/v1/auth/sso/entra/callback"
	return c
}

func (a *App) providers(ctx context.Context) Providers {
	var p Providers
	a.st.Setting(ctx, keyProviders, &p) //nolint:errcheck
	p.Google.Issuer, p.Apple.Issuer = GoogleIssuer, AppleIssuer
	return p
}

// Method is a way to sign in, as the sign-in page and the federation config list it.
type Method struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// methods lists what the sign-in page offers.
func (a *App) methods(ctx context.Context, r *http.Request) []Method {
	out := []Method{}
	if a.general(ctx).AllowLocal {
		out = append(out, Method{"password", "Password"})
	}
	if a.passkeys(ctx).Enabled {
		out = append(out, Method{"passkey", "Passkey"})
	}
	if l := a.ldap(ctx); l.Enabled {
		title := "Active Directory"
		if l.Kind == directory.KindOpenLDAP {
			title = "LDAP"
		}
		out = append(out, Method{"ldap", title})
	}
	if a.entra(ctx, r).Enabled {
		out = append(out, Method{"entra", "Microsoft"})
	}
	p := a.providers(ctx)
	for _, k := range providerKinds {
		if pr := p.get(k); pr.Enabled {
			out = append(out, Method{k, providerTitle(k, *pr)})
		}
	}
	return out
}

// providerClient is the OpenID Connect client of a provider.
func (a *App) providerClient(ctx context.Context, r *http.Request, kind string) (oidcx.Client, Provider, error) {
	all := a.providers(ctx)
	p := all.get(kind)
	if p == nil || !p.Enabled {
		return oidcx.Client{}, Provider{}, fail(http.StatusNotFound, "method_off", "This sign-in method is turned off")
	}
	secret := ""
	if kind == "apple" {
		key := secretsValue(ctx, a, secretProvider(kind), "private_key")
		s, err := oidcx.AppleSecret(p.TeamID, p.KeyID, p.ClientID, key, a.now())
		if err != nil {
			return oidcx.Client{}, *p, err
		}
		secret = s
	} else {
		secret = secretsValue(ctx, a, secretProvider(kind), "client_secret")
	}
	c := oidcx.Client{Issuer: p.Issuer, ClientID: p.ClientID, Secret: secret,
		RedirectURI: a.Issuer(r) + "/api/v1/auth/sso/" + kind + "/callback", Scopes: []string{"openid", "email", "profile"}, Extra: url.Values{}}
	switch kind {
	case "google":
		c.Extra.Set("prompt", "select_account")
		if len(p.AllowedDomains) == 1 {
			c.Extra.Set("hd", p.AllowedDomains[0])
		}
	case "apple":
		c.Scopes = []string{"openid", "email", "name"}
		c.Extra.Set("response_mode", "form_post")
	default:
		c.Scopes = append(c.Scopes, strings.Fields(p.Scopes)...)
	}
	return c, *p, nil
}

// ---- a simple per-address limiter for sign-in attempts (on top of the per-account lockout)

type limiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newLimiter() *limiter { return &limiter{hits: map[string][]time.Time{}} }

// Allow records an attempt from key and tells whether fewer than 20 were made in the last 5 minutes.
func (l *limiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if now.Sub(t) < 5*time.Minute {
			kept = append(kept, t)
		}
	}
	if len(kept) >= 20 {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	if len(l.hits) > 10000 {
		l.hits = map[string][]time.Time{}
	}
	return true
}

func secretsValue(ctx context.Context, a *App, path, field string) string {
	m, err := a.sec.Get(ctx, path)
	if err != nil {
		return ""
	}
	return m[field]
}
