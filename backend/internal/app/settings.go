package app

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sbrw-evc/spa/internal/directory"
	"github.com/sbrw-evc/spa/internal/entra"
	"github.com/sbrw-evc/spa/internal/oidcx"
	"github.com/sbrw-evc/spa/internal/policy"
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

// General: how SPA presents itself.
type General struct {
	// Organization is shown on the sign-in page.
	Organization string `json:"organization"`
	// AllowLocal: local accounts (username + password) may sign in. Turn off when everyone comes from a directory.
	AllowLocal bool `json:"allow_local"`
}

type PasskeySettings struct {
	Enabled bool `json:"enabled"`
	// RPID: the passkey domain; empty = the host name of SPA. A parent domain lets passkeys survive a move of SPA
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
	// ExistingOnly: only people who already have an SPA account (matched by verified e-mail) may sign in.
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

func (a *App) general(ctx context.Context) General {
	g := General{AllowLocal: true}
	a.st.Setting(ctx, keyGeneral, &g) //nolint:errcheck
	return g
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
