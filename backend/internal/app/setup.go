package app

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/sbrw-evc/keystone/internal/policy"
	"github.com/sbrw-evc/keystone/internal/store"
)

// The steps of the setup wizard after its storage step (internal/setup asks for them): the first administrator, the
// organisation and the public address, the trusted proxies. Where the wizard is is kept in the settings.

const keySetup = "setup"

// Setup steps after the storage.
const (
	SetupAdmin        = "admin"
	SetupOrganization = "organization"
	SetupProxies      = "proxies"
	SetupDone         = "done"
)

// SetupStep is the step of the wizard Keystone is at. A database with people (an installation from before the wizard)
// is done.
func (a *App) SetupStep(ctx context.Context) (string, error) {
	var s struct {
		Step string `json:"step"`
	}
	ok, err := a.st.Setting(ctx, keySetup, &s)
	if err != nil {
		return "", err
	}
	if ok && s.Step != "" {
		return s.Step, nil
	}
	n, err := a.st.CountUsers(ctx)
	if err != nil {
		return "", err
	}
	step := SetupAdmin
	if n > 0 {
		step = SetupDone
	}
	return step, a.SetSetupStep(ctx, step)
}

func (a *App) SetSetupStep(ctx context.Context, step string) error {
	return a.st.PutSetting(ctx, keySetup, map[string]string{"step": step})
}

// CreateFirstAdmin creates the first administrator in the wizard: a local account under the password policy whose
// password does not need to be changed. Only while Keystone has no administrator.
func (a *App) CreateFirstAdmin(ctx context.Context, username, name, email, password, ip string) (store.User, error) {
	in := userIn{Username: username, Name: name, Email: email, SPARole: "admin"}
	if err := in.check(); err != nil {
		return store.User{}, err
	}
	if n, err := a.st.CountAdmins(ctx); err != nil {
		return store.User{}, err
	} else if n > 0 {
		return store.User{}, fail(http.StatusConflict, "admin_exists", "Keystone has an administrator already")
	}
	if v := a.policy(ctx).Check(password, in.Username); len(v) > 0 {
		return store.User{}, &apiError{Status: http.StatusBadRequest, Code: "password_policy", Message: "The password does not meet the password policy", Violations: v}
	}
	hash, err := policy.HashPassword(password)
	if err != nil {
		return store.User{}, err
	}
	now := a.now()
	u, err := a.newLocalUser(ctx, store.User{Username: in.Username, Name: in.Name, Email: in.Email, Source: "local", SPARole: "admin",
		PasswordChangedAt: &now}, hash)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return u, fail(http.StatusConflict, "username_taken", "This user name is taken")
		}
		return u, err
	}
	a.st.Audit(ctx, "spa", "user.created", u.Username, ip, map[string]any{"setup": true, "spa_role": "admin"})
	return u, nil
}

// SetupSettings is what the wizard asks after the administrator.
type SetupSettings struct {
	Organization   *string
	PublicURL      *string
	TrustedProxies *[]string
}

// SetupGeneral saves settings from the wizard.
func (a *App) SetupGeneral(ctx context.Context, s SetupSettings, ip string) (General, error) {
	g, err := a.UpdateGeneral(ctx, func(g *General) {
		if s.Organization != nil {
			g.Organization = *s.Organization
		}
		if s.PublicURL != nil {
			g.PublicURL = *s.PublicURL
		}
		if s.TrustedProxies != nil {
			g.TrustedProxies = *s.TrustedProxies
		}
	})
	if err != nil {
		return g, err
	}
	a.st.Audit(ctx, "spa", "settings.general", "", ip, map[string]any{"setup": true, "public_url": g.PublicURL, "trusted_proxies": g.TrustedProxies})
	return g, nil
}

// SetupFinished records the end of the wizard.
func (a *App) SetupFinished(ctx context.Context, ip string) error {
	if err := a.SetSetupStep(ctx, SetupDone); err != nil {
		return err
	}
	a.st.Audit(ctx, "spa", "setup.finished", "", ip, map[string]any{"at": a.now().UTC().Format(time.RFC3339)})
	return nil
}

// Store is the database of Keystone (the wizard checks it).
func (a *App) Store() *store.Store { return a.st }

// ClientIP is the address of the person (X-Forwarded-For from a trusted proxy).
func (a *App) ClientIP(r *http.Request) string { return a.clientIP(r) }

// Trusted tells whether the request came through a trusted proxy.
func (a *App) Trusted(r *http.Request) bool { return a.trusted(r) }
