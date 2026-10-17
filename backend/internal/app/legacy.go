package app

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
)

// LegacySettings are the settings an older version took from the environment (SPA_PUBLIC_URL, SPA_TRUSTED_PROXIES,
// SPA_SESSION_HOURS). They are taken over into the general settings once, when Keystone starts without bootstrap.json;
// values already in the settings win.
type LegacySettings struct {
	PublicURL      string
	TrustedProxies string // comma-separated
	SessionHours   string
}

func (l LegacySettings) empty() bool {
	return l.PublicURL == "" && l.TrustedProxies == "" && l.SessionHours == ""
}

// ImportLegacySettings takes LegacySettings over into the general settings.
func (a *App) ImportLegacySettings(ctx context.Context, l LegacySettings) error {
	if l.empty() {
		return nil
	}
	taken := []string{}
	g, err := a.UpdateGeneral(ctx, func(g *General) {
		if l.PublicURL != "" && g.PublicURL == "" {
			g.PublicURL = l.PublicURL
			taken = append(taken, "SPA_PUBLIC_URL")
		}
		if l.TrustedProxies != "" && len(g.TrustedProxies) == 0 {
			g.TrustedProxies = strings.Split(l.TrustedProxies, ",")
			taken = append(taken, "SPA_TRUSTED_PROXIES")
		}
		if h, err := strconv.Atoi(strings.TrimSpace(l.SessionHours)); err == nil && h > 0 {
			g.SessionHours = h
			taken = append(taken, "SPA_SESSION_HOURS")
		}
	})
	if err != nil {
		return err
	}
	if len(taken) > 0 {
		a.st.Audit(ctx, "spa", "settings.imported", "", "", map[string]any{"from": taken, "public_url": g.PublicURL})
		slog.Warn("took settings over from the environment into Keystone's settings; change them in Settings → General from now on, and remove them from .env", "variables", taken)
	}
	return nil
}
