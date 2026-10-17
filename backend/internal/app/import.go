package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/sbrw-evc/keystone/internal/policy"
	"github.com/sbrw-evc/keystone/internal/store"
)

// An application that had local users before it was connected moves them to Keystone once
// (POST /api/spa/v1/users/import, docs/protocol.md §3). An administrator opens the window for it; the window closes
// after the first request that imports someone, or after importWindow.

const (
	importWindow   = 24 * time.Hour
	importMaxUsers = 1000
)

func (a *App) importOpen(app store.Application) bool {
	return app.UserImportUntil != nil && app.UserImportUntil.After(a.now())
}

// fedError is an error of the federation API with the "error" field the protocol names (and code and message as the
// rest of the API).
func fedError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": code, "code": code, "message": message})
}

type importUser struct {
	Username     string  `json:"username"`
	Name         string  `json:"name"`
	Email        string  `json:"email"`
	Role         string  `json:"role"`
	PasswordHash *string `json:"password_hash"`
}

type importDone struct {
	Username string `json:"username"`
	ID       string `json:"id"`
}

type importSkipped struct {
	Username string `json:"username"`
	Reason   string `json:"reason"`
}

func validUsername(u string) bool {
	return u != "" && len(u) <= 128 && !strings.ContainsAny(u, " \t/\\")
}

func (a *App) fedImport(w http.ResponseWriter, r *http.Request, app store.Application) {
	ctx := r.Context()
	var in struct {
		Users []importUser `json:"users"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fedError(w, http.StatusBadRequest, "bad_request", "The request is not valid JSON")
		return
	}
	if len(in.Users) > importMaxUsers {
		fedError(w, http.StatusBadRequest, "too_many_users", "At most 1000 people per request")
		return
	}
	until, err := a.st.TakeUserImport(ctx, app.ID, a.now())
	if err != nil {
		writeError(w, err)
		return
	}
	if until == nil {
		fedError(w, http.StatusForbidden, "import_not_allowed", "A Keystone administrator has not allowed this application to move its users")
		return
	}

	roles := map[string]bool{}
	for _, role := range app.Roles {
		roles[role.ID] = true
	}
	out := struct {
		Imported  []importDone    `json:"imported"`
		Conflicts []importSkipped `json:"conflicts"`
		Rejected  []importSkipped `json:"rejected"`
	}{[]importDone{}, []importSkipped{}, []importSkipped{}}
	seenName, seenEmail := map[string]bool{}, map[string]bool{}
	ip := a.clientIP(r)
	now := a.now()
	for _, u := range in.Users {
		u.Username, u.Name, u.Email, u.Role = strings.TrimSpace(u.Username), strings.TrimSpace(u.Name), strings.TrimSpace(u.Email), strings.TrimSpace(u.Role)
		hash := ""
		if u.PasswordHash != nil {
			hash = strings.TrimSpace(*u.PasswordHash)
		}
		if u.Email != "" && (!strings.Contains(u.Email, "@") || len(u.Email) > 256) {
			u.Email = ""
		}
		reject := func(reason string) { out.Rejected = append(out.Rejected, importSkipped{u.Username, reason}) }
		conflict := func(reason string) { out.Conflicts = append(out.Conflicts, importSkipped{u.Username, reason}) }
		switch {
		case !validUsername(u.Username):
			reject("invalid_username")
			continue
		case !roles[u.Role]:
			reject("invalid_role")
			continue
		case hash != "" && !policy.ValidHash(hash):
			reject("invalid_hash")
			continue
		}
		name, email := strings.ToLower(u.Username), strings.ToLower(u.Email)
		if seenName[name] {
			conflict("username_taken")
			continue
		}
		if _, err := a.st.UserByUsername(ctx, u.Username); err == nil {
			conflict("username_taken")
			continue
		} else if !errors.Is(err, store.ErrNotFound) {
			writeError(w, err)
			return
		}
		if email != "" {
			same, err := a.st.UsersByEmail(ctx, u.Email)
			if err != nil {
				writeError(w, err)
				return
			}
			if seenEmail[email] || len(same) > 0 {
				conflict("email_taken")
				continue
			}
		}
		nu := store.User{Username: u.Username, Name: u.Name, Email: u.Email, Source: "local", SPARole: "user", MustChange: hash == ""}
		if hash != "" {
			nu.PasswordChangedAt = &now
		}
		created, err := a.newLocalUser(ctx, nu, hash)
		if errors.Is(err, store.ErrConflict) {
			conflict("username_taken")
			continue
		}
		if err != nil {
			writeError(w, err)
			return
		}
		seenName[name] = true
		if email != "" {
			seenEmail[email] = true
		}
		if err := a.st.AddAssignment(ctx, app.ID, "user", created.ID, u.Role); err != nil {
			writeError(w, err)
			return
		}
		a.st.Audit(ctx, app.Name, "user.created", created.Username, ip, map[string]any{"source": "import", "application": app.Name,
			"role": u.Role, "password": hash != ""})
		out.Imported = append(out.Imported, importDone{created.Username, created.ID})
	}

	if len(out.Imported) == 0 {
		// nobody moved: the window stays open as it was
		if err := a.st.SetUserImport(ctx, app.ID, until); err != nil {
			writeError(w, err)
			return
		}
	} else {
		a.st.Audit(ctx, app.Name, "application.user_import_closed", app.Name, ip, map[string]any{"reason": "used"})
	}
	a.st.Audit(ctx, app.Name, "application.users_imported", app.Name, ip, map[string]any{"imported": len(out.Imported),
		"conflicts": len(out.Conflicts), "rejected": len(out.Rejected)})
	writeJSON(w, http.StatusOK, out)
}

// allowUserImport opens (for importWindow) or closes the window in which the application may move its users here.
func (a *App) allowUserImport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app, err := a.st.ApplicationByID(ctx, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	var in struct {
		Allow bool `json:"allow"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	var until *time.Time
	action, detail := "application.user_import_closed", map[string]any{"reason": "administrator"}
	if in.Allow {
		t := a.now().Add(importWindow)
		until, action, detail = &t, "application.user_import_opened", map[string]any{"until": t.UTC().Format(time.RFC3339)}
	}
	if err := a.st.SetUserImport(ctx, app.ID, until); err != nil {
		writeError(w, err)
		return
	}
	a.st.Audit(ctx, actor(r), action, app.Name, a.clientIP(r), detail)
	app, err = a.st.ApplicationByID(ctx, app.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	v, err := a.appView(ctx, app)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
