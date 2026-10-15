package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/sbrw-evc/spa/internal/passkey"
)

// ---- groups

type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Source      string    `json:"source"`
	Members     int       `json:"members"`
	CreatedAt   time.Time `json:"created_at"`
}

func (s *Store) Groups(ctx context.Context) ([]Group, error) {
	rows, err := s.DB.Query(ctx, `SELECT g.id, g.name, g.description, g.source, count(m.user_id), g.created_at
		FROM groups g LEFT JOIN group_members m ON m.group_id = g.id GROUP BY g.id ORDER BY lower(g.name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.Source, &g.Members, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) GroupByID(ctx context.Context, id string) (Group, error) {
	var g Group
	err := s.DB.QueryRow(ctx, `SELECT g.id, g.name, g.description, g.source, (SELECT count(*) FROM group_members WHERE group_id = g.id), g.created_at
		FROM groups g WHERE g.id = $1`, id).Scan(&g.ID, &g.Name, &g.Description, &g.Source, &g.Members, &g.CreatedAt)
	return g, mapErr(err)
}

func (s *Store) CreateGroup(ctx context.Context, g Group) (Group, error) {
	if g.ID == "" {
		g.ID = NewID("grp")
	}
	if g.Source == "" {
		g.Source = "local"
	}
	if _, err := s.DB.Exec(ctx, `INSERT INTO groups (id, name, description, source) VALUES ($1, $2, $3, $4)`, g.ID, g.Name, g.Description, g.Source); err != nil {
		return Group{}, mapErr(err)
	}
	return s.GroupByID(ctx, g.ID)
}

func (s *Store) UpdateGroup(ctx context.Context, g Group) error {
	tag, err := s.DB.Exec(ctx, `UPDATE groups SET name = $2, description = $3 WHERE id = $1`, g.ID, g.Name, g.Description)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	if _, err := s.DB.Exec(ctx, `DELETE FROM role_assignments WHERE subject_type = 'group' AND subject_id = $1`, id); err != nil {
		return err
	}
	tag, err := s.DB.Exec(ctx, `DELETE FROM groups WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GroupMembers lists the IDs of the members of a group.
func (s *Store) GroupMembers(ctx context.Context, id string) ([]string, error) {
	return s.strings(ctx, `SELECT user_id FROM group_members WHERE group_id = $1 ORDER BY user_id`, id)
}

func (s *Store) SetGroupMembers(ctx context.Context, id string, users []string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `DELETE FROM group_members WHERE group_id = $1`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO group_members (group_id, user_id) SELECT $1, u FROM unnest($2::text[]) u
		WHERE EXISTS (SELECT 1 FROM users WHERE id = u) ON CONFLICT DO NOTHING`, id, users); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// UserGroups lists the names of the groups of a person.
func (s *Store) UserGroups(ctx context.Context, userID string) ([]string, error) {
	return s.strings(ctx, `SELECT g.name FROM groups g JOIN group_members m ON m.group_id = g.id WHERE m.user_id = $1 ORDER BY lower(g.name)`, userID)
}

// UserGroupIDs lists the IDs of the groups of a person.
func (s *Store) UserGroupIDs(ctx context.Context, userID string) ([]string, error) {
	return s.strings(ctx, `SELECT group_id FROM group_members WHERE user_id = $1`, userID)
}

// DirGroup is a group of a directory or provider: its ID there (a DN, an Entra object ID, a claim value) and name.
type DirGroup struct {
	ExternalID string
	Name       string
}

// SyncDirectoryGroups makes the person a member of exactly these groups of source (created when missing, matched by
// their ID in the directory, so renaming them in SPA keeps them); memberships in groups of other sources are kept.
func (s *Store) SyncDirectoryGroups(ctx context.Context, userID, source string, groups []DirGroup) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	ids := []string{}
	for _, g := range groups {
		if g.ExternalID == "" {
			continue
		}
		var id string
		err := tx.QueryRow(ctx, `SELECT id FROM groups WHERE source = $1 AND external_id = $2`, source, g.ExternalID).Scan(&id)
		if err != nil {
			id = NewID("grp")
			name := g.Name
			if name == "" {
				name = g.ExternalID
			}
			var taken bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM groups WHERE lower(name) = lower($1))`, name).Scan(&taken); err != nil {
				return err
			}
			if taken {
				name = name + " (" + source + ")"
			}
			if _, err := tx.Exec(ctx, `INSERT INTO groups (id, name, source, external_id) VALUES ($1, $2, $3, $4)`, id, name, source, g.ExternalID); err != nil {
				return mapErr(err)
			}
		}
		ids = append(ids, id)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM group_members m USING groups g WHERE m.group_id = g.id AND m.user_id = $1
		AND g.source = $2 AND NOT (g.id = ANY($3::text[]))`, userID, source, ids); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO group_members (group_id, user_id) SELECT g, $1 FROM unnest($2::text[]) g ON CONFLICT DO NOTHING`, userID, ids); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) strings(ctx context.Context, sql string, args ...any) ([]string, error) {
	rows, err := s.DB.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ---- passkeys

const passkeyCols = `id, name, credential_id, public_key, user_handle, sign_count, coalesce(aaguid, ''::bytea), transports,
	backup_eligible, backup_state, created_at, last_used_at`

func (s *Store) Passkeys(ctx context.Context, userID string) ([]passkey.Passkey, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+passkeyCols+` FROM passkeys WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []passkey.Passkey{}
	for rows.Next() {
		var k passkey.Passkey
		var count int64
		if err := rows.Scan(&k.ID, &k.Name, &k.CredentialID, &k.PublicKey, &k.UserHandle, &count, &k.AAGUID, &k.Transports,
			&k.BackupEligible, &k.BackupState, &k.CreatedAt, &k.LastUsedAt); err != nil {
			return nil, err
		}
		k.SignCount = uint32(count)
		out = append(out, k)
	}
	return out, rows.Err()
}

// PasskeyOwner finds the person of a credential.
func (s *Store) PasskeyOwner(ctx context.Context, credentialID []byte) (string, error) {
	var id string
	err := s.DB.QueryRow(ctx, `SELECT user_id FROM passkeys WHERE credential_id = $1`, credentialID).Scan(&id)
	return id, mapErr(err)
}

func (s *Store) AddPasskey(ctx context.Context, userID string, k passkey.Passkey) error {
	if k.Transports == nil {
		k.Transports = []string{}
	}
	_, err := s.DB.Exec(ctx, `INSERT INTO passkeys (id, user_id, name, credential_id, public_key, user_handle, sign_count, aaguid,
		transports, backup_eligible, backup_state) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		k.ID, userID, k.Name, k.CredentialID, k.PublicKey, k.UserHandle, int64(k.SignCount), k.AAGUID, k.Transports, k.BackupEligible, k.BackupState)
	return mapErr(err)
}

func (s *Store) PasskeyUsed(ctx context.Context, id string, count uint32, backedUp bool) error {
	_, err := s.DB.Exec(ctx, `UPDATE passkeys SET sign_count = $2, backup_state = $3, last_used_at = now() WHERE id = $1`, id, int64(count), backedUp)
	return err
}

func (s *Store) RenamePasskey(ctx context.Context, userID, id, name string) error {
	tag, err := s.DB.Exec(ctx, `UPDATE passkeys SET name = $3 WHERE id = $2 AND user_id = $1`, userID, id, name)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// DeletePasskeys removes one passkey of a person, or all of them when id is empty.
func (s *Store) DeletePasskeys(ctx context.Context, userID, id string) (int64, error) {
	tag, err := s.DB.Exec(ctx, `DELETE FROM passkeys WHERE user_id = $1 AND ($2 = '' OR id = $2)`, userID, id)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *Store) CountPasskeys(ctx context.Context) (n int, err error) {
	err = s.DB.QueryRow(ctx, `SELECT count(*) FROM passkeys`).Scan(&n)
	return
}

// ---- sessions

type Session struct {
	ID         string    `json:"id"`
	UserID     string    `json:"-"`
	Method     string    `json:"method"`
	MFA        bool      `json:"mfa"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

const sessionCols = `id, user_id, method, mfa, ip, user_agent, created_at, last_seen_at, expires_at`

func (s *Store) CreateSession(ctx context.Context, x Session) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO sessions (id, user_id, method, mfa, ip, user_agent, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		x.ID, x.UserID, x.Method, x.MFA, x.IP, x.UserAgent, x.ExpiresAt)
	return err
}

func (s *Store) SessionByID(ctx context.Context, id string) (Session, error) {
	var x Session
	err := s.DB.QueryRow(ctx, `SELECT `+sessionCols+` FROM sessions WHERE id = $1 AND expires_at > now()`, id).Scan(
		&x.ID, &x.UserID, &x.Method, &x.MFA, &x.IP, &x.UserAgent, &x.CreatedAt, &x.LastSeenAt, &x.ExpiresAt)
	return x, mapErr(err)
}

func (s *Store) TouchSession(ctx context.Context, id string) {
	s.DB.Exec(ctx, `UPDATE sessions SET last_seen_at = now() WHERE id = $1 AND last_seen_at < now() - interval '1 minute'`, id) //nolint:errcheck
}

func (s *Store) UserSessions(ctx context.Context, userID string) ([]Session, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+sessionCols+` FROM sessions WHERE user_id = $1 AND expires_at > now() ORDER BY last_seen_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Session{}
	for rows.Next() {
		var x Session
		if err := rows.Scan(&x.ID, &x.UserID, &x.Method, &x.MFA, &x.IP, &x.UserAgent, &x.CreatedAt, &x.LastSeenAt, &x.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// DeleteSessions ends one session of a person, all of them (id empty), or all but keep.
func (s *Store) DeleteSessions(ctx context.Context, userID, id, keep string) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1 AND ($2 = '' OR id = $2 OR left(id, 16) = $2) AND id <> $3`, userID, id, keep)
	return err
}

func (s *Store) PurgeExpired(ctx context.Context) {
	s.DB.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()`)    //nolint:errcheck
	s.DB.Exec(ctx, `DELETE FROM oauth_codes WHERE expires_at < now()`) //nolint:errcheck
}

// ---- applications

type Role struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type Application struct {
	ID             string     `json:"id"`
	Type           string     `json:"type"`
	Name           string     `json:"name"`
	BaseURL        string     `json:"base_url"`
	RedirectURIs   []string   `json:"redirect_uris"`
	LogoutURIs     []string   `json:"logout_uris"`
	ClientID       string     `json:"client_id"`
	SecretHash     string     `json:"-"`
	TokenHash      string     `json:"-"`
	Roles          []Role     `json:"roles"`
	DefaultRole    string     `json:"default_role"`
	RolesPublished *time.Time `json:"roles_published,omitempty"`
	LastSyncAt     *time.Time `json:"last_sync_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

const appCols = `id, type, name, base_url, redirect_uris, logout_uris, client_id, secret_hash, token_hash, roles, default_role,
	roles_published, last_sync_at, created_at, updated_at`

type scanner interface{ Scan(...any) error }

func scanApp(row scanner) (Application, error) {
	var a Application
	var roles []byte
	err := row.Scan(&a.ID, &a.Type, &a.Name, &a.BaseURL, &a.RedirectURIs, &a.LogoutURIs, &a.ClientID, &a.SecretHash, &a.TokenHash,
		&roles, &a.DefaultRole, &a.RolesPublished, &a.LastSyncAt, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return a, mapErr(err)
	}
	json.Unmarshal(roles, &a.Roles) //nolint:errcheck
	if a.Roles == nil {
		a.Roles = []Role{}
	}
	return a, nil
}

func (s *Store) Applications(ctx context.Context) ([]Application, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+appCols+` FROM applications ORDER BY lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Application{}
	for rows.Next() {
		a, err := scanApp(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) ApplicationByID(ctx context.Context, id string) (Application, error) {
	return scanApp(s.DB.QueryRow(ctx, `SELECT `+appCols+` FROM applications WHERE id = $1`, id))
}

func (s *Store) ApplicationByClientID(ctx context.Context, clientID string) (Application, error) {
	return scanApp(s.DB.QueryRow(ctx, `SELECT `+appCols+` FROM applications WHERE client_id = $1`, clientID))
}

func (s *Store) ApplicationByToken(ctx context.Context, tokenHash string) (Application, error) {
	return scanApp(s.DB.QueryRow(ctx, `SELECT `+appCols+` FROM applications WHERE token_hash = $1`, tokenHash))
}

func (s *Store) SaveApplication(ctx context.Context, a Application) error {
	roles, _ := json.Marshal(a.Roles)
	if a.RedirectURIs == nil {
		a.RedirectURIs = []string{}
	}
	if a.LogoutURIs == nil {
		a.LogoutURIs = []string{}
	}
	_, err := s.DB.Exec(ctx, `INSERT INTO applications (id, type, name, base_url, redirect_uris, logout_uris, client_id, secret_hash, token_hash,
		roles, default_role, roles_published) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (id) DO UPDATE SET type = excluded.type, name = excluded.name, base_url = excluded.base_url,
		redirect_uris = excluded.redirect_uris, logout_uris = excluded.logout_uris, secret_hash = excluded.secret_hash,
		token_hash = excluded.token_hash, roles = excluded.roles, default_role = excluded.default_role,
		roles_published = excluded.roles_published, updated_at = now()`,
		a.ID, a.Type, a.Name, a.BaseURL, a.RedirectURIs, a.LogoutURIs, a.ClientID, a.SecretHash, a.TokenHash, roles, a.DefaultRole, a.RolesPublished)
	return mapErr(err)
}

func (s *Store) ApplicationSynced(ctx context.Context, id string) {
	s.DB.Exec(ctx, `UPDATE applications SET last_sync_at = now() WHERE id = $1`, id) //nolint:errcheck
}

func (s *Store) DeleteApplication(ctx context.Context, id string) error {
	tag, err := s.DB.Exec(ctx, `DELETE FROM applications WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---- role assignments

type Assignment struct {
	ID          int64  `json:"id"`
	AppID       string `json:"app_id"`
	SubjectType string `json:"subject_type"`
	SubjectID   string `json:"subject_id"`
	SubjectName string `json:"subject_name"`
	Role        string `json:"role"`
}

func (s *Store) Assignments(ctx context.Context, appID string) ([]Assignment, error) {
	rows, err := s.DB.Query(ctx, `SELECT a.id, a.app_id, a.subject_type, a.subject_id,
		coalesce(CASE a.subject_type WHEN 'user' THEN (SELECT coalesce(nullif(name, ''), username) FROM users WHERE id = a.subject_id)
		ELSE (SELECT name FROM groups WHERE id = a.subject_id) END, '?'), a.role
		FROM role_assignments a WHERE ($1 = '' OR a.app_id = $1) ORDER BY a.app_id, a.subject_type DESC, a.id`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Assignment{}
	for rows.Next() {
		var a Assignment
		if err := rows.Scan(&a.ID, &a.AppID, &a.SubjectType, &a.SubjectID, &a.SubjectName, &a.Role); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetAssignments replaces the assignments of an application.
func (s *Store) SetAssignments(ctx context.Context, appID string, list []Assignment) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `DELETE FROM role_assignments WHERE app_id = $1`, appID); err != nil {
		return err
	}
	for _, a := range list {
		if _, err := tx.Exec(ctx, `INSERT INTO role_assignments (app_id, subject_type, subject_id, role) VALUES ($1, $2, $3, $4)
			ON CONFLICT DO NOTHING`, appID, a.SubjectType, a.SubjectID, a.Role); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// UserAppRoles returns, for every application, the roles a person holds directly or through groups.
func (s *Store) UserAppRoles(ctx context.Context, userID string) (map[string][]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT DISTINCT a.app_id, a.role FROM role_assignments a
		WHERE (a.subject_type = 'user' AND a.subject_id = $1)
		   OR (a.subject_type = 'group' AND a.subject_id IN (SELECT group_id FROM group_members WHERE user_id = $1))
		ORDER BY a.app_id, a.role`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var app, role string
		if err := rows.Scan(&app, &role); err != nil {
			return nil, err
		}
		out[app] = append(out[app], role)
	}
	return out, rows.Err()
}

// AppUserRoles returns the roles of every person who holds at least one in the application.
func (s *Store) AppUserRoles(ctx context.Context, appID string) (map[string][]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT DISTINCT u.user_id, a.role FROM role_assignments a
		JOIN LATERAL (SELECT a.subject_id AS user_id WHERE a.subject_type = 'user'
		              UNION SELECT m.user_id FROM group_members m WHERE a.subject_type = 'group' AND m.group_id = a.subject_id) u ON true
		WHERE a.app_id = $1 ORDER BY 1, 2`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var u, role string
		if err := rows.Scan(&u, &role); err != nil {
			return nil, err
		}
		out[u] = append(out[u], role)
	}
	return out, rows.Err()
}

// ---- authorization codes

type Code struct {
	Hash        string
	AppID       string
	UserID      string
	SessionID   string
	RedirectURI string
	Nonce       string
	Challenge   string
	Scope       string
	ExpiresAt   time.Time
}

func (s *Store) PutCode(ctx context.Context, c Code) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO oauth_codes (code_hash, app_id, user_id, session_id, redirect_uri, nonce, challenge, scope, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, c.Hash, c.AppID, c.UserID, c.SessionID, c.RedirectURI, c.Nonce, c.Challenge, c.Scope, c.ExpiresAt)
	return err
}

// TakeCode returns the code and deletes it: a code is redeemed once.
func (s *Store) TakeCode(ctx context.Context, hash string) (Code, error) {
	var c Code
	err := s.DB.QueryRow(ctx, `DELETE FROM oauth_codes WHERE code_hash = $1 RETURNING code_hash, app_id, user_id, session_id, redirect_uri,
		nonce, challenge, scope, expires_at`, hash).Scan(&c.Hash, &c.AppID, &c.UserID, &c.SessionID, &c.RedirectURI, &c.Nonce, &c.Challenge, &c.Scope, &c.ExpiresAt)
	return c, mapErr(err)
}

// ---- sealed secrets (when no OpenBao)

func (s *Store) Sealed(ctx context.Context, path string) ([]byte, error) {
	var b []byte
	err := s.DB.QueryRow(ctx, `SELECT sealed FROM secrets WHERE path = $1`, path).Scan(&b)
	return b, mapErr(err)
}

func (s *Store) PutSealed(ctx context.Context, path string, b []byte) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO secrets (path, sealed) VALUES ($1, $2) ON CONFLICT (path) DO UPDATE SET sealed = excluded.sealed, updated_at = now()`, path, b)
	return err
}

func (s *Store) DeleteSealed(ctx context.Context, path string) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM secrets WHERE path = $1`, path)
	return err
}

// ---- passkey ceremonies (passkey.Keeper)

// Ceremonies keeps started passkey ceremonies in the database.
type Ceremonies struct{ S *Store }

func (c Ceremonies) Put(id string, data []byte, expiry time.Time) error {
	ctx := context.Background()
	c.S.DB.Exec(ctx, `DELETE FROM passkey_ceremonies WHERE expires_at < now()`) //nolint:errcheck
	_, err := c.S.DB.Exec(ctx, `INSERT INTO passkey_ceremonies (id, data, expires_at) VALUES ($1, $2, $3)`, id, data, expiry)
	return err
}

func (c Ceremonies) Take(id string) ([]byte, bool) {
	var data []byte
	err := c.S.DB.QueryRow(context.Background(), `DELETE FROM passkey_ceremonies WHERE id = $1 AND expires_at > now() RETURNING data`, id).Scan(&data)
	return data, err == nil
}
