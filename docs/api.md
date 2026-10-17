# Keystone HTTP API

Keystone was called SPA before; the identifiers of this API keep the historical `spa` spelling (`/api/spa/v1/`,
`spa_session`, `X-Requested-With: spa`, `spa_role`, `spa_admin`, the `spa1.` key prefix, client IDs `spa_…`).

Keystone answers on one address (`SPA_PUBLIC_URL`, the OpenID Connect issuer) with four interfaces:

| | prefix | used by | authentication |
| --- | --- | --- | --- |
| [OpenID Connect provider](#1-openid-connect-provider) | `/.well-known/`, `/oauth2/` | applications, browsers | client ID + secret; Bearer access token |
| [Federation API](#2-federation-api) | `/api/spa/v1/` | applications (server to server) | `Authorization: Bearer <federation token>` |
| [Web app API](#3-web-app-api-apiv1) | `/api/v1/` | Keystone's own web app | session cookie `spa_session` + CSRF header |
| health | `GET /healthz` | load balancers | none |

Everything else serves the web app (`SPA_WEB_DIR`): existing files as they are, any other path gets `index.html`.
The protocol between Keystone and the applications — what they do with this API — is in [protocol.md](protocol.md).

Every answer carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, a
strict `Content-Security-Policy` and, on https, `Strict-Transport-Security`. JSON answers of `/api/` and `/oauth2/`
are `Cache-Control: no-store` unless stated otherwise.

## Errors

`/api/v1/` and `/api/spa/v1/` answer errors with an HTTP status and:

```json
{"code": "password_policy", "message": "The password does not meet the password policy", "violations": ["length", "digits"]}
```

`code` is stable (the web app branches on it), `message` is English. `violations` (password policy: `length`,
`digits`, `special`, `mixed_case`, `letters`, `username`, `control`, `common`, `history`) and `extra` appear when
they apply. Common codes: `unauthorized` (401, sign in first), `forbidden` (403, the Keystone role is too low),
`not_found` (404), `bad_request` (400, not JSON), `csrf` (403), `conflict` (409), `internal` (500).

The OAuth endpoints (`/oauth2/token`, `/oauth2/userinfo`) answer errors as OAuth does:
`{"error": "invalid_grant", "error_description": "…"}`.

## 1. OpenID Connect provider

Authorization code flow with PKCE (S256 only). See [protocol.md §2](protocol.md#2-sign-in-openid-connect) for the
claims and the security rules.

### `GET /.well-known/openid-configuration`

```json
{
  "issuer": "https://keystone.example.com",
  "authorization_endpoint": "https://keystone.example.com/oauth2/authorize",
  "token_endpoint": "https://keystone.example.com/oauth2/token",
  "userinfo_endpoint": "https://keystone.example.com/oauth2/userinfo",
  "jwks_uri": "https://keystone.example.com/oauth2/jwks",
  "end_session_endpoint": "https://keystone.example.com/oauth2/logout",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email", "groups", "roles"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
  "code_challenge_methods_supported": ["S256"],
  "claims_supported": ["sub", "name", "preferred_username", "email", "email_verified", "groups", "roles", "amr", "auth_time", "sid", "spa_admin"]
}
```

### `GET /oauth2/jwks`

`{"keys": [<RSA JWK>, …]}` — the current signing key and, after a rotation, the previous one. `Cache-Control:
public, max-age=300`.

### `GET /oauth2/authorize`

| parameter | |
| --- | --- |
| `client_id` | required; unknown → `400 invalid_client` (no redirect) |
| `redirect_uri` | required, exactly one of the registered addresses; else `400 invalid_redirect` (no redirect) |
| `response_type` | `code` |
| `scope` | must contain `openid` |
| `code_challenge`, `code_challenge_method` | required, `S256`, challenge ≥ 43 characters |
| `state`, `nonce` | required |
| `prompt` | `login` asks again even with a Keystone session; `none` fails with `login_required` instead of showing the sign-in page |
| `login_hint` | user name to put into the sign-in form |
| `idp_hint` | `password`, `passkey`, `ldap`, `entra`, `google`, `apple`, `oidc`: open that method directly |

Errors after the client and the redirect address are known go back to the application:
`<redirect_uri>?error=…&error_description=…&state=…&iss=…`.

- With a Keystone session (and no `prompt=login`) Keystone answers `302` to `<redirect_uri>?code=…&state=…&iss=…` — or
  `error=access_denied` when the person has no role in the application.
- Without one Keystone seals the request (30 minutes) and redirects to the web app:
  `/signin?request=<sealed>&app=<name>[&method=<idp_hint>][&login_hint=…]`. The sign-in page passes `request` to
  the sign-in calls below (or to `POST /api/v1/auth/continue`), which then return the application's redirect in
  `next`.

The code lives 60 seconds and is single use.

### `POST /oauth2/token`

Form-encoded. Client authentication: `client_secret_basic` (HTTP Basic, URL-encoded ID and secret) or
`client_secret_post` (`client_id`, `client_secret`).

```
grant_type=authorization_code&code=…&redirect_uri=…&code_verifier=…
```

```json
{"access_token": "<JWT>", "token_type": "Bearer", "expires_in": 600, "id_token": "<JWT>", "scope": "openid profile email groups roles"}
```

The ID token (RS256, 5 minutes) carries `iss`, `aud` (client ID), `iat`, `exp`, `nonce`, `sub`,
`preferred_username`, `name`, `email`, `email_verified`, `roles` (the person's roles in this application),
`groups`, `spa_admin`, `sid`, `auth_time`, `amr`. The access token (10 minutes) is only good for user info.
Errors: `invalid_client` (401), `unsupported_grant_type`, `invalid_grant` (unknown/expired/used code, other
application, other redirect address, PKCE mismatch, disabled account, ended Keystone session, no role).

### `GET|POST /oauth2/userinfo`

`Authorization: Bearer <access token>` → the same person claims as the ID token, without the session claims.
`401 invalid_token` with `WWW-Authenticate: Bearer error="invalid_token"` otherwise.

### `GET /oauth2/logout`

`?post_logout_redirect_uri=…&client_id=…` — ends the Keystone session and redirects to `post_logout_redirect_uri` when it
is a registered sign-out address (or the address) of the application, else to `/signin?signed_out=1`.

## 2. Federation API

`Authorization: Bearer <token>` — the `token` of the application's connection key. `401 unauthorized` when the
token is missing or no longer valid (the key was replaced or the application removed). GET answers carry an
`ETag`; with a matching `If-None-Match` Keystone answers `304 Not Modified`.

### `GET /api/spa/v1/config`

```json
{
  "application": {"id": "app_…", "name": "Network Control", "type": "network-control"},
  "roles": [{"id": "admin", "name": "Administrator", "description": "…"}],
  "methods": [{"id": "password", "title": "Password"}, {"id": "passkey", "title": "Passkey"}],
  "sign_out_url": "https://keystone.example.com/oauth2/logout",
  "account_url": "https://keystone.example.com/profile",
  "user_import": false
}
```

`user_import`: the import window of the application is open (`POST /api/spa/v1/users/import`).

### `GET /api/spa/v1/users`

Everyone with at least one known role in the application, enabled or not, sorted by user name. Records the
synchronisation time of the application.

```json
{"users": [{"id": "usr_…", "username": "jdoe", "email": "jdoe@example.com", "name": "John Doe", "disabled": false,
            "roles": ["operator"], "groups": ["NOC"], "source": "ldap", "updated_at": "2026-10-15T12:00:00Z"}]}
```

### `PUT /api/spa/v1/roles`

```json
{"roles": [{"id": "admin", "name": "Administrator", "description": "Everything"}, {"id": "viewer", "name": "Viewer"}], "default": "viewer"}
```

Role IDs match `[a-z0-9_.:-]{1,64}`, 1–200 roles. Answer: `{"roles": [...]}` as stored.

### `POST /api/spa/v1/users/import`

Moves the local users of the application to Keystone, once; the full contract is in
[protocol.md §3](protocol.md#post-issuerapispav1usersimport). Only while the import window of the application is
open: an administrator opens it (`POST /api/v1/applications/{id}/user-import`), and it closes after the first request
that imports someone, or after 24 hours.

```json
{"users": [{"username": "jdoe", "name": "John Doe", "email": "jdoe@example.com", "role": "operator",
            "password_hash": "$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>"}]}
```

At most 1000 entries. `password_hash`: `pbkdf2-sha256$<iter>$<salt b64>$<key b64>`, Argon2id in the PHC format, or
`null` (an administrator gives the person a temporary password). `role`: one of the application's roles.

Answer `200`:

```json
{"imported": [{"username": "jdoe", "id": "usr_…"}],
 "conflicts": [{"username": "…", "reason": "username_taken|email_taken"}],
 "rejected": [{"username": "…", "reason": "invalid_username|invalid_role|invalid_hash"}]}
```

`401` — the token is not valid; `403 {"error": "import_not_allowed"}` — the window is closed;
`400 {"error": "too_many_users"}` — more than 1000 entries. Existing accounts are never changed; TOTP is not moved.

## 3. Web app API (`/api/v1/`)

JSON in and out. The session is the HttpOnly cookie `spa_session` (`SameSite=Lax`, `Secure` on https) set by the
sign-in calls. **Every request other than GET/HEAD must carry `X-Requested-With: spa`** (a cross-site form cannot
set it); without it Keystone answers `403 csrf`. The provider redirects under `/api/v1/auth/sso/` are exempt.

Keystone roles: `user` < `auditor` < `admin`. In the tables below *public* needs nothing, *person* needs a session,
*auditor* reads administration data, *admin* changes it.

### Sign-in

| | | access |
| --- | --- | --- |
| `GET /api/v1/auth/methods` | `{"organization", "methods": [{"id","title"}], "password_policy": {…}}` — what the sign-in page offers | public |
| `POST /api/v1/auth/password` | `{"username","password","request"?,"return"?}` → `SignedIn` | public |
| `POST /api/v1/auth/password/change` | `{"ticket"?,"current","new"}` | public with a ticket, else person |
| `POST /api/v1/auth/totp` | `{"ticket","code"}` — the code of the authenticator app or a recovery code → `SignedIn` | public with a ticket |
| `POST /api/v1/auth/totp/setup` | `{"ticket"}` → `TotpSetup` — a new secret, when the policy requires a second factor | public with a ticket |
| `POST /api/v1/auth/totp/setup/confirm` | `{"ticket","code"}` → `SignedIn` with `recovery_codes` | public with a ticket |
| `POST /api/v1/auth/passkey/begin` | `{}` → `{"ceremony","options":{"publicKey":{…}}}` (WebAuthn request options, binary fields base64url) | public |
| `POST /api/v1/auth/passkey/finish` | `{"ceremony","credential":<PublicKeyCredential JSON>,"request"?,"return"?}` → `SignedIn` | public |
| `GET /api/v1/auth/sso/{kind}/start` | `?request=…&return=…` → `302` to the provider (`entra`, `google`, `apple`, `oidc`) | public |
| `GET|POST /api/v1/auth/sso/{kind}/callback` | the provider's answer → `302` to `next`, or to `/signin?error=<message>` | public |
| `POST /api/v1/auth/continue` | `{"request"}` → `{"next"}` — finish an application's sign-in with the current session | person |
| `POST /api/v1/auth/logout` | ends the session → `{"ok": true}` | public |

`SignedIn` is `{"user": Account, "next": "<URL>", "recovery_codes"?: [...]}`: `next` is the application's redirect
with the code when `request` was given, else the same-site `return` path (or `/`); `recovery_codes` come only from
`/auth/totp/setup/confirm` and are shown once.

`POST /api/v1/auth/password` checks local accounts, then LDAP / Active Directory (unknown or `ldap` accounts).
Notable errors: `invalid_credentials` (401), `locked` (403), `disabled` (403), `too_many_attempts` (429, 20
attempts per address in 5 minutes), `use_provider` (401, the account signs in with a provider), `local_off`,
`directory_unavailable` (502), `request_expired` (400). When the password of a local account must be changed (set
by an administrator, or expired) the answer is `409 password_change_required` with
`"extra": {"ticket": "…", "expired": true|false}`; the ticket (10 minutes) goes to `/auth/password/change`, which
then answers `SignedIn` like a sign-in. Without a ticket the change needs a session and ends the person's other
sessions (`{"ok": true}`). Errors: `wrong_password`, `password_policy` (with `violations`), `not_local`,
`ticket_expired`.

**Two-step verification.** After a right password (local or LDAP) the sign-in goes through these steps, each
answered `409` with `"extra": {"ticket": "…"}` for the next call, until the session starts:

1. `totp_required` — the person has an authenticator app: `POST /auth/totp` with the ticket (5 minutes) and the
   6-digit code (RFC 6238: HMAC-SHA1, 30 s, ±1 step, each step accepted once) or a recovery code (`xxxxx-xxxxx`,
   case, spaces and dashes ignored, each once).
2. `password_change_required` — as above (its ticket remembers that the code was given).
3. `totp_setup_required` — the password policy (`second_factor`) requires a second factor and the person has none:
   `POST /auth/totp/setup` with the ticket (15 minutes) shows a new secret, `POST /auth/totp/setup/confirm` turns it
   on with its first code and answers `SignedIn` with the ten recovery codes.

The session of a sign-in with a code has `mfa: true` and applications get `amr: ["pwd", "otp", "mfa"]` (`["pwd",
"fed", "otp", "mfa"]` for LDAP). A passkey sign-in never asks for a code. Errors: `wrong_code` (401), `locked` (403:
wrong codes count like wrong passwords: the lockout of the policy, or 20 in a row when it is off), `too_many_attempts`
(429, 20 code attempts per address in 5 minutes), `ticket_expired` (400), `totp_no_setup` (400, confirm without a
started set-up).

Passkey errors: `method_off` (404), `passkey_origin`, `passkey_failed` (401).

### The signed-in person

| | | access |
| --- | --- | --- |
| `GET /api/v1/me` | `Account` | person |
| `GET /api/v1/me/passkeys` | `[Passkey]` | person |
| `POST /api/v1/me/passkeys/begin` | → `{"ceremony","options":{"publicKey":{…}}}` (creation options); `409 passkey_limit` | person |
| `POST /api/v1/me/passkeys/finish` | `{"ceremony","credential","name"?}` → `201 Passkey` | person |
| `PATCH /api/v1/me/passkeys/{id}` | `{"name"}` (1–64 characters) → `{"ok": true}` | person |
| `DELETE /api/v1/me/passkeys/{id}` | `204` | person |
| `GET /api/v1/me/totp` | `TotpState` | person |
| `POST /api/v1/me/totp/setup` | `{"code"?}` → `TotpSetup`; a new secret, pending until confirmed (replacing an app that is on needs a current `code`); `409 totp_not_password` for provider accounts | person |
| `POST /api/v1/me/totp/setup/confirm` | `{"code"}` → `{"recovery_codes": [...]}` (ten, shown once; an earlier app and its codes stop working) | person |
| `POST /api/v1/me/totp/disable` | `{"code"}` (a current code or a recovery code) → `{"ok": true}`; `409 totp_required_by_policy`, `409 totp_off` | person |
| `POST /api/v1/me/totp/recovery-codes` | `{"code"}` → `{"recovery_codes": [...]}`; the old ones stop working | person |
| `GET /api/v1/me/sessions` | `[Session]` | person |
| `DELETE /api/v1/me/sessions/{id}` | `204` (the current session is kept) | person |

```jsonc
// Account
{"id": "usr_…", "username": "jdoe", "name": "John Doe", "email": "…", "source": "local|ldap|entra|google|apple|oidc",
 "spa_role": "user|auditor|admin", "must_change": false, "password_expires_at": "…", "password_expires_soon": false,
 "passkeys": 1, "passkeys_enabled": true, "groups": ["NOC"], "session_method": "pwd|passkey|ldap|entra|…",
 "totp": true, "totp_required": false,
 "applications": [{"id": "app_…", "name": "Ledger", "type": "ledger", "url": "https://…", "roles": ["viewer"]}]}
// Passkey
{"id": "pk_…", "name": "Work laptop", "kind": "device|phone|security_key", "transports": ["internal"],
 "backup_eligible": true, "backup_state": true, "created_at": "…", "last_used_at": "…"}
// TotpState — available: the account signs in with a password; required: by the password policy
{"enabled": true, "enabled_at": "…", "recovery_codes_left": 9, "available": true, "required": false}
// TotpSetup — the key to type, the otpauth:// address and its QR code (PNG)
{"secret": "JBSWY3DPEHPK3PXP…", "uri": "otpauth://totp/Keystone:jdoe?algorithm=SHA1&digits=6&issuer=Keystone&period=30&secret=…",
 "qr": "data:image/png;base64,…"}
// Session (id: the first 16 characters of the session hash)
{"id": "…", "method": "pwd", "mfa": false, "ip": "10.0.0.5", "user_agent": "…", "created_at": "…",
 "last_seen_at": "…", "expires_at": "…", "current": true}
```

### Administration

| | | access |
| --- | --- | --- |
| `GET /api/v1/onboarding` | `{"done", "steps": [{"id","done","optional","path"}]}` — ids `public_url`, `policy`, `passkey`, `directory`, `application`, `roles`, `second_admin` | auditor |
| `GET /api/v1/users` | `[User]` | auditor |
| `POST /api/v1/users` | `UserInput` with `password` → `201 User` (local account, must change the password); `409 username_taken` | admin |
| `PUT /api/v1/users/{id}` | `UserInput` → `User`; disabling ends the person's sessions; `self`, `last_admin` | admin |
| `DELETE /api/v1/users/{id}` | `204` | admin |
| `POST /api/v1/users/{id}/password` | `{"password"}` — temporary password, ends the sessions; `not_local` | admin |
| `POST /api/v1/users/{id}/unlock` | `{"ok": true}` | admin |
| `GET /api/v1/users/{id}/passkeys` | `[Passkey]` | auditor |
| `DELETE /api/v1/users/{id}/passkeys` | `?passkey=<id>` one, else all → `204` | admin |
| `DELETE /api/v1/users/{id}/sessions` | sign the person out everywhere → `204` | admin |
| `DELETE /api/v1/users/{id}/totp` | turn off the person's two-step verification (a lost phone) → `204`; `409 totp_off` | admin |
| `GET /api/v1/groups` | `[Group]` | auditor |
| `POST /api/v1/groups` | `GroupInput` → `201 GroupDetail`; `409 name_taken`, `invalid_dn`, `invalid_group_id` | admin |
| `GET /api/v1/groups/{id}` | `GroupDetail` | auditor |
| `PUT /api/v1/groups/{id}` | `GroupInput` (name, description, members of a local group) → `GroupDetail` | admin |
| `DELETE /api/v1/groups/{id}` | `204` (its role rules go too) | admin |
| `GET /api/v1/applications` | `{"applications": [Application], "types": {type: name}, "presets": {type: [Role]}}` | auditor |
| `POST /api/v1/applications` | `AppInput` + `"assignments"` → `201 Connection` | admin |
| `PUT /api/v1/applications/{id}` | `AppInput` + `"assignments"` (replaces the rules when given) → `Application` | admin |
| `POST /api/v1/applications/{id}/user-import` | `{"allow": true}` opens for 24 hours, `{"allow": false}` closes the window in which the application may move its local users to Keystone → `Application` | admin |
| `POST /api/v1/applications/{id}/key` | → `Connection` with a new key; the old secret and token stop working | admin |
| `DELETE /api/v1/applications/{id}` | `204` | admin |
| `GET /api/v1/audit` | `?q=<text>&before=<id>` → up to 100 `[{"id","at","actor","action","target","detail","ip"}]`, newest first | auditor |

```jsonc
// User (administration view)
{"id": "usr_…", "username": "jdoe", "email": "…", "name": "…", "source": "local", "spa_role": "user",
 "disabled": false, "must_change": true, "locked": false, "locked_until": "…", "last_sign_in_at": "…",
 "password_changed_at": "…", "password_expires_at": "…", "created_at": "…", "updated_at": "…",
 "groups": ["grp_…"], "passkeys": 0, "totp": false, "app_roles": {"app_…": ["viewer"]}}
// UserInput — groups: the local groups of the person (directory groups follow the directory)
{"username": "jdoe", "name": "John Doe", "email": "…", "spa_role": "user", "disabled": false, "password": "…", "groups": ["grp_…"]}
// Group / GroupDetail
{"id": "grp_…", "name": "NOC", "description": "…", "source": "local|ldap|entra|google|apple|oidc", "external_id": "…",
 "members": 4, "created_at": "…", "member_ids": ["usr_…"]}
// GroupInput — source + external_id create a directory group ahead of its members' first sign-in:
// ldap + the group's DN, or entra + the group's object ID
{"name": "Network Admins", "description": "", "members": ["usr_…"], "source": "ldap", "external_id": "CN=Network Admins,OU=Groups,DC=example,DC=com"}
// AppInput — type: beacon | current | ledger | network-control | oidc (the IDs from before the rename,
// umbrella-monitoring | umbrella-flow | inventory-db, are accepted and stored as the new ones).
// For the Umbrella types the redirect address is <base_url>/api/auth/spa/callback; for oidc give redirect_uris.
// roles: the catalogue until the application publishes its own (PUT /api/spa/v1/roles).
{"type": "network-control", "name": "Network Control", "base_url": "https://netctl.example.com",
 "redirect_uris": [], "logout_uris": [], "roles": [{"id": "viewer", "name": "Viewer"}], "default_role": "viewer",
 "assignments": [{"subject_type": "group", "subject_id": "grp_…", "role": "operator"}]}
// Application
{"id": "app_…", "type": "…", "name": "…", "base_url": "…", "redirect_uris": ["…"], "logout_uris": ["…"],
 "client_id": "spa_…", "roles": [Role], "default_role": "", "roles_published": "…", "last_sync_at": "…",
 "user_import_until": "…", // while the import window is open; absent when it is closed
 "created_at": "…", "updated_at": "…", "users": 7, "callback": "https://…/api/auth/spa/callback",
 "assignments": [{"id": 1, "app_id": "app_…", "subject_type": "group", "subject_id": "grp_…", "subject_name": "NOC", "role": "viewer"}]}
// Connection — the key is shown once: spa1.<base64url of {"issuer","client_id","client_secret","token"}>
{"application": Application, "key": "spa1.…"}
```

### Settings

| | | access |
| --- | --- | --- |
| `GET /api/v1/settings/password-policy` | `{"policy": PasswordPolicy, "local_users", "expired_users", "expiring_users", "locked_users"}` | auditor |
| `PUT /api/v1/settings/password-policy` | `PasswordPolicy` → the same as GET; `invalid_policy` | admin |
| `GET /api/v1/settings/general` | `{"general": {"organization","allow_local"}, "passkeys": {"enabled","rp_id"}, "issuer", "secrets": "database|openbao", "public_url_set"}` | auditor |
| `PUT /api/v1/settings/general` | `{"general", "passkeys"}` → the same as GET; `passkey_domain` | admin |
| `POST /api/v1/settings/signing-key/rotate` | new ID token signing key; the previous stays in the JWKS → `{"ok": true}` | admin |
| `GET /api/v1/settings/ldap` | `{"config": LDAPConfig, "bind_password_set"}` | auditor |
| `PUT /api/v1/settings/ldap` | `{"config", "bind_password"?}` → the same as GET; `invalid_directory` | admin |
| `POST /api/v1/settings/ldap/test` | `{"config", "bind_password"?, "test_username"?, "test_password"?}` → `{"ok", "error"?, "probe": {"server","tls","base_dn","admin_group","user_authenticated","user"?}}` | admin |
| `GET /api/v1/settings/entra` | `{"config": EntraConfig, "client_secret_set", "clouds"}` | auditor |
| `PUT /api/v1/settings/entra` | `{"config", "client_secret"?}` → the same as GET; `invalid_entra` | admin |
| `POST /api/v1/settings/entra/test` | `{"config", "client_secret"?}` → `{"ok", "error"?, "probe": {"issuer","tenant_id","credentials"}}` | admin |
| `GET /api/v1/settings/providers` | `[{"kind": "google|apple|oidc", "config": Provider, "client_secret_set", "private_key_set", "redirect_uri"}]` | auditor |
| `PUT /api/v1/settings/providers/{kind}` | `{"config": Provider, "client_secret"?, "private_key"?}` → the list; checks the provider's discovery when enabled | admin |

Secrets (`bind_password`, `client_secret`, `private_key`) are write-only: an empty value keeps the stored one.

```jsonc
// PasswordPolicy (letters: latin | cyrillic | latin_cyrillic | any; 0 turns lifetime, history and lockout off;
// second_factor: optional | admins | everyone — who must use an authenticator app after a password)
{"min_length": 12, "require_digits": true, "min_digits": 1, "require_special": true, "min_special": 1,
 "require_mixed_case": true, "letters": "latin", "max_age_days": 180, "warn_days": 14, "history_count": 5,
 "block_common": true, "lockout_attempts": 5, "lockout_minutes": 15, "second_factor": "admins"}
// LDAPConfig (kind: ad | openldap; {username} in user_filter is what the person types)
{"enabled": true, "kind": "ad", "url": "ldaps://dc.example.com", "start_tls": false, "skip_verify": false,
 "ca_cert": "", "bind_dn": "CN=svc-keystone,…", "base_dn": "DC=example,DC=com",
 "user_filter": "(&(objectCategory=person)(objectClass=user)(sAMAccountName={username}))",
 "username_attr": "sAMAccountName", "name_attr": "displayName", "email_attr": "mail", "first_name_attr": "givenName",
 "last_name_attr": "sn", "middle_name_attr": "middleName", "title_attr": "title", "department_attr": "department",
 "manager_attr": "manager", "photo_attr": "thumbnailPhoto", "admin_group_dn": ""}
// EntraConfig (cloud: global | usgov | china; redirect_url is set by Keystone)
{"enabled": true, "cloud": "global", "tenant_id": "…", "client_id": "…", "redirect_url": "https://keystone…/api/v1/auth/sso/entra/callback",
 "admin_group_id": "", "user_group_id": ""}
// Provider (issuer: fixed for Google and Apple; team_id/key_id for Apple; scopes and groups_claim for oidc)
{"enabled": true, "title": "Keycloak", "issuer": "https://id.example.com/realms/main", "client_id": "…", "team_id": "",
 "key_id": "", "allowed_domains": ["example.com"], "existing_only": false, "scopes": "groups", "groups_claim": "groups"}
```

### Audit actions

`auth.sign_in`, `auth.sign_out`, `auth.sign_in_failed`, `auth.password_changed`, `user.created`, `user.updated`,
`user.deleted`, `user.password_reset`, `user.unlocked`, `user.locked`, `user.linked`, `user.passkeys_removed`,
`user.signed_out`, `user.totp_reset`, `totp.enabled`, `totp.disabled`, `totp.failed`, `totp.recovery_used`,
`totp.recovery_renewed`, `passkey.added`, `passkey.removed`, `group.saved`, `group.deleted`, `application.connected`,
`application.updated`, `application.key_issued`, `application.removed`, `application.roles_published`,
`application.user_import_opened`, `application.user_import_closed`, `application.users_imported`,
`oauth.token`, `oauth.denied`, `settings.password_policy`, `settings.general`, `settings.ldap`, `settings.entra`,
`settings.provider`, `settings.signing_key_rotated`.
