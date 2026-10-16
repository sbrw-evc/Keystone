-- Keystone (formerly SPA): people, groups, sign-in, applications and their roles.

CREATE TABLE users (
    id                  text PRIMARY KEY,
    username            text NOT NULL,
    email               text NOT NULL DEFAULT '',
    name                text NOT NULL DEFAULT '',
    -- local, ldap, entra, google, apple, oidc
    source              text NOT NULL DEFAULT 'local',
    external_id         text,
    password_hash       text NOT NULL DEFAULT '',
    password_changed_at timestamptz,
    must_change         boolean NOT NULL DEFAULT false,
    disabled            boolean NOT NULL DEFAULT false,
    -- the person's role in Keystone itself: admin, auditor (read-only), user
    spa_role            text NOT NULL DEFAULT 'user' CHECK (spa_role IN ('admin', 'auditor', 'user')),
    failed_attempts     integer NOT NULL DEFAULT 0,
    locked_until        timestamptz,
    last_sign_in_at     timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_username_key ON users (lower(username));
CREATE UNIQUE INDEX users_external_key ON users (source, external_id) WHERE external_id IS NOT NULL;
CREATE INDEX users_email_idx ON users (lower(email));

CREATE TABLE password_history (
    id            bigserial PRIMARY KEY,
    user_id       text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    password_hash text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX password_history_user_idx ON password_history (user_id, created_at DESC);

CREATE TABLE passkeys (
    id              text PRIMARY KEY,
    user_id         text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name            text NOT NULL DEFAULT '',
    credential_id   bytea NOT NULL UNIQUE,
    public_key      bytea NOT NULL,
    user_handle     bytea NOT NULL,
    sign_count      bigint NOT NULL DEFAULT 0,
    aaguid          bytea,
    transports      text[] NOT NULL DEFAULT '{}',
    backup_eligible boolean NOT NULL DEFAULT false,
    backup_state    boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz
);
CREATE INDEX passkeys_user_idx ON passkeys (user_id);

CREATE TABLE groups (
    id          text PRIMARY KEY,
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    -- local, ldap, entra: directory groups are filled at sign-in
    source      text NOT NULL DEFAULT 'local',
    external_id text,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX groups_name_key ON groups (lower(name));

CREATE TABLE group_members (
    group_id text NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    user_id  text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX group_members_user_idx ON group_members (user_id);

CREATE TABLE sessions (
    id           text PRIMARY KEY, -- SHA-256 of the cookie value
    user_id      text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    method       text NOT NULL DEFAULT 'pwd',
    mfa          boolean NOT NULL DEFAULT false,
    ip           text NOT NULL DEFAULT '',
    user_agent   text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL
);
CREATE INDEX sessions_user_idx ON sessions (user_id);

CREATE TABLE applications (
    id               text PRIMARY KEY,
    type             text NOT NULL,
    name             text NOT NULL,
    base_url         text NOT NULL DEFAULT '',
    redirect_uris    text[] NOT NULL DEFAULT '{}',
    logout_uris      text[] NOT NULL DEFAULT '{}',
    client_id        text NOT NULL UNIQUE,
    secret_hash      text NOT NULL,
    token_hash       text NOT NULL,
    -- the role catalogue: [{"id","name","description"}]; published by the application or set by hand
    roles            jsonb NOT NULL DEFAULT '[]',
    default_role     text NOT NULL DEFAULT '',
    roles_published  timestamptz,
    last_sync_at     timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

-- Who gets which role of an application: a user or a group.
CREATE TABLE role_assignments (
    id           bigserial PRIMARY KEY,
    app_id       text NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    subject_type text NOT NULL CHECK (subject_type IN ('user', 'group')),
    subject_id   text NOT NULL,
    role         text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (app_id, subject_type, subject_id, role)
);
CREATE INDEX role_assignments_subject_idx ON role_assignments (subject_type, subject_id);

CREATE TABLE oauth_codes (
    code_hash    text PRIMARY KEY,
    app_id       text NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    user_id      text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    session_id   text NOT NULL,
    redirect_uri text NOT NULL,
    nonce        text NOT NULL DEFAULT '',
    challenge    text NOT NULL,
    scope        text NOT NULL DEFAULT '',
    expires_at   timestamptz NOT NULL
);

CREATE TABLE settings (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Secrets when no OpenBao is configured: AES-256-GCM with the master key.
CREATE TABLE secrets (
    path       text PRIMARY KEY,
    sealed     bytea NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit (
    id     bigserial PRIMARY KEY,
    at     timestamptz NOT NULL DEFAULT now(),
    actor  text NOT NULL DEFAULT '',
    action text NOT NULL,
    target text NOT NULL DEFAULT '',
    detail jsonb NOT NULL DEFAULT '{}',
    ip     text NOT NULL DEFAULT ''
);
CREATE INDEX audit_at_idx ON audit (at DESC);
