-- The second factor of password sign-in: an authenticator app (TOTP). The secret itself is in the secret store
-- (OpenBao or sealed in the secrets table, path totp/<user id>); here only whether it is on, and the last time step
-- accepted, so that a code is never accepted twice.
CREATE TABLE totp (
    user_id    text PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    enabled_at timestamptz NOT NULL DEFAULT now(),
    last_step  bigint NOT NULL DEFAULT 0
);

-- One-time recovery codes, as keyed hashes (HMAC-SHA256).
CREATE TABLE recovery_codes (
    id        bigserial PRIMARY KEY,
    user_id   text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash text NOT NULL,
    used_at   timestamptz
);
CREATE INDEX recovery_codes_user_idx ON recovery_codes (user_id);
