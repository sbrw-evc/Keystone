-- Started passkey ceremonies, so that any replica of SPA accepts the answer (once).
CREATE TABLE passkey_ceremonies (
    id         text PRIMARY KEY,
    data       bytea NOT NULL,
    expires_at timestamptz NOT NULL
);
