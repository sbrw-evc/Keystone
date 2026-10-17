-- Passwords and secrets leave the database for the secret store (OpenBao): password hashes and their history,
-- recovery codes, the hashes of client secrets and federation tokens. Keystone moves the values at its first start
-- with this version and then drops the columns and tables (store.DropLegacySecrets); until then they get defaults so
-- that new rows need no value.
ALTER TABLE users ALTER COLUMN password_hash SET DEFAULT '';
ALTER TABLE applications ALTER COLUMN secret_hash SET DEFAULT '';
ALTER TABLE applications ALTER COLUMN token_hash SET DEFAULT '';

-- The window in which an application may move its local users to Keystone (POST /api/spa/v1/users/import).
ALTER TABLE applications ADD COLUMN user_import_until timestamptz;
