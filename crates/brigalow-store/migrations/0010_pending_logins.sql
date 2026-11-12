-- Shared, single-use pending OIDC logins. The PKCE verifier and nonce are stored only as
-- AEAD ciphertext; the key ring is operator-provisioned and never enters the database.
CREATE TABLE brigalow.pending_logins (
    org_id uuid NOT NULL REFERENCES brigalow.organisations,
    state_hash text NOT NULL CHECK (state_hash ~ '^[0-9a-f]{64}$'),
    provider text NOT NULL CHECK (provider ~ '^[A-Za-z0-9_-]{1,128}$'),
    browser_hash text NOT NULL CHECK (browser_hash ~ '^[0-9a-f]{64}$'),
    expires_ms bigint NOT NULL,
    key_id text NOT NULL CHECK (key_id ~ '^[A-Za-z0-9_-]{1,32}$'),
    version smallint NOT NULL CHECK (version = 1),
    nonce bytea NOT NULL CHECK (length(nonce) = 12),
    ciphertext bytea NOT NULL CHECK (length(ciphertext) BETWEEN 17 AND 512),
    slot uuid NOT NULL UNIQUE,
    PRIMARY KEY (org_id, state_hash)
);
CREATE INDEX pending_logins_expiry ON brigalow.pending_logins (org_id, expires_ms);
ALTER TABLE brigalow.pending_logins ENABLE ROW LEVEL SECURITY;
ALTER TABLE brigalow.pending_logins FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON brigalow.pending_logins TO brigalow_app
    USING (org_id = nullif(current_setting('brigalow.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('brigalow.org_id', true), '')::uuid);
-- No UPDATE: rows are inserted once and consumed or expired by DELETE.
GRANT SELECT, INSERT, DELETE ON brigalow.pending_logins TO brigalow_app;

-- Global inventory bound across tenants. Not tenant-owned, so not RLS-scoped: it holds only a
-- random slot UUID and expiry, never an organisation, state digest, provider or secret.
CREATE TABLE brigalow.pending_login_inventory (
    slot uuid PRIMARY KEY,
    expires_ms bigint NOT NULL
);
CREATE INDEX pending_login_inventory_expiry ON brigalow.pending_login_inventory (expires_ms);
GRANT SELECT, INSERT, DELETE ON brigalow.pending_login_inventory TO brigalow_app;

-- Committed AEAD encryptions per configured key ID, shared by every instance.
CREATE TABLE brigalow.pending_login_key_usage (
    key_id text PRIMARY KEY CHECK (key_id ~ '^[A-Za-z0-9_-]{1,32}$'),
    sealed bigint NOT NULL CHECK (sealed > 0)
);
GRANT SELECT, INSERT ON brigalow.pending_login_key_usage TO brigalow_app;
GRANT UPDATE (sealed) ON brigalow.pending_login_key_usage TO brigalow_app;
