-- Optional CA is a separate operator process and login, never the web runtime.
CREATE ROLE brigalow_ca NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
GRANT USAGE ON SCHEMA brigalow TO brigalow_ca;
GRANT SELECT ON brigalow.organisations, brigalow.audit_entries TO brigalow_ca;
GRANT INSERT ON brigalow.audit_entries TO brigalow_ca;
CREATE POLICY ca_audit ON brigalow.audit_entries TO brigalow_ca
    USING (org_id = nullif(current_setting('brigalow.org_id', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('brigalow.org_id', true), '')::uuid);
CREATE POLICY ca_org ON brigalow.organisations TO brigalow_ca
    USING (org_id = nullif(current_setting('brigalow.org_id', true), '')::uuid);
CREATE TABLE brigalow.ca_profiles (
    org_id uuid NOT NULL REFERENCES brigalow.organisations,
    profile uuid NOT NULL,
    record jsonb NOT NULL,
    PRIMARY KEY(org_id,profile)
);
CREATE TABLE brigalow.ca_leaves (
    org_id uuid NOT NULL,
    profile uuid NOT NULL,
    day bigint NOT NULL CHECK(day >= 0),
    issuer uuid NOT NULL,
    serial bytea NOT NULL CHECK(octet_length(serial)=16),
    public_key bytea NOT NULL CHECK(octet_length(public_key) BETWEEN 32 AND 65536),
    issued_at bigint NOT NULL,
    chain jsonb,
    revoked_at bigint,
    PRIMARY KEY(org_id,profile,day),
    UNIQUE(org_id,issuer,serial),
    FOREIGN KEY(org_id,profile) REFERENCES brigalow.ca_profiles
);
CREATE TABLE brigalow.ca_crls (
    org_id uuid NOT NULL REFERENCES brigalow.organisations,
    issuer uuid NOT NULL,
    number bigint NOT NULL CHECK(number > 0),
    created_at bigint NOT NULL,
    der bytea,
    PRIMARY KEY(org_id,issuer,number)
);
GRANT SELECT,INSERT ON brigalow.ca_profiles,brigalow.ca_leaves,brigalow.ca_crls TO brigalow_ca;
GRANT UPDATE(chain,revoked_at) ON brigalow.ca_leaves TO brigalow_ca;
GRANT UPDATE(der) ON brigalow.ca_crls TO brigalow_ca;
-- Web runtime receives no CA ledger permission. CA runtime cannot alter profiles or delete history.
DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['ca_profiles','ca_leaves','ca_crls'] LOOP
        EXECUTE format('ALTER TABLE brigalow.%I ENABLE ROW LEVEL SECURITY',table_name);
        EXECUTE format('ALTER TABLE brigalow.%I FORCE ROW LEVEL SECURITY',table_name);
        EXECUTE format($policy$CREATE POLICY tenant_isolation ON brigalow.%I TO brigalow_ca USING (org_id = nullif(current_setting('brigalow.org_id', true), '')::uuid) WITH CHECK (org_id = nullif(current_setting('brigalow.org_id', true), '')::uuid)$policy$,table_name);
    END LOOP;
END $$;
