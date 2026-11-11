-- Run as a dedicated migration owner, never as the runtime login.
CREATE ROLE brigalow_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE SCHEMA brigalow;
REVOKE ALL ON SCHEMA brigalow FROM PUBLIC;
GRANT USAGE ON SCHEMA brigalow TO brigalow_app;

CREATE TABLE brigalow.organisations (
    org_id uuid PRIMARY KEY,
    name text NOT NULL
);
CREATE TABLE brigalow.projects (
    org_id uuid NOT NULL REFERENCES brigalow.organisations,
    id uuid NOT NULL,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    PRIMARY KEY (org_id, id)
);
-- Metadata placeholders only: no key material or signing authority in Phase 0.
CREATE TABLE brigalow.signing_keys (
    org_id uuid NOT NULL,
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, project_id, id),
    FOREIGN KEY (org_id, project_id) REFERENCES brigalow.projects (org_id, id)
);
CREATE TABLE brigalow.policies (
    org_id uuid NOT NULL,
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    key_id uuid NOT NULL,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, project_id, id),
    FOREIGN KEY (org_id, project_id) REFERENCES brigalow.projects (org_id, id),
    FOREIGN KEY (org_id, project_id, key_id) REFERENCES brigalow.signing_keys (org_id, project_id, id)
);
CREATE TABLE brigalow.sign_requests (
    org_id uuid NOT NULL,
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, project_id) REFERENCES brigalow.projects (org_id, id),
    FOREIGN KEY (org_id, project_id, policy_id) REFERENCES brigalow.policies (org_id, project_id, id)
);
CREATE TABLE brigalow.audit_entries (
    org_id uuid NOT NULL REFERENCES brigalow.organisations,
    seq bigint NOT NULL CHECK (seq BETWEEN 1 AND 9007199254740991),
    entry jsonb NOT NULL,
    PRIMARY KEY (org_id, seq),
    CHECK (entry ? 'org_id' AND (entry->>'org_id')::uuid = org_id),
    CHECK (entry ? 'seq' AND (entry->>'seq')::bigint = seq)
);

GRANT SELECT ON ALL TABLES IN SCHEMA brigalow TO brigalow_app;
GRANT INSERT ON brigalow.projects, brigalow.audit_entries TO brigalow_app;
-- No UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, ownership or schema CREATE.
-- Tenant context is transaction-local, set only by the trusted store layer.
DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['organisations','projects','signing_keys','policies','sign_requests','audit_entries'] LOOP
        EXECUTE format('ALTER TABLE brigalow.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE brigalow.%I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format($policy$CREATE POLICY tenant_isolation ON brigalow.%I TO brigalow_app USING (org_id = nullif(current_setting('brigalow.org_id', true), '')::uuid) WITH CHECK (org_id = nullif(current_setting('brigalow.org_id', true), '')::uuid)$policy$, table_name);
    END LOOP;
END $$;
