CREATE TABLE brigalow.credentials (
    org_id uuid NOT NULL REFERENCES brigalow.organisations,
    id uuid NOT NULL,
    secret_hash text NOT NULL CHECK (secret_hash ~ '^[0-9a-f]{64}$'),
    kind text NOT NULL CHECK (kind IN ('session','api')),
    principal jsonb NOT NULL,
    csrf text,
    project_id uuid,
    policy_id uuid,
    expires_at timestamptz NOT NULL,
    revoked boolean NOT NULL DEFAULT false,
    PRIMARY KEY(org_id,id),
    UNIQUE(org_id,secret_hash),
    FOREIGN KEY(org_id,project_id,policy_id) REFERENCES brigalow.policies(org_id,project_id,id),
    CHECK ((kind='session' AND csrf IS NOT NULL AND project_id IS NULL AND policy_id IS NULL) OR
           (kind='api' AND csrf IS NULL AND project_id IS NOT NULL AND policy_id IS NOT NULL)),
    CHECK (coalesce((principal->>'org_id')::uuid = org_id,false))
);
CREATE TABLE brigalow.request_ids (
    org_id uuid NOT NULL REFERENCES brigalow.organisations,
    id uuid NOT NULL,
    PRIMARY KEY(org_id,id)
);
GRANT SELECT,INSERT ON brigalow.credentials TO brigalow_app;
GRANT UPDATE(revoked) ON brigalow.credentials TO brigalow_app;
GRANT SELECT,INSERT ON brigalow.request_ids TO brigalow_app;
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['credentials','request_ids'] LOOP
        EXECUTE format('ALTER TABLE brigalow.%I ENABLE ROW LEVEL SECURITY',t);
        EXECUTE format('ALTER TABLE brigalow.%I FORCE ROW LEVEL SECURITY',t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON brigalow.%I TO brigalow_app USING (org_id=nullif(current_setting('brigalow.org_id',true),'')::uuid) WITH CHECK (org_id=nullif(current_setting('brigalow.org_id',true),'')::uuid)$p$,t);
    END LOOP;
END $$;
