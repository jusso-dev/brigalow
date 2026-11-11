CREATE TABLE brigalow.audit_checkpoints (
    org_id uuid NOT NULL,
    seq bigint NOT NULL,
    record jsonb NOT NULL,
    PRIMARY KEY(org_id,seq),
    FOREIGN KEY(org_id,seq) REFERENCES brigalow.audit_entries(org_id,seq)
);
ALTER TABLE brigalow.audit_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE brigalow.audit_checkpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON brigalow.audit_checkpoints TO brigalow_app
    USING(org_id=nullif(current_setting('brigalow.org_id',true),'')::uuid)
    WITH CHECK(org_id=nullif(current_setting('brigalow.org_id',true),'')::uuid);
GRANT SELECT,INSERT ON brigalow.audit_checkpoints TO brigalow_app;
