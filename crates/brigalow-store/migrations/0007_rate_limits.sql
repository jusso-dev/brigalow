CREATE TABLE brigalow.rate_limits (
    org_id uuid NOT NULL REFERENCES brigalow.organisations,
    credential text NOT NULL CHECK(length(credential) BETWEEN 1 AND 128),
    resets_at bigint NOT NULL,
    count bigint NOT NULL CHECK(count>0),
    PRIMARY KEY(org_id,credential)
);
ALTER TABLE brigalow.rate_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE brigalow.rate_limits FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON brigalow.rate_limits TO brigalow_app
    USING(org_id=nullif(current_setting('brigalow.org_id',true),'')::uuid)
    WITH CHECK(org_id=nullif(current_setting('brigalow.org_id',true),'')::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON brigalow.rate_limits TO brigalow_app;
