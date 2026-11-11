CREATE TABLE brigalow.release_windows (
 org_id uuid NOT NULL, id uuid NOT NULL, project_id uuid NOT NULL, key_id uuid NOT NULL,
 record jsonb NOT NULL, used bigint NOT NULL DEFAULT 0 CHECK(used>=0),closed boolean NOT NULL DEFAULT false,
 PRIMARY KEY(org_id,id),FOREIGN KEY(org_id,project_id,key_id) REFERENCES brigalow.signing_keys(org_id,project_id,id),
 CHECK((record->>'id')::uuid=id AND (record->>'key')::uuid=key_id AND (record->>'project')::uuid=project_id)
);
ALTER TABLE brigalow.release_windows ENABLE ROW LEVEL SECURITY;
ALTER TABLE brigalow.release_windows FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON brigalow.release_windows TO brigalow_app USING(org_id=nullif(current_setting('brigalow.org_id',true),'')::uuid) WITH CHECK(org_id=nullif(current_setting('brigalow.org_id',true),'')::uuid);
GRANT SELECT,INSERT ON brigalow.release_windows TO brigalow_app;
GRANT UPDATE(used,closed) ON brigalow.release_windows TO brigalow_app;
CREATE INDEX pending_expiry ON brigalow.sign_requests(org_id,((record->'approval'->>'expires_at')::bigint)) WHERE state='awaiting_approval';
