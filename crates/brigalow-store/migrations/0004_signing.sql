ALTER TABLE brigalow.policies ADD COLUMN record jsonb;
ALTER TABLE brigalow.policies ADD COLUMN name text;
CREATE UNIQUE INDEX policy_name ON brigalow.policies(org_id,project_id,name);
ALTER TABLE brigalow.policies ADD CONSTRAINT policy_record_identity CHECK(record IS NULL OR ((record->>'id')::uuid=id AND (record->>'project')::uuid=project_id AND (record->>'key')::uuid=key_id));
ALTER TABLE brigalow.sign_requests ADD COLUMN record jsonb;
ALTER TABLE brigalow.sign_requests ADD COLUMN state text NOT NULL DEFAULT 'placeholder';
ALTER TABLE brigalow.sign_requests ADD CONSTRAINT request_record_identity CHECK(record IS NULL OR ((record->'submission'->>'request_id')::uuid=id AND (record->>'project')::uuid=project_id AND (record->'submission'->>'policy')::uuid=policy_id AND record->>'state'=state));
GRANT INSERT ON brigalow.policies,brigalow.sign_requests TO brigalow_app;
GRANT UPDATE(record,state) ON brigalow.sign_requests TO brigalow_app;
