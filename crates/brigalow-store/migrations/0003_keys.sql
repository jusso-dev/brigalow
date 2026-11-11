-- Existing placeholder rows remain non-signing until explicitly replaced by generated metadata.
ALTER TABLE brigalow.signing_keys ADD COLUMN record jsonb;
ALTER TABLE brigalow.signing_keys ADD COLUMN revision bigint NOT NULL DEFAULT 0;
ALTER TABLE brigalow.signing_keys ADD CONSTRAINT key_record_identity CHECK (
    record IS NULL OR ((record->'key'->>'id')::uuid = id AND (record->>'project')::uuid = project_id)
);
GRANT INSERT ON brigalow.signing_keys TO brigalow_app;
GRANT UPDATE (record, revision) ON brigalow.signing_keys TO brigalow_app;
