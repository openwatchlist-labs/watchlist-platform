BEGIN;
CREATE TABLE IF NOT EXISTS vendor_adapter_record (
 record_id text PRIMARY KEY, adapter_id text NOT NULL, adapter_version text NOT NULL,
 profile_sha256 text NOT NULL CHECK(length(profile_sha256)=64), source_sha256 text NOT NULL CHECK(length(source_sha256)=64),
 envelope_sha256 text NOT NULL CHECK(length(envelope_sha256)=64), tenant_id text NOT NULL, source_alert_id text NOT NULL,
 occurred_at timestamptz NOT NULL, envelope_json jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS vendor_adapter_source_identity_uq ON vendor_adapter_record(adapter_id,tenant_id,source_alert_id,source_sha256);
CREATE TABLE IF NOT EXISTS vendor_adapter_idempotency (
 scope text NOT NULL, idempotency_key text NOT NULL, source_sha256 text NOT NULL CHECK(length(source_sha256)=64),
 record_id text NOT NULL REFERENCES vendor_adapter_record(record_id), receipt_json jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(scope,idempotency_key)
);
CREATE TABLE IF NOT EXISTS vendor_adapter_audit (
 stream_id text NOT NULL, sequence bigint NOT NULL, previous_audit_sha256 text NOT NULL,
 audit_sha256 text NOT NULL CHECK(length(audit_sha256)=64), occurred_at timestamptz NOT NULL,
 action text NOT NULL, object_type text NOT NULL, object_id text NOT NULL, details jsonb,
 PRIMARY KEY(stream_id,sequence), UNIQUE(audit_sha256)
);
CREATE OR REPLACE FUNCTION openwatchlist_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable relation %', TG_TABLE_NAME; END $$;
DROP TRIGGER IF EXISTS vendor_adapter_record_immutable ON vendor_adapter_record;
CREATE TRIGGER vendor_adapter_record_immutable BEFORE UPDATE OR DELETE ON vendor_adapter_record FOR EACH ROW EXECUTE FUNCTION openwatchlist_reject_mutation();
DROP TRIGGER IF EXISTS vendor_adapter_idempotency_immutable ON vendor_adapter_idempotency;
CREATE TRIGGER vendor_adapter_idempotency_immutable BEFORE UPDATE OR DELETE ON vendor_adapter_idempotency FOR EACH ROW EXECUTE FUNCTION openwatchlist_reject_mutation();
DROP TRIGGER IF EXISTS vendor_adapter_audit_immutable ON vendor_adapter_audit;
CREATE TRIGGER vendor_adapter_audit_immutable BEFORE UPDATE OR DELETE ON vendor_adapter_audit FOR EACH ROW EXECUTE FUNCTION openwatchlist_reject_mutation();
COMMIT;
