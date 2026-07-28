-- Phase 9A-9B deterministic alert and case-management backend.
-- Full watchlist catalog rows are intentionally excluded.
BEGIN;
CREATE TABLE IF NOT EXISTS alert_record(
 alert_id text PRIMARY KEY, tenant_id text NOT NULL, source_type text NOT NULL,
 source_identity text NOT NULL, record_sha256 text NOT NULL UNIQUE,
 policy_route text NOT NULL, created_at timestamptz NOT NULL,
 alert_json jsonb NOT NULL, inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,source_type,source_identity,record_sha256)
);
CREATE TABLE IF NOT EXISTS alert_case(
 case_id text PRIMARY KEY, tenant_id text NOT NULL, state text NOT NULL,
 revision bigint NOT NULL CHECK(revision>0), created_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL, projection_json jsonb NOT NULL,
 inserted_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS alert_case_membership(
 case_id text NOT NULL REFERENCES alert_case(case_id), alert_id text NOT NULL REFERENCES alert_record(alert_id),
 joined_at timestamptz NOT NULL, PRIMARY KEY(case_id,alert_id)
);
CREATE TABLE IF NOT EXISTS alert_case_event(
 case_id text NOT NULL REFERENCES alert_case(case_id), sequence bigint NOT NULL,
 revision bigint NOT NULL, event_sha256 text PRIMARY KEY, previous_event_sha256 text NOT NULL,
 occurred_at timestamptz NOT NULL, action text NOT NULL, actor text NOT NULL,
 event_json jsonb NOT NULL, inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(case_id,sequence), UNIQUE(case_id,revision)
);
CREATE TABLE IF NOT EXISTS alert_case_idempotency(
 scope text NOT NULL, key_sha256 text NOT NULL, request_sha256 text NOT NULL,
 response_sha256 text NOT NULL, object_type text NOT NULL, object_id text NOT NULL,
 created_at timestamptz NOT NULL, receipt_json jsonb NOT NULL,
 inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(scope,key_sha256)
);
CREATE TABLE IF NOT EXISTS alert_case_audit(
 stream_id text NOT NULL, sequence bigint NOT NULL, audit_sha256 text PRIMARY KEY,
 previous_audit_sha256 text NOT NULL, occurred_at timestamptz NOT NULL, action text NOT NULL,
 actor text, object_type text NOT NULL, object_id text NOT NULL, audit_json jsonb NOT NULL,
 inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(stream_id,sequence)
);
CREATE OR REPLACE FUNCTION alert_case_reject_immutable_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'alert and case history rows are append-only'; END $$;
DROP TRIGGER IF EXISTS alert_record_immutable ON alert_record;
CREATE TRIGGER alert_record_immutable BEFORE UPDATE OR DELETE ON alert_record FOR EACH ROW EXECUTE FUNCTION alert_case_reject_immutable_mutation();
DROP TRIGGER IF EXISTS alert_case_event_immutable ON alert_case_event;
CREATE TRIGGER alert_case_event_immutable BEFORE UPDATE OR DELETE ON alert_case_event FOR EACH ROW EXECUTE FUNCTION alert_case_reject_immutable_mutation();
DROP TRIGGER IF EXISTS alert_case_membership_immutable ON alert_case_membership;
CREATE TRIGGER alert_case_membership_immutable BEFORE UPDATE OR DELETE ON alert_case_membership FOR EACH ROW EXECUTE FUNCTION alert_case_reject_immutable_mutation();
DROP TRIGGER IF EXISTS alert_case_idempotency_immutable ON alert_case_idempotency;
CREATE TRIGGER alert_case_idempotency_immutable BEFORE UPDATE OR DELETE ON alert_case_idempotency FOR EACH ROW EXECUTE FUNCTION alert_case_reject_immutable_mutation();
DROP TRIGGER IF EXISTS alert_case_audit_immutable ON alert_case_audit;
CREATE TRIGGER alert_case_audit_immutable BEFORE UPDATE OR DELETE ON alert_case_audit FOR EACH ROW EXECUTE FUNCTION alert_case_reject_immutable_mutation();
COMMIT;
