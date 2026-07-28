BEGIN;
CREATE TABLE IF NOT EXISTS rag_corpus_snapshot(
 snapshot_sha256 text PRIMARY KEY, corpus_id text NOT NULL, corpus_version text NOT NULL,
 built_at timestamptz NOT NULL, passage_count integer NOT NULL CHECK(passage_count>=0),
 snapshot_json jsonb NOT NULL, inserted_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS case_assistance_record(
 assistance_id text PRIMARY KEY, case_id text NOT NULL REFERENCES alert_case(case_id), tenant_id text NOT NULL,
 task text NOT NULL, status text NOT NULL, record_sha256 text NOT NULL UNIQUE,
 snapshot_sha256 text NOT NULL REFERENCES rag_corpus_snapshot(snapshot_sha256),
 generation_model_id text NOT NULL, guardian_model_id text NOT NULL, occurred_at timestamptz NOT NULL,
 record_json jsonb NOT NULL, inserted_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS case_assistance_review(
 assistance_id text NOT NULL REFERENCES case_assistance_record(assistance_id), case_id text NOT NULL,
 sequence bigint NOT NULL, event_sha256 text PRIMARY KEY, previous_event_sha256 text NOT NULL,
 action text NOT NULL CHECK(action IN ('accept','reject')), actor text NOT NULL, reason text NOT NULL,
 occurred_at timestamptz NOT NULL, event_json jsonb NOT NULL,
 inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(assistance_id,sequence)
);
CREATE TABLE IF NOT EXISTS case_assistance_idempotency(
 scope text NOT NULL,key_sha256 text NOT NULL,request_sha256 text NOT NULL,response_sha256 text NOT NULL,
 object_type text NOT NULL,object_id text NOT NULL,created_at timestamptz NOT NULL,receipt_json jsonb NOT NULL,
 inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(scope,key_sha256)
);
CREATE TABLE IF NOT EXISTS case_assistance_audit(
 stream_id text NOT NULL,sequence bigint NOT NULL,audit_sha256 text PRIMARY KEY,previous_audit_sha256 text NOT NULL,
 occurred_at timestamptz NOT NULL,action text NOT NULL,actor text,object_type text NOT NULL,object_id text NOT NULL,
 audit_json jsonb NOT NULL,inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(stream_id,sequence)
);
CREATE OR REPLACE FUNCTION case_assistance_reject_immutable_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'case assistance history rows are append-only'; END $$;
DROP TRIGGER IF EXISTS rag_corpus_snapshot_immutable ON rag_corpus_snapshot;
CREATE TRIGGER rag_corpus_snapshot_immutable BEFORE UPDATE OR DELETE ON rag_corpus_snapshot FOR EACH ROW EXECUTE FUNCTION case_assistance_reject_immutable_mutation();
DROP TRIGGER IF EXISTS case_assistance_record_immutable ON case_assistance_record;
CREATE TRIGGER case_assistance_record_immutable BEFORE UPDATE OR DELETE ON case_assistance_record FOR EACH ROW EXECUTE FUNCTION case_assistance_reject_immutable_mutation();
DROP TRIGGER IF EXISTS case_assistance_review_immutable ON case_assistance_review;
CREATE TRIGGER case_assistance_review_immutable BEFORE UPDATE OR DELETE ON case_assistance_review FOR EACH ROW EXECUTE FUNCTION case_assistance_reject_immutable_mutation();
DROP TRIGGER IF EXISTS case_assistance_idempotency_immutable ON case_assistance_idempotency;
CREATE TRIGGER case_assistance_idempotency_immutable BEFORE UPDATE OR DELETE ON case_assistance_idempotency FOR EACH ROW EXECUTE FUNCTION case_assistance_reject_immutable_mutation();
DROP TRIGGER IF EXISTS case_assistance_audit_immutable ON case_assistance_audit;
CREATE TRIGGER case_assistance_audit_immutable BEFORE UPDATE OR DELETE ON case_assistance_audit FOR EACH ROW EXECUTE FUNCTION case_assistance_reject_immutable_mutation();
COMMIT;
