-- SEC-2: statement-level TRUNCATE guards for every immutable relation.
-- Row-level BEFORE UPDATE OR DELETE triggers never fire on TRUNCATE, so the
-- immutability guarantees in prior migrations do not cover it. This adds a
-- BEFORE TRUNCATE ... FOR EACH STATEMENT trigger to each listed relation.
-- Fails closed: if any listed relation is missing, the migration aborts
-- instead of silently skipping the guard for it.
BEGIN;

CREATE OR REPLACE FUNCTION owl_reject_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
  RAISE EXCEPTION 'relation % is append-only; TRUNCATE is prohibited', TG_TABLE_NAME;
END $$;

DO $$
DECLARE
  t text;
  relations text[] := ARRAY[
    'alert_case_audit',
    'alert_case_event',
    'alert_case_idempotency',
    'alert_case_membership',
    'alert_record',
    'case_assistance_audit',
    'case_assistance_idempotency',
    'case_assistance_record',
    'case_assistance_review',
    'operational_backup_catalog',
    'operational_outbox_event',
    'operational_outbox_message',
    'operational_recovery_audit',
    'operational_runtime_config_snapshot',
    'rag_corpus_snapshot',
    'release_artifact_record',
    'release_deployment_audit',
    'release_qualification_audit',
    'release_qualification_evidence',
    'release_qualification_gate',
    'release_qualification_report',
    'review_identity_registry_snapshot',
    'review_security_audit_event',
    'screening_idempotency_receipt',
    'screening_ledger_audit',
    'screening_ledger_event',
    'screening_ledger_replication',
    'screening_ledger_retention_tombstone',
    'screening_ledger_snapshot',
    'tenant_quota_registry_snapshot',
    'vendor_adapter_audit',
    'vendor_adapter_idempotency',
    'vendor_adapter_record',
    'watchlist_operational_audit'
  ];
BEGIN
  FOREACH t IN ARRAY relations LOOP
    IF to_regclass(t) IS NULL THEN
      RAISE EXCEPTION 'SEC-2 truncate guard: relation % does not exist; migration 012 requires all 34 listed relations to be present', t;
    END IF;
  END LOOP;
END $$;

DROP TRIGGER IF EXISTS alert_case_audit_no_truncate ON alert_case_audit;
CREATE TRIGGER alert_case_audit_no_truncate BEFORE TRUNCATE ON alert_case_audit FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS alert_case_event_no_truncate ON alert_case_event;
CREATE TRIGGER alert_case_event_no_truncate BEFORE TRUNCATE ON alert_case_event FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS alert_case_idempotency_no_truncate ON alert_case_idempotency;
CREATE TRIGGER alert_case_idempotency_no_truncate BEFORE TRUNCATE ON alert_case_idempotency FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS alert_case_membership_no_truncate ON alert_case_membership;
CREATE TRIGGER alert_case_membership_no_truncate BEFORE TRUNCATE ON alert_case_membership FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS alert_record_no_truncate ON alert_record;
CREATE TRIGGER alert_record_no_truncate BEFORE TRUNCATE ON alert_record FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS case_assistance_audit_no_truncate ON case_assistance_audit;
CREATE TRIGGER case_assistance_audit_no_truncate BEFORE TRUNCATE ON case_assistance_audit FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS case_assistance_idempotency_no_truncate ON case_assistance_idempotency;
CREATE TRIGGER case_assistance_idempotency_no_truncate BEFORE TRUNCATE ON case_assistance_idempotency FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS case_assistance_record_no_truncate ON case_assistance_record;
CREATE TRIGGER case_assistance_record_no_truncate BEFORE TRUNCATE ON case_assistance_record FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS case_assistance_review_no_truncate ON case_assistance_review;
CREATE TRIGGER case_assistance_review_no_truncate BEFORE TRUNCATE ON case_assistance_review FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS operational_backup_catalog_no_truncate ON operational_backup_catalog;
CREATE TRIGGER operational_backup_catalog_no_truncate BEFORE TRUNCATE ON operational_backup_catalog FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS operational_outbox_event_no_truncate ON operational_outbox_event;
CREATE TRIGGER operational_outbox_event_no_truncate BEFORE TRUNCATE ON operational_outbox_event FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS operational_outbox_message_no_truncate ON operational_outbox_message;
CREATE TRIGGER operational_outbox_message_no_truncate BEFORE TRUNCATE ON operational_outbox_message FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS operational_recovery_audit_no_truncate ON operational_recovery_audit;
CREATE TRIGGER operational_recovery_audit_no_truncate BEFORE TRUNCATE ON operational_recovery_audit FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS operational_runtime_config_snapshot_no_truncate ON operational_runtime_config_snapshot;
CREATE TRIGGER operational_runtime_config_snapshot_no_truncate BEFORE TRUNCATE ON operational_runtime_config_snapshot FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS rag_corpus_snapshot_no_truncate ON rag_corpus_snapshot;
CREATE TRIGGER rag_corpus_snapshot_no_truncate BEFORE TRUNCATE ON rag_corpus_snapshot FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS release_artifact_record_no_truncate ON release_artifact_record;
CREATE TRIGGER release_artifact_record_no_truncate BEFORE TRUNCATE ON release_artifact_record FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS release_deployment_audit_no_truncate ON release_deployment_audit;
CREATE TRIGGER release_deployment_audit_no_truncate BEFORE TRUNCATE ON release_deployment_audit FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS release_qualification_audit_no_truncate ON release_qualification_audit;
CREATE TRIGGER release_qualification_audit_no_truncate BEFORE TRUNCATE ON release_qualification_audit FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS release_qualification_evidence_no_truncate ON release_qualification_evidence;
CREATE TRIGGER release_qualification_evidence_no_truncate BEFORE TRUNCATE ON release_qualification_evidence FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS release_qualification_gate_no_truncate ON release_qualification_gate;
CREATE TRIGGER release_qualification_gate_no_truncate BEFORE TRUNCATE ON release_qualification_gate FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS release_qualification_report_no_truncate ON release_qualification_report;
CREATE TRIGGER release_qualification_report_no_truncate BEFORE TRUNCATE ON release_qualification_report FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS review_identity_registry_snapshot_no_truncate ON review_identity_registry_snapshot;
CREATE TRIGGER review_identity_registry_snapshot_no_truncate BEFORE TRUNCATE ON review_identity_registry_snapshot FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS review_security_audit_event_no_truncate ON review_security_audit_event;
CREATE TRIGGER review_security_audit_event_no_truncate BEFORE TRUNCATE ON review_security_audit_event FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS screening_idempotency_receipt_no_truncate ON screening_idempotency_receipt;
CREATE TRIGGER screening_idempotency_receipt_no_truncate BEFORE TRUNCATE ON screening_idempotency_receipt FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS screening_ledger_audit_no_truncate ON screening_ledger_audit;
CREATE TRIGGER screening_ledger_audit_no_truncate BEFORE TRUNCATE ON screening_ledger_audit FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS screening_ledger_event_no_truncate ON screening_ledger_event;
CREATE TRIGGER screening_ledger_event_no_truncate BEFORE TRUNCATE ON screening_ledger_event FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS screening_ledger_replication_no_truncate ON screening_ledger_replication;
CREATE TRIGGER screening_ledger_replication_no_truncate BEFORE TRUNCATE ON screening_ledger_replication FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS screening_ledger_retention_tombstone_no_truncate ON screening_ledger_retention_tombstone;
CREATE TRIGGER screening_ledger_retention_tombstone_no_truncate BEFORE TRUNCATE ON screening_ledger_retention_tombstone FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS screening_ledger_snapshot_no_truncate ON screening_ledger_snapshot;
CREATE TRIGGER screening_ledger_snapshot_no_truncate BEFORE TRUNCATE ON screening_ledger_snapshot FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS tenant_quota_registry_snapshot_no_truncate ON tenant_quota_registry_snapshot;
CREATE TRIGGER tenant_quota_registry_snapshot_no_truncate BEFORE TRUNCATE ON tenant_quota_registry_snapshot FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS vendor_adapter_audit_no_truncate ON vendor_adapter_audit;
CREATE TRIGGER vendor_adapter_audit_no_truncate BEFORE TRUNCATE ON vendor_adapter_audit FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS vendor_adapter_idempotency_no_truncate ON vendor_adapter_idempotency;
CREATE TRIGGER vendor_adapter_idempotency_no_truncate BEFORE TRUNCATE ON vendor_adapter_idempotency FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS vendor_adapter_record_no_truncate ON vendor_adapter_record;
CREATE TRIGGER vendor_adapter_record_no_truncate BEFORE TRUNCATE ON vendor_adapter_record FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS watchlist_operational_audit_no_truncate ON watchlist_operational_audit;
CREATE TRIGGER watchlist_operational_audit_no_truncate BEFORE TRUNCATE ON watchlist_operational_audit FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();

COMMIT;
