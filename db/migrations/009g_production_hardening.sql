BEGIN;
SELECT pg_advisory_xact_lock(hashtext('openwatchlist-phase9g-production-hardening'));

CREATE TABLE IF NOT EXISTS operational_runtime_config_snapshot(
 config_sha256 text PRIMARY KEY CHECK(length(config_sha256)=64),
 config_id text NOT NULL,
 version text NOT NULL,
 environment text NOT NULL CHECK(environment IN ('fixture','production')),
 config_json jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS tenant_quota_registry_snapshot(
 registry_sha256 text PRIMARY KEY CHECK(length(registry_sha256)=64),
 registry_id text NOT NULL,
 version text NOT NULL,
 registry_json jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS operational_outbox_message(
 message_id text PRIMARY KEY,
 topic text NOT NULL,
 tenant_id text NOT NULL,
 idempotency_key text NOT NULL,
 payload_sha256 text NOT NULL CHECK(length(payload_sha256)=64),
 message_sha256 text NOT NULL UNIQUE CHECK(length(message_sha256)=64),
 max_attempts integer NOT NULL CHECK(max_attempts>0),
 created_at timestamptz NOT NULL,
 message_json jsonb NOT NULL,
 inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(topic,tenant_id,idempotency_key)
);
CREATE TABLE IF NOT EXISTS operational_outbox_event(
 stream_id text NOT NULL,
 sequence bigint NOT NULL,
 event_sha256 text PRIMARY KEY CHECK(length(event_sha256)=64),
 previous_event_sha256 text NOT NULL,
 message_id text NOT NULL REFERENCES operational_outbox_message(message_id),
 occurred_at timestamptz NOT NULL,
 action text NOT NULL CHECK(action IN ('enqueued','leased','retry_scheduled','recovered','completed','dead')),
 attempt integer NOT NULL CHECK(attempt>=0),
 event_json jsonb NOT NULL,
 inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(stream_id,sequence)
);
CREATE INDEX IF NOT EXISTS operational_outbox_pending_idx ON operational_outbox_event(message_id,occurred_at DESC);
CREATE TABLE IF NOT EXISTS operational_backup_catalog(
 backup_id text PRIMARY KEY,
 content_sha256 text NOT NULL UNIQUE CHECK(length(content_sha256)=64),
 entry_count integer NOT NULL CHECK(entry_count>=0),
 total_bytes bigint NOT NULL CHECK(total_bytes>=0),
 created_at timestamptz NOT NULL,
 manifest_json jsonb NOT NULL,
 inserted_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS operational_recovery_audit(
 stream_id text NOT NULL,
 sequence bigint NOT NULL,
 event_sha256 text PRIMARY KEY CHECK(length(event_sha256)=64),
 previous_event_sha256 text NOT NULL,
 occurred_at timestamptz NOT NULL,
 action text NOT NULL,
 object_type text NOT NULL,
 object_id text NOT NULL,
 detail jsonb,
 inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(stream_id,sequence)
);

CREATE OR REPLACE FUNCTION openwatchlist_phase9g_reject_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Phase 9G immutable relation % rejects %',TG_TABLE_NAME,TG_OP; END $$;
DROP TRIGGER IF EXISTS operational_runtime_config_snapshot_immutable ON operational_runtime_config_snapshot;
CREATE TRIGGER operational_runtime_config_snapshot_immutable BEFORE UPDATE OR DELETE ON operational_runtime_config_snapshot FOR EACH ROW EXECUTE FUNCTION openwatchlist_phase9g_reject_mutation();
DROP TRIGGER IF EXISTS tenant_quota_registry_snapshot_immutable ON tenant_quota_registry_snapshot;
CREATE TRIGGER tenant_quota_registry_snapshot_immutable BEFORE UPDATE OR DELETE ON tenant_quota_registry_snapshot FOR EACH ROW EXECUTE FUNCTION openwatchlist_phase9g_reject_mutation();
DROP TRIGGER IF EXISTS operational_outbox_message_immutable ON operational_outbox_message;
CREATE TRIGGER operational_outbox_message_immutable BEFORE UPDATE OR DELETE ON operational_outbox_message FOR EACH ROW EXECUTE FUNCTION openwatchlist_phase9g_reject_mutation();
DROP TRIGGER IF EXISTS operational_outbox_event_immutable ON operational_outbox_event;
CREATE TRIGGER operational_outbox_event_immutable BEFORE UPDATE OR DELETE ON operational_outbox_event FOR EACH ROW EXECUTE FUNCTION openwatchlist_phase9g_reject_mutation();
DROP TRIGGER IF EXISTS operational_backup_catalog_immutable ON operational_backup_catalog;
CREATE TRIGGER operational_backup_catalog_immutable BEFORE UPDATE OR DELETE ON operational_backup_catalog FOR EACH ROW EXECUTE FUNCTION openwatchlist_phase9g_reject_mutation();
DROP TRIGGER IF EXISTS operational_recovery_audit_immutable ON operational_recovery_audit;
CREATE TRIGGER operational_recovery_audit_immutable BEFORE UPDATE OR DELETE ON operational_recovery_audit FOR EACH ROW EXECUTE FUNCTION openwatchlist_phase9g_reject_mutation();

CREATE OR REPLACE FUNCTION openwatchlist_tenant_visible(row_tenant text) RETURNS boolean
LANGUAGE sql STABLE AS $$ SELECT current_setting('openwatchlist.tenant_id',true)='*' OR row_tenant=current_setting('openwatchlist.tenant_id',true) $$;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['alert_record','alert_case','case_assistance_record','vendor_adapter_record'] LOOP
    IF to_regclass(t) IS NOT NULL THEN
      EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
      EXECUTE format('DROP POLICY IF EXISTS openwatchlist_tenant_scope ON %I',t);
      EXECUTE format('CREATE POLICY openwatchlist_tenant_scope ON %I USING (openwatchlist_tenant_visible(tenant_id)) WITH CHECK (openwatchlist_tenant_visible(tenant_id))',t);
    END IF;
  END LOOP;
  IF to_regclass('review_security_audit_event') IS NOT NULL THEN
    ALTER TABLE review_security_audit_event ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS openwatchlist_tenant_scope ON review_security_audit_event;
    CREATE POLICY openwatchlist_tenant_scope ON review_security_audit_event USING (tenant_id IS NULL OR openwatchlist_tenant_visible(tenant_id)) WITH CHECK (tenant_id IS NULL OR openwatchlist_tenant_visible(tenant_id));
  END IF;
END $$;

COMMIT;
