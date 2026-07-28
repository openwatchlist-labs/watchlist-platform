package screeningledger

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type CommandRunner interface {
	Run(context.Context, string, []string, []byte) ([]byte, error)
}
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

type PostgresSink struct {
	DSN      string
	PSQLPath string
	Runner   CommandRunner
	Timeout  time.Duration
}

func NewPostgresSink(dsn, psqlPath string, runner CommandRunner, timeout time.Duration) (*PostgresSink, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("PostgreSQL DSN is required")
	}
	if psqlPath == "" {
		psqlPath = "psql"
	}
	if runner == nil {
		runner = ExecRunner{}
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &PostgresSink{DSN: dsn, PSQLPath: psqlPath, Runner: runner, Timeout: timeout}, nil
}
func (p *PostgresSink) run(ctx context.Context, sql string) error {
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	_, err := p.Runner.Run(ctx, p.PSQLPath, []string{p.DSN, "-X", "-v", "ON_ERROR_STOP=1", "--no-psqlrc", "--quiet"}, []byte(sql))
	return err
}
func (p *PostgresSink) Ping(ctx context.Context) error    { return p.run(ctx, "SELECT 1;\n") }
func (p *PostgresSink) Migrate(ctx context.Context) error { return p.run(ctx, SchemaSQL) }
func (p *PostgresSink) Persist(ctx context.Context, event Event, request, response SnapshotEnvelope) error {
	eventJSON, _ := json.Marshal(event)
	reqJSON, _ := json.Marshal(request)
	respJSON, _ := json.Marshal(response)
	idempotencyGuard := ""
	if event.IdempotencyKeyHash != "" {
		idempotencyGuard = "DO $$ BEGIN IF EXISTS (SELECT 1 FROM screening_idempotency_receipt WHERE scope=" + sqlText(event.Route) + " AND idempotency_key_sha256=" + sqlText(event.IdempotencyKeyHash) + " AND (request_sha256<>" + sqlText(event.RequestSHA256) + " OR response_sha256<>" + sqlText(event.ResponseSHA256) + " OR http_status<>" + fmt.Sprint(event.HTTPStatus) + ")) THEN RAISE EXCEPTION 'idempotency receipt conflict'; END IF; END $$;\n"
	}
	sql := "BEGIN;\n" + idempotencyGuard +
		"INSERT INTO screening_ledger_event(event_id,ledger_id,sequence,event_sha256,previous_event_sha256,occurred_at,route,http_status,request_sha256,response_sha256,request_snapshot_sha256,response_snapshot_sha256,retention_class,expires_at,event_json) VALUES (" + sqlText(event.EventID) + "," + sqlText(event.LedgerID) + "," + fmt.Sprint(event.Sequence) + "," + sqlText(event.EventSHA256) + "," + sqlText(event.PreviousEventSHA256) + "," + sqlText(event.OccurredAt) + "::timestamptz," + sqlText(event.Route) + "," + fmt.Sprint(event.HTTPStatus) + "," + sqlText(event.RequestSHA256) + "," + sqlText(event.ResponseSHA256) + "," + sqlText(event.RequestSnapshotSHA256) + "," + sqlText(event.ResponseSnapshotSHA256) + "," + sqlText(event.RetentionClass) + "," + sqlText(event.ExpiresAt) + "::timestamptz," + sqlJSON(eventJSON) + ") ON CONFLICT (event_id) DO NOTHING;\n" +
		insertSnapshotSQL(request, reqJSON) + insertSnapshotSQL(response, respJSON) +
		"INSERT INTO screening_ledger_replication(event_id,replicated_at) VALUES (" + sqlText(event.EventID) + ",clock_timestamp()) ON CONFLICT (event_id) DO NOTHING;\n" +
		"INSERT INTO screening_idempotency_receipt(scope,idempotency_key_sha256,request_sha256,response_sha256,http_status,event_id) SELECT " + sqlText(event.Route) + "," + sqlNullableText(event.IdempotencyKeyHash) + "," + sqlText(event.RequestSHA256) + "," + sqlText(event.ResponseSHA256) + "," + fmt.Sprint(event.HTTPStatus) + "," + sqlText(event.EventID) + " WHERE " + sqlNullableText(event.IdempotencyKeyHash) + " IS NOT NULL ON CONFLICT (scope,idempotency_key_sha256) DO NOTHING;\nCOMMIT;\n"
	return p.run(ctx, sql)
}
func (p *PostgresSink) PersistAudit(ctx context.Context, event AuditEvent) error {
	raw, _ := json.Marshal(event)
	sql := "INSERT INTO screening_ledger_audit(ledger_id,sequence,audit_sha256,previous_audit_sha256,occurred_at,action,event_id,audit_json) VALUES (" + sqlText(event.LedgerID) + "," + fmt.Sprint(event.Sequence) + "," + sqlText(event.AuditSHA256) + "," + sqlText(event.PreviousAuditSHA256) + "," + sqlText(event.OccurredAt) + "::timestamptz," + sqlText(event.Action) + "," + sqlNullableText(event.EventID) + "," + sqlJSON(raw) + ") ON CONFLICT (audit_sha256) DO NOTHING;\n"
	return p.run(ctx, sql)
}
func (p *PostgresSink) PurgeExpired(ctx context.Context, before, operator, reason string) error {
	return p.run(ctx, "SELECT screening_ledger_purge_snapshots("+sqlText(before)+"::timestamptz,"+sqlText(operator)+","+sqlText(reason)+");\n")
}
func (p *PostgresSink) PersistExternalAudit(ctx context.Context, source, streamID string, sequence uint64, eventSHA, previous, occurred, action string, payload []byte) error {
	sql := "INSERT INTO watchlist_operational_audit(source,stream_id,sequence,event_sha256,previous_event_sha256,occurred_at,action,payload_json) VALUES (" + sqlText(source) + "," + sqlText(streamID) + "," + fmt.Sprint(sequence) + "," + sqlText(eventSHA) + "," + sqlText(previous) + "," + sqlText(occurred) + "::timestamptz," + sqlText(action) + "," + sqlJSON(payload) + ") ON CONFLICT (source,event_sha256) DO NOTHING;\n"
	return p.run(ctx, sql)
}
func insertSnapshotSQL(e SnapshotEnvelope, raw []byte) string {
	return "INSERT INTO screening_ledger_snapshot(snapshot_sha256,kind,created_at,expires_at,retention_class,envelope_json) VALUES (" + sqlText(e.SnapshotSHA256) + "," + sqlText(e.Kind) + "," + sqlText(e.CreatedAt) + "::timestamptz," + sqlText(e.ExpiresAt) + "::timestamptz," + sqlText(e.RetentionClass) + "," + sqlJSON(raw) + ") ON CONFLICT (snapshot_sha256) DO NOTHING;\n"
}
func sqlText(v string) string {
	return "convert_from(decode('" + hex.EncodeToString([]byte(v)) + "','hex'),'UTF8')"
}
func sqlNullableText(v string) string {
	if v == "" {
		return "NULL"
	}
	return sqlText(v)
}
func sqlJSON(raw []byte) string {
	return "convert_from(decode('" + hex.EncodeToString(raw) + "','hex'),'UTF8')::jsonb"
}

const SchemaSQL = `BEGIN;
CREATE TABLE IF NOT EXISTS screening_ledger_event (event_id text PRIMARY KEY,ledger_id text NOT NULL,sequence bigint NOT NULL,event_sha256 text NOT NULL UNIQUE,previous_event_sha256 text NOT NULL,occurred_at timestamptz NOT NULL,route text NOT NULL,http_status integer NOT NULL,request_sha256 text NOT NULL,response_sha256 text NOT NULL,request_snapshot_sha256 text NOT NULL,response_snapshot_sha256 text NOT NULL,retention_class text NOT NULL,expires_at timestamptz NOT NULL,event_json jsonb NOT NULL,inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(ledger_id,sequence));
CREATE TABLE IF NOT EXISTS screening_ledger_snapshot (snapshot_sha256 text PRIMARY KEY,kind text NOT NULL CHECK(kind IN('request','response')),created_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,retention_class text NOT NULL,envelope_json jsonb NOT NULL,purged_at timestamptz,purge_reason text,inserted_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE IF NOT EXISTS screening_ledger_replication (event_id text PRIMARY KEY REFERENCES screening_ledger_event(event_id),replicated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS screening_idempotency_receipt (scope text NOT NULL,idempotency_key_sha256 text NOT NULL,request_sha256 text NOT NULL,response_sha256 text NOT NULL,http_status integer NOT NULL,event_id text NOT NULL REFERENCES screening_ledger_event(event_id),inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(scope,idempotency_key_sha256));
CREATE TABLE IF NOT EXISTS screening_ledger_retention_tombstone(snapshot_sha256 text PRIMARY KEY,purged_at timestamptz NOT NULL,operator text NOT NULL,reason text NOT NULL);
CREATE TABLE IF NOT EXISTS watchlist_operational_audit(source text NOT NULL,stream_id text NOT NULL,sequence bigint NOT NULL,event_sha256 text NOT NULL,previous_event_sha256 text NOT NULL,occurred_at timestamptz NOT NULL,action text NOT NULL,payload_json jsonb NOT NULL,inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(source,event_sha256),UNIQUE(source,stream_id,sequence));
CREATE TABLE IF NOT EXISTS screening_ledger_audit(ledger_id text NOT NULL,sequence bigint NOT NULL,audit_sha256 text PRIMARY KEY,previous_audit_sha256 text NOT NULL,occurred_at timestamptz NOT NULL,action text NOT NULL,event_id text,audit_json jsonb NOT NULL,inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(ledger_id,sequence));
CREATE OR REPLACE FUNCTION screening_ledger_reject_mutation()RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'screening ledger rows are append-only';END $$;
DROP TRIGGER IF EXISTS screening_ledger_event_immutable ON screening_ledger_event;CREATE TRIGGER screening_ledger_event_immutable BEFORE UPDATE OR DELETE ON screening_ledger_event FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation();
DROP TRIGGER IF EXISTS screening_ledger_audit_immutable ON screening_ledger_audit;CREATE TRIGGER screening_ledger_audit_immutable BEFORE UPDATE OR DELETE ON screening_ledger_audit FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation();
DROP TRIGGER IF EXISTS watchlist_operational_audit_immutable ON watchlist_operational_audit;CREATE TRIGGER watchlist_operational_audit_immutable BEFORE UPDATE OR DELETE ON watchlist_operational_audit FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation();
DROP TRIGGER IF EXISTS screening_idempotency_receipt_immutable ON screening_idempotency_receipt;CREATE TRIGGER screening_idempotency_receipt_immutable BEFORE UPDATE OR DELETE ON screening_idempotency_receipt FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation();
DROP TRIGGER IF EXISTS screening_ledger_replication_immutable ON screening_ledger_replication;CREATE TRIGGER screening_ledger_replication_immutable BEFORE UPDATE OR DELETE ON screening_ledger_replication FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation();
DROP TRIGGER IF EXISTS screening_ledger_retention_tombstone_immutable ON screening_ledger_retention_tombstone;CREATE TRIGGER screening_ledger_retention_tombstone_immutable BEFORE UPDATE OR DELETE ON screening_ledger_retention_tombstone FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation();
CREATE OR REPLACE FUNCTION screening_ledger_snapshot_guard()RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF TG_OP='DELETE'THEN RAISE EXCEPTION 'screening snapshots cannot be deleted';END IF;IF OLD.purged_at IS NULL AND NEW.purged_at IS NOT NULL AND OLD.snapshot_sha256=NEW.snapshot_sha256 AND OLD.kind=NEW.kind AND OLD.created_at=NEW.created_at AND OLD.expires_at=NEW.expires_at AND OLD.retention_class=NEW.retention_class AND NOT(NEW.envelope_json?'ciphertext_base64')THEN RETURN NEW;END IF;RAISE EXCEPTION 'screening snapshot mutation is not an allowed retention transition';END $$;
DROP TRIGGER IF EXISTS screening_ledger_snapshot_guard_trigger ON screening_ledger_snapshot;CREATE TRIGGER screening_ledger_snapshot_guard_trigger BEFORE UPDATE OR DELETE ON screening_ledger_snapshot FOR EACH ROW EXECUTE FUNCTION screening_ledger_snapshot_guard();
CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_before timestamptz,p_operator text,p_reason text)RETURNS bigint LANGUAGE plpgsql AS $$ DECLARE affected bigint;BEGIN INSERT INTO screening_ledger_retention_tombstone(snapshot_sha256,purged_at,operator,reason)SELECT snapshot_sha256,clock_timestamp(),p_operator,p_reason FROM screening_ledger_snapshot WHERE expires_at<p_before AND purged_at IS NULL ON CONFLICT(snapshot_sha256)DO NOTHING;UPDATE screening_ledger_snapshot SET purged_at=clock_timestamp(),purge_reason=p_reason,envelope_json=(envelope_json-'nonce_base64'-'ciphertext_base64')||jsonb_build_object('purged_at',clock_timestamp(),'purge_reason',p_reason)WHERE expires_at<p_before AND purged_at IS NULL;GET DIAGNOSTICS affected=ROW_COUNT;RETURN affected;END $$;
COMMIT;
`
