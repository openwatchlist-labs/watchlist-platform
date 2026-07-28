package assistancerag

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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
	DSN, PSQLPath string
	Runner        CommandRunner
	Timeout       time.Duration
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
		timeout = 30 * time.Second
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
func (p *PostgresSink) PersistSnapshot(ctx context.Context, s CorpusSnapshot) error {
	raw, _ := json.Marshal(s)
	sql := "INSERT INTO rag_corpus_snapshot(snapshot_sha256,corpus_id,corpus_version,built_at,passage_count,snapshot_json) VALUES (" + sqlText(s.SnapshotSHA256) + "," + sqlText(s.CorpusID) + "," + sqlText(s.Version) + "," + sqlText(s.BuiltAt) + "::timestamptz," + fmt.Sprint(s.PassageCount) + "," + sqlJSON(raw) + ") ON CONFLICT(snapshot_sha256) DO NOTHING;\n"
	return p.run(ctx, sql)
}
func (p *PostgresSink) PersistRecord(ctx context.Context, r AssistanceRecord, receipt IdempotencyReceipt) error {
	raw, _ := json.Marshal(r)
	rr, _ := json.Marshal(receipt)
	sql := "BEGIN;\nINSERT INTO case_assistance_record(assistance_id,case_id,tenant_id,task,status,record_sha256,snapshot_sha256,generation_model_id,guardian_model_id,occurred_at,record_json) VALUES (" + sqlText(r.AssistanceID) + "," + sqlText(r.CaseID) + "," + sqlText(r.TenantID) + "," + sqlText(r.Task) + "," + sqlText(r.Status) + "," + sqlText(r.RecordSHA256) + "," + sqlText(r.Retrieval.SnapshotSHA256) + "," + sqlText(r.Generation.ModelID) + "," + sqlText(r.GuardianInvocation.ModelID) + "," + sqlText(r.OccurredAt) + "::timestamptz," + sqlJSON(raw) + ") ON CONFLICT(assistance_id) DO NOTHING;\nINSERT INTO case_assistance_idempotency(scope,key_sha256,request_sha256,response_sha256,object_type,object_id,created_at,receipt_json) VALUES (" + sqlText(receipt.Scope) + "," + sqlText(receipt.KeySHA256) + "," + sqlText(receipt.RequestSHA256) + "," + sqlText(receipt.ResponseSHA256) + "," + sqlText(receipt.ObjectType) + "," + sqlText(receipt.ObjectID) + "," + sqlText(receipt.CreatedAt) + "::timestamptz," + sqlJSON(rr) + ") ON CONFLICT(scope,key_sha256) DO NOTHING;\nCOMMIT;\n"
	return p.run(ctx, sql)
}
func (p *PostgresSink) PersistReview(ctx context.Context, e ReviewEvent, receipt IdempotencyReceipt) error {
	raw, _ := json.Marshal(e)
	rr, _ := json.Marshal(receipt)
	sql := "BEGIN;\nINSERT INTO case_assistance_review(assistance_id,case_id,sequence,event_sha256,previous_event_sha256,action,actor,reason,occurred_at,event_json) VALUES (" + sqlText(e.AssistanceID) + "," + sqlText(e.CaseID) + "," + fmt.Sprint(e.Sequence) + "," + sqlText(e.EventSHA256) + "," + sqlText(e.PreviousEventSHA256) + "," + sqlText(e.Action) + "," + sqlText(e.Actor) + "," + sqlText(e.Reason) + "," + sqlText(e.OccurredAt) + "::timestamptz," + sqlJSON(raw) + ") ON CONFLICT(event_sha256) DO NOTHING;\nINSERT INTO case_assistance_idempotency(scope,key_sha256,request_sha256,response_sha256,object_type,object_id,created_at,receipt_json) VALUES (" + sqlText(receipt.Scope) + "," + sqlText(receipt.KeySHA256) + "," + sqlText(receipt.RequestSHA256) + "," + sqlText(receipt.ResponseSHA256) + "," + sqlText(receipt.ObjectType) + "," + sqlText(receipt.ObjectID) + "," + sqlText(receipt.CreatedAt) + "::timestamptz," + sqlJSON(rr) + ") ON CONFLICT(scope,key_sha256) DO NOTHING;\nCOMMIT;\n"
	return p.run(ctx, sql)
}
func (p *PostgresSink) SyncAudit(ctx context.Context, stateDir string) error {
	files, _ := filepath.Glob(filepath.Join(stateDir, "audit", "events", "*.json"))
	sort.Strings(files)
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var e AuditEvent
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		sql := "INSERT INTO case_assistance_audit(stream_id,sequence,audit_sha256,previous_audit_sha256,occurred_at,action,actor,object_type,object_id,audit_json) VALUES (" + sqlText(e.StreamID) + "," + fmt.Sprint(e.Sequence) + "," + sqlText(e.AuditSHA256) + "," + sqlText(e.PreviousAuditSHA256) + "," + sqlText(e.OccurredAt) + "::timestamptz," + sqlText(e.Action) + "," + sqlText(e.Actor) + "," + sqlText(e.ObjectType) + "," + sqlText(e.ObjectID) + "," + sqlJSON(raw) + ") ON CONFLICT(audit_sha256) DO NOTHING;\n"
		if err := p.run(ctx, sql); err != nil {
			return err
		}
	}
	return nil
}
func sqlText(v string) string {
	return "convert_from(decode('" + hex.EncodeToString([]byte(v)) + "','hex'),'UTF8')"
}
func sqlJSON(raw []byte) string {
	return "convert_from(decode('" + hex.EncodeToString(raw) + "','hex'),'UTF8')::jsonb"
}

const SchemaSQL = `BEGIN;
CREATE TABLE IF NOT EXISTS rag_corpus_snapshot(
 snapshot_sha256 text PRIMARY KEY, corpus_id text NOT NULL, corpus_version text NOT NULL,
 built_at timestamptz NOT NULL, passage_count integer NOT NULL CHECK(passage_count>=0),
 snapshot_json jsonb NOT NULL, inserted_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS case_assistance_record(
 assistance_id text PRIMARY KEY, case_id text NOT NULL REFERENCES alert_case(case_id), tenant_id text NOT NULL,
 task text NOT NULL, status text NOT NULL, record_sha256 text NOT NULL UNIQUE, snapshot_sha256 text NOT NULL REFERENCES rag_corpus_snapshot(snapshot_sha256),
 generation_model_id text NOT NULL, guardian_model_id text NOT NULL, occurred_at timestamptz NOT NULL,
 record_json jsonb NOT NULL, inserted_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS case_assistance_review(
 assistance_id text NOT NULL REFERENCES case_assistance_record(assistance_id), case_id text NOT NULL,
 sequence bigint NOT NULL, event_sha256 text PRIMARY KEY, previous_event_sha256 text NOT NULL,
 action text NOT NULL CHECK(action IN ('accept','reject')), actor text NOT NULL, reason text NOT NULL,
 occurred_at timestamptz NOT NULL, event_json jsonb NOT NULL, inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(assistance_id,sequence)
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
`
