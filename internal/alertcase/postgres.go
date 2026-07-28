package alertcase

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
		timeout = 20 * time.Second
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

func (p *PostgresSink) PersistAlert(ctx context.Context, alert AlertRecord, receipt IdempotencyReceipt) error {
	alertJSON, _ := json.Marshal(alert)
	receiptJSON, _ := json.Marshal(receipt)
	sql := "BEGIN;\n" +
		"INSERT INTO alert_record(alert_id,tenant_id,source_type,source_identity,record_sha256,policy_route,created_at,alert_json) VALUES (" + sqlText(alert.AlertID) + "," + sqlText(alert.TenantID) + "," + sqlText(alert.SourceType) + "," + sqlText(alert.SourceIdentity) + "," + sqlText(alert.RecordSHA256) + "," + sqlText(alert.PolicyDecision.Route) + "," + sqlText(alert.CreatedAt) + "::timestamptz," + sqlJSON(alertJSON) + ") ON CONFLICT(alert_id) DO NOTHING;\n" +
		"INSERT INTO alert_case_idempotency(scope,key_sha256,request_sha256,response_sha256,object_type,object_id,created_at,receipt_json) VALUES (" + sqlText(receipt.Scope) + "," + sqlText(receipt.KeySHA256) + "," + sqlText(receipt.RequestSHA256) + "," + sqlText(receipt.ResponseSHA256) + "," + sqlText(receipt.ObjectType) + "," + sqlText(receipt.ObjectID) + "," + sqlText(receipt.CreatedAt) + "::timestamptz," + sqlJSON(receiptJSON) + ") ON CONFLICT(scope,key_sha256) DO NOTHING;\nCOMMIT;\n"
	return p.run(ctx, sql)
}

func (p *PostgresSink) PersistCase(ctx context.Context, projection CaseProjection, event CaseEvent, receipt IdempotencyReceipt) error {
	projectionJSON, _ := json.Marshal(projection)
	eventJSON, _ := json.Marshal(event)
	receiptJSON, _ := json.Marshal(receipt)
	memberships := ""
	for _, alertID := range projection.AlertIDs {
		memberships += "INSERT INTO alert_case_membership(case_id,alert_id,joined_at) VALUES (" + sqlText(projection.CaseID) + "," + sqlText(alertID) + "," + sqlText(projection.CreatedAt) + "::timestamptz) ON CONFLICT(case_id,alert_id) DO NOTHING;\n"
	}
	sql := "BEGIN;\n" +
		"INSERT INTO alert_case(case_id,tenant_id,state,revision,created_at,updated_at,projection_json) VALUES (" + sqlText(projection.CaseID) + "," + sqlText(projection.TenantID) + "," + sqlText(projection.State) + "," + fmt.Sprint(projection.Revision) + "," + sqlText(projection.CreatedAt) + "::timestamptz," + sqlText(projection.UpdatedAt) + "::timestamptz," + sqlJSON(projectionJSON) + ") ON CONFLICT(case_id) DO UPDATE SET state=EXCLUDED.state,revision=EXCLUDED.revision,updated_at=EXCLUDED.updated_at,projection_json=EXCLUDED.projection_json WHERE alert_case.revision<EXCLUDED.revision;\n" + memberships +
		"INSERT INTO alert_case_event(case_id,sequence,revision,event_sha256,previous_event_sha256,occurred_at,action,actor,event_json) VALUES (" + sqlText(event.CaseID) + "," + fmt.Sprint(event.Sequence) + "," + fmt.Sprint(event.Revision) + "," + sqlText(event.EventSHA256) + "," + sqlText(event.PreviousEventSHA256) + "," + sqlText(event.OccurredAt) + "::timestamptz," + sqlText(event.Action) + "," + sqlText(event.Actor) + "," + sqlJSON(eventJSON) + ") ON CONFLICT(event_sha256) DO NOTHING;\n" +
		"INSERT INTO alert_case_idempotency(scope,key_sha256,request_sha256,response_sha256,object_type,object_id,created_at,receipt_json) VALUES (" + sqlText(receipt.Scope) + "," + sqlText(receipt.KeySHA256) + "," + sqlText(receipt.RequestSHA256) + "," + sqlText(receipt.ResponseSHA256) + "," + sqlText(receipt.ObjectType) + "," + sqlText(receipt.ObjectID) + "," + sqlText(receipt.CreatedAt) + "::timestamptz," + sqlJSON(receiptJSON) + ") ON CONFLICT(scope,key_sha256) DO NOTHING;\nCOMMIT;\n"
	return p.run(ctx, sql)
}

func (p *PostgresSink) SyncAudit(ctx context.Context, stateDirectory string) error {
	files, err := filepath.Glob(filepath.Join(stateDirectory, "audit", "events", "*.json"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var event AuditEvent
		if err := json.Unmarshal(raw, &event); err != nil {
			return err
		}
		sql := "INSERT INTO alert_case_audit(stream_id,sequence,audit_sha256,previous_audit_sha256,occurred_at,action,actor,object_type,object_id,audit_json) VALUES (" + sqlText(event.StreamID) + "," + fmt.Sprint(event.Sequence) + "," + sqlText(event.AuditSHA256) + "," + sqlText(event.PreviousAuditSHA256) + "," + sqlText(event.OccurredAt) + "::timestamptz," + sqlText(event.Action) + "," + sqlText(event.Actor) + "," + sqlText(event.ObjectType) + "," + sqlText(event.ObjectID) + "," + sqlJSON(raw) + ") ON CONFLICT(audit_sha256) DO NOTHING;\n"
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
CREATE TABLE IF NOT EXISTS alert_record(
 alert_id text PRIMARY KEY,
 tenant_id text NOT NULL,
 source_type text NOT NULL,
 source_identity text NOT NULL,
 record_sha256 text NOT NULL UNIQUE,
 policy_route text NOT NULL,
 created_at timestamptz NOT NULL,
 alert_json jsonb NOT NULL,
 inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,source_type,source_identity,record_sha256)
);
CREATE TABLE IF NOT EXISTS alert_case(
 case_id text PRIMARY KEY,
 tenant_id text NOT NULL,
 state text NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),
 created_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL,
 projection_json jsonb NOT NULL,
 inserted_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS alert_case_membership(
 case_id text NOT NULL REFERENCES alert_case(case_id),
 alert_id text NOT NULL REFERENCES alert_record(alert_id),
 joined_at timestamptz NOT NULL,
 PRIMARY KEY(case_id,alert_id)
);
CREATE TABLE IF NOT EXISTS alert_case_event(
 case_id text NOT NULL REFERENCES alert_case(case_id),
 sequence bigint NOT NULL,
 revision bigint NOT NULL,
 event_sha256 text PRIMARY KEY,
 previous_event_sha256 text NOT NULL,
 occurred_at timestamptz NOT NULL,
 action text NOT NULL,
 actor text NOT NULL,
 event_json jsonb NOT NULL,
 inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(case_id,sequence),UNIQUE(case_id,revision)
);
CREATE TABLE IF NOT EXISTS alert_case_idempotency(
 scope text NOT NULL,
 key_sha256 text NOT NULL,
 request_sha256 text NOT NULL,
 response_sha256 text NOT NULL,
 object_type text NOT NULL,
 object_id text NOT NULL,
 created_at timestamptz NOT NULL,
 receipt_json jsonb NOT NULL,
 inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(scope,key_sha256)
);
CREATE TABLE IF NOT EXISTS alert_case_audit(
 stream_id text NOT NULL,
 sequence bigint NOT NULL,
 audit_sha256 text PRIMARY KEY,
 previous_audit_sha256 text NOT NULL,
 occurred_at timestamptz NOT NULL,
 action text NOT NULL,
 actor text,
 object_type text NOT NULL,
 object_id text NOT NULL,
 audit_json jsonb NOT NULL,
 inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(stream_id,sequence)
);
CREATE OR REPLACE FUNCTION alert_case_reject_immutable_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'alert and case history rows are append-only'; END $$;
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
`
