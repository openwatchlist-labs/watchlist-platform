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

	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewauth"
	"github.com/openwatchlist-labs/watchlist-platform/internal/tenantctx"
	"github.com/openwatchlist-labs/watchlist-platform/internal/tenantsql"
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

// runBound is the tenantsql.Runner this sink hands to tenantsql.WithTenant.
// Only internal/tenantsql can construct the Bound proof it requires, which
// is what makes every statement below reach Postgres through the seam
// (ADR-0001 SEC-1 §3).
func (p *PostgresSink) runBound(ctx context.Context, _ tenantsql.Bound, sql string) error {
	return p.run(ctx, sql)
}

func (p *PostgresSink) Ping(ctx context.Context) error    { return p.run(ctx, "SELECT 1;\n") }
func (p *PostgresSink) Migrate(ctx context.Context) error { return p.run(ctx, SchemaSQL) }

// PersistSnapshot writes rag_corpus_snapshot, which is Class D (platform-
// global, ADR-0001 SEC-1 §4) -- content-addressed and shared across
// tenants by design, so it is deliberately not routed through the seam.
func (p *PostgresSink) PersistSnapshot(ctx context.Context, s CorpusSnapshot) error {
	raw, _ := json.Marshal(s)
	sql := "INSERT INTO rag_corpus_snapshot(snapshot_sha256,corpus_id,corpus_version,built_at,passage_count,snapshot_json) VALUES (" + sqlText(s.SnapshotSHA256) + "," + sqlText(s.CorpusID) + "," + sqlText(s.Version) + "," + sqlText(s.BuiltAt) + "::timestamptz," + fmt.Sprint(s.PassageCount) + "," + sqlJSON(raw) + ") ON CONFLICT(snapshot_sha256) DO NOTHING;\n"
	return p.run(ctx, sql)
}

func (p *PostgresSink) PersistRecord(ctx context.Context, r AssistanceRecord, receipt IdempotencyReceipt) error {
	tenant, err := tenantctx.Assert(ctx, r.TenantID)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(r)
	rr, _ := json.Marshal(receipt)
	body := tenantsql.Insert("case_assistance_record", []tenantsql.Col{
		{Name: "assistance_id", SQL: sqlText(r.AssistanceID)},
		{Name: "case_id", SQL: sqlText(r.CaseID)},
		{Name: "tenant_id", SQL: sqlText(r.TenantID)},
		{Name: "task", SQL: sqlText(r.Task)},
		{Name: "status", SQL: sqlText(r.Status)},
		{Name: "record_sha256", SQL: sqlText(r.RecordSHA256)},
		{Name: "snapshot_sha256", SQL: sqlText(r.Retrieval.SnapshotSHA256)},
		{Name: "generation_model_id", SQL: sqlText(r.Generation.ModelID)},
		{Name: "guardian_model_id", SQL: sqlText(r.GuardianInvocation.ModelID)},
		{Name: "occurred_at", SQL: sqlText(r.OccurredAt) + "::timestamptz"},
		{Name: "record_json", SQL: sqlJSON(raw)},
	}, "ON CONFLICT(assistance_id) DO NOTHING") +
		tenantsql.Insert("case_assistance_idempotency", []tenantsql.Col{
			{Name: "scope", SQL: sqlText(receipt.Scope)},
			{Name: "key_sha256", SQL: sqlText(receipt.KeySHA256)},
			{Name: "request_sha256", SQL: sqlText(receipt.RequestSHA256)},
			{Name: "response_sha256", SQL: sqlText(receipt.ResponseSHA256)},
			{Name: "object_type", SQL: sqlText(receipt.ObjectType)},
			{Name: "object_id", SQL: sqlText(receipt.ObjectID)},
			{Name: "created_at", SQL: sqlText(receipt.CreatedAt) + "::timestamptz"},
			{Name: "receipt_json", SQL: sqlJSON(rr)},
		}, "ON CONFLICT(scope,key_sha256) DO NOTHING")
	return tenantsql.WithTenant(ctx, tenant, body, p.runBound)
}

// PersistReview writes case_assistance_review, which -- like ReviewEvent
// itself -- carries no tenant_id (only assistance_id/case_id). tenantID is
// the assistance record's own stored tenant, which the caller already has
// via Store.Record(assistance_id) before calling this; it goes through
// the same Assert() path as every other write, so it is still checked
// against a ctx-bound tenant rather than trusted outright.
func (p *PostgresSink) PersistReview(ctx context.Context, e ReviewEvent, receipt IdempotencyReceipt, tenantID string) error {
	tenant, err := tenantctx.Assert(ctx, tenantID)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(e)
	rr, _ := json.Marshal(receipt)
	body := tenantsql.Insert("case_assistance_review", []tenantsql.Col{
		{Name: "assistance_id", SQL: sqlText(e.AssistanceID)},
		{Name: "case_id", SQL: sqlText(e.CaseID)},
		{Name: "sequence", SQL: fmt.Sprint(e.Sequence)},
		{Name: "event_sha256", SQL: sqlText(e.EventSHA256)},
		{Name: "previous_event_sha256", SQL: sqlText(e.PreviousEventSHA256)},
		{Name: "action", SQL: sqlText(e.Action)},
		{Name: "actor", SQL: sqlText(e.Actor)},
		{Name: "reason", SQL: sqlText(e.Reason)},
		{Name: "occurred_at", SQL: sqlText(e.OccurredAt) + "::timestamptz"},
		{Name: "event_json", SQL: sqlJSON(raw)},
	}, "ON CONFLICT(event_sha256) DO NOTHING") +
		tenantsql.Insert("case_assistance_idempotency", []tenantsql.Col{
			{Name: "scope", SQL: sqlText(receipt.Scope)},
			{Name: "key_sha256", SQL: sqlText(receipt.KeySHA256)},
			{Name: "request_sha256", SQL: sqlText(receipt.RequestSHA256)},
			{Name: "response_sha256", SQL: sqlText(receipt.ResponseSHA256)},
			{Name: "object_type", SQL: sqlText(receipt.ObjectType)},
			{Name: "object_id", SQL: sqlText(receipt.ObjectID)},
			{Name: "created_at", SQL: sqlText(receipt.CreatedAt) + "::timestamptz"},
			{Name: "receipt_json", SQL: sqlJSON(rr)},
		}, "ON CONFLICT(scope,key_sha256) DO NOTHING")
	return tenantsql.WithTenant(ctx, tenant, body, p.runBound)
}

// SyncAudit pushes the on-disk audit-event backlog to case_assistance_audit
// (Class B, ADR-0001 SEC-1 §4). See internal/alertcase/postgres.go's
// SyncAudit doc comment for why this resolves tenant from the on-disk
// assistance record rather than a live Postgres lookup: case_assistance_record
// is FORCE RLS'd already, so an unbound SELECT over this sink's own
// connection always returns zero rows -- the resolver needs the tenant
// before it can query for it. Every audit event here has object_type
// "assistance", so the join is a single lookup rather than alertcase's
// two-way one. Resolved events are grouped by tenant so each Postgres
// transaction binds exactly one; an event whose object_id doesn't resolve
// is logged and skipped, never fatal to the rest of the sweep.
func (p *PostgresSink) SyncAudit(ctx context.Context, stateDir string) error {
	files, _ := filepath.Glob(filepath.Join(stateDir, "audit", "events", "*.json"))
	sort.Strings(files)
	byTenant := map[string]string{}
	var order []string
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var e AuditEvent
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		tenantID, ok := resolveAuditTenant(stateDir, e)
		if !ok {
			continue
		}
		stmt := tenantsql.Insert("case_assistance_audit", []tenantsql.Col{
			{Name: "stream_id", SQL: sqlText(e.StreamID)},
			{Name: "sequence", SQL: fmt.Sprint(e.Sequence)},
			{Name: "audit_sha256", SQL: sqlText(e.AuditSHA256)},
			{Name: "previous_audit_sha256", SQL: sqlText(e.PreviousAuditSHA256)},
			{Name: "occurred_at", SQL: sqlText(e.OccurredAt) + "::timestamptz"},
			{Name: "action", SQL: sqlText(e.Action)},
			{Name: "actor", SQL: sqlText(e.Actor)},
			{Name: "object_type", SQL: sqlText(e.ObjectType)},
			{Name: "object_id", SQL: sqlText(e.ObjectID)},
			{Name: "audit_json", SQL: sqlJSON(raw)},
		}, "ON CONFLICT(audit_sha256) DO NOTHING")
		if _, seen := byTenant[tenantID]; !seen {
			order = append(order, tenantID)
		}
		byTenant[tenantID] += stmt
	}
	sort.Strings(order)
	for _, tenantID := range order {
		tenant, err := tenantctx.Resolve(reviewauth.Claims{TenantID: tenantID})
		if err != nil {
			return err
		}
		if err := tenantsql.WithTenant(ctx, tenant, byTenant[tenantID], p.runBound); err != nil {
			return err
		}
	}
	return nil
}

func resolveAuditTenant(stateDir string, event AuditEvent) (string, bool) {
	if event.ObjectType != "assistance" {
		fmt.Fprintf(os.Stderr, "assistancerag: SyncAudit: unsupported object_type for stream_id=%s sequence=%d object_type=%s object_id=%s; skipping\n",
			event.StreamID, event.Sequence, event.ObjectType, event.ObjectID)
		return "", false
	}
	if err := validateAssistanceID(event.ObjectID); err != nil {
		fmt.Fprintf(os.Stderr, "assistancerag: SyncAudit: cannot resolve tenant for stream_id=%s sequence=%d object_id=%s: %v; skipping\n",
			event.StreamID, event.Sequence, event.ObjectID, err)
		return "", false
	}
	path, err := confinedStatePath(stateDir, "assistance", event.ObjectID+".json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "assistancerag: SyncAudit: cannot resolve tenant for stream_id=%s sequence=%d object_id=%s: %v; skipping\n",
			event.StreamID, event.Sequence, event.ObjectID, err)
		return "", false
	}
	var record AssistanceRecord
	if err := ReadStrictJSON(path, &record); err != nil || record.TenantID == "" {
		if err == nil {
			err = errors.New("record has empty tenant_id")
		}
		fmt.Fprintf(os.Stderr, "assistancerag: SyncAudit: cannot resolve tenant for stream_id=%s sequence=%d object_id=%s path=%q: %v; skipping\n",
			event.StreamID, event.Sequence, event.ObjectID, path, err)
		return "", false
	}
	return record.TenantID, true
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
