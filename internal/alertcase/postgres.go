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

// runBound is the tenantsql.Runner this sink hands to tenantsql.WithTenant.
// Only internal/tenantsql can construct the Bound proof it requires, which
// is what makes every statement below reach Postgres through the seam
// (ADR-0001 SEC-1 §3).
func (p *PostgresSink) runBound(ctx context.Context, _ tenantsql.Bound, sql string) error {
	return p.run(ctx, sql)
}

func (p *PostgresSink) Ping(ctx context.Context) error    { return p.run(ctx, "SELECT 1;\n") }
func (p *PostgresSink) Migrate(ctx context.Context) error { return p.run(ctx, SchemaSQL) }

func (p *PostgresSink) PersistAlert(ctx context.Context, alert AlertRecord, receipt IdempotencyReceipt) error {
	tenant, err := tenantctx.Assert(ctx, alert.TenantID)
	if err != nil {
		return err
	}
	alertJSON, _ := json.Marshal(alert)
	receiptJSON, _ := json.Marshal(receipt)
	body := tenantsql.Insert("alert_record", []tenantsql.Col{
		{Name: "alert_id", SQL: sqlText(alert.AlertID)},
		{Name: "tenant_id", SQL: sqlText(alert.TenantID)},
		{Name: "source_type", SQL: sqlText(alert.SourceType)},
		{Name: "source_identity", SQL: sqlText(alert.SourceIdentity)},
		{Name: "record_sha256", SQL: sqlText(alert.RecordSHA256)},
		{Name: "policy_route", SQL: sqlText(alert.PolicyDecision.Route)},
		{Name: "created_at", SQL: sqlText(alert.CreatedAt) + "::timestamptz"},
		{Name: "alert_json", SQL: sqlJSON(alertJSON)},
	}, "ON CONFLICT(alert_id) DO NOTHING") +
		tenantsql.InsertCatchConflict("alert_case_idempotency", []tenantsql.Col{
			{Name: "tenant_id", SQL: sqlText(tenant.String())},
			{Name: "scope", SQL: sqlText(receipt.Scope)},
			{Name: "key_sha256", SQL: sqlText(receipt.KeySHA256)},
			{Name: "request_sha256", SQL: sqlText(receipt.RequestSHA256)},
			{Name: "response_sha256", SQL: sqlText(receipt.ResponseSHA256)},
			{Name: "object_type", SQL: sqlText(receipt.ObjectType)},
			{Name: "object_id", SQL: sqlText(receipt.ObjectID)},
			{Name: "created_at", SQL: sqlText(receipt.CreatedAt) + "::timestamptz"},
			{Name: "receipt_json", SQL: sqlJSON(receiptJSON)},
		})
	return tenantsql.WithTenant(ctx, tenant, body, p.runBound)
}

func (p *PostgresSink) PersistCase(ctx context.Context, projection CaseProjection, event CaseEvent, receipt IdempotencyReceipt) error {
	tenant, err := tenantctx.Assert(ctx, projection.TenantID)
	if err != nil {
		return err
	}
	projectionJSON, _ := json.Marshal(projection)
	eventJSON, _ := json.Marshal(event)
	receiptJSON, _ := json.Marshal(receipt)
	memberships := ""
	for _, alertID := range projection.AlertIDs {
		memberships += tenantsql.Insert("alert_case_membership", []tenantsql.Col{
			{Name: "case_id", SQL: sqlText(projection.CaseID)},
			{Name: "alert_id", SQL: sqlText(alertID)},
			{Name: "joined_at", SQL: sqlText(projection.CreatedAt) + "::timestamptz"},
		}, "ON CONFLICT(case_id,alert_id) DO NOTHING")
	}
	body := tenantsql.Insert("alert_case", []tenantsql.Col{
		{Name: "case_id", SQL: sqlText(projection.CaseID)},
		{Name: "tenant_id", SQL: sqlText(projection.TenantID)},
		{Name: "state", SQL: sqlText(projection.State)},
		{Name: "revision", SQL: fmt.Sprint(projection.Revision)},
		{Name: "created_at", SQL: sqlText(projection.CreatedAt) + "::timestamptz"},
		{Name: "updated_at", SQL: sqlText(projection.UpdatedAt) + "::timestamptz"},
		{Name: "projection_json", SQL: sqlJSON(projectionJSON)},
	}, "ON CONFLICT(case_id) DO UPDATE SET state=EXCLUDED.state,revision=EXCLUDED.revision,updated_at=EXCLUDED.updated_at,projection_json=EXCLUDED.projection_json WHERE alert_case.revision<EXCLUDED.revision") +
		memberships +
		tenantsql.Insert("alert_case_event", []tenantsql.Col{
			{Name: "case_id", SQL: sqlText(event.CaseID)},
			{Name: "sequence", SQL: fmt.Sprint(event.Sequence)},
			{Name: "revision", SQL: fmt.Sprint(event.Revision)},
			{Name: "event_sha256", SQL: sqlText(event.EventSHA256)},
			{Name: "previous_event_sha256", SQL: sqlText(event.PreviousEventSHA256)},
			{Name: "occurred_at", SQL: sqlText(event.OccurredAt) + "::timestamptz"},
			{Name: "action", SQL: sqlText(event.Action)},
			{Name: "actor", SQL: sqlText(event.Actor)},
			{Name: "event_json", SQL: sqlJSON(eventJSON)},
		}, "ON CONFLICT(event_sha256) DO NOTHING") +
		tenantsql.InsertCatchConflict("alert_case_idempotency", []tenantsql.Col{
			{Name: "tenant_id", SQL: sqlText(tenant.String())},
			{Name: "scope", SQL: sqlText(receipt.Scope)},
			{Name: "key_sha256", SQL: sqlText(receipt.KeySHA256)},
			{Name: "request_sha256", SQL: sqlText(receipt.RequestSHA256)},
			{Name: "response_sha256", SQL: sqlText(receipt.ResponseSHA256)},
			{Name: "object_type", SQL: sqlText(receipt.ObjectType)},
			{Name: "object_id", SQL: sqlText(receipt.ObjectID)},
			{Name: "created_at", SQL: sqlText(receipt.CreatedAt) + "::timestamptz"},
			{Name: "receipt_json", SQL: sqlJSON(receiptJSON)},
		})
	return tenantsql.WithTenant(ctx, tenant, body, p.runBound)
}

// SyncAudit pushes the on-disk audit-event backlog to alert_case_audit
// (Class B, ADR-0001 SEC-1 §4). AuditEvent carries object_type/object_id
// but no tenant_id, and a live Postgres lookup can't supply one either:
// alert_case/alert_record are already FORCE RLS (db/migrations/013), so a
// SELECT issued over this sink's own owl_app connection returns zero rows
// until a tenant is already bound -- the exact chicken-and-egg the ADR's
// wildcard carve-out exists for, and tenantctx deliberately never
// constructs '*' for owl_app (invariant 6, ADR §8). The resolver instead
// reads the same on-disk projection ADR §5 derives tenant_id from during
// backfill (alerts/<id>.json, cases/<id>/projection.json) -- the
// authoritative source per the ADR's own Context section, and already
// present under stateDirectory. Resolved events are grouped by tenant so
// each Postgres transaction binds exactly one tenant; an event whose
// object_id doesn't resolve is logged and skipped, never fatal to the
// rest of the sweep.
func (p *PostgresSink) SyncAudit(ctx context.Context, stateDirectory string) error {
	files, err := filepath.Glob(filepath.Join(stateDirectory, "audit", "events", "*.json"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	byTenant := map[string]string{}
	var order []string
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var event AuditEvent
		if err := json.Unmarshal(raw, &event); err != nil {
			return err
		}
		tenantID, ok := resolveAuditTenant(stateDirectory, event)
		if !ok {
			continue
		}
		stmt := tenantsql.Insert("alert_case_audit", []tenantsql.Col{
			{Name: "stream_id", SQL: sqlText(event.StreamID)},
			{Name: "sequence", SQL: fmt.Sprint(event.Sequence)},
			{Name: "audit_sha256", SQL: sqlText(event.AuditSHA256)},
			{Name: "previous_audit_sha256", SQL: sqlText(event.PreviousAuditSHA256)},
			{Name: "occurred_at", SQL: sqlText(event.OccurredAt) + "::timestamptz"},
			{Name: "action", SQL: sqlText(event.Action)},
			{Name: "actor", SQL: sqlText(event.Actor)},
			{Name: "object_type", SQL: sqlText(event.ObjectType)},
			{Name: "object_id", SQL: sqlText(event.ObjectID)},
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

// resolveAuditTenant derives the tenant that owns an audit event's
// object_id, per the same object_type-driven join ADR-0001 SEC-1 §5 uses
// for the Postgres backfill, sourced from the on-disk record instead of a
// query RLS would block (see SyncAudit doc comment).
func resolveAuditTenant(stateDirectory string, event AuditEvent) (string, bool) {
	tenantID, path, err := lookupAuditTenant(stateDirectory, event.ObjectType, event.ObjectID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "alertcase: SyncAudit: cannot resolve tenant for stream_id=%s sequence=%d object_type=%s object_id=%s path=%q: %v; skipping\n",
			event.StreamID, event.Sequence, event.ObjectType, event.ObjectID, path, err)
		return "", false
	}
	return tenantID, true
}

func lookupAuditTenant(stateDirectory, objectType, objectID string) (tenantID, path string, err error) {
	switch objectType {
	case "alert":
		if err = validateAlertID(objectID); err != nil {
			return "", "", err
		}
		if path, err = confinedStatePath(stateDirectory, "alerts", objectID+".json"); err != nil {
			return "", path, err
		}
		var a AlertRecord
		if err = readStrictJSON(path, &a); err != nil {
			return "", path, err
		}
		if a.TenantID == "" {
			return "", path, errors.New("record has empty tenant_id")
		}
		return a.TenantID, path, nil
	case "case":
		if err = validateCaseID(objectID); err != nil {
			return "", "", err
		}
		if path, err = confinedStatePath(stateDirectory, "cases", objectID, "projection.json"); err != nil {
			return "", path, err
		}
		var c CaseProjection
		if err = readStrictJSON(path, &c); err != nil {
			return "", path, err
		}
		if c.TenantID == "" {
			return "", path, errors.New("record has empty tenant_id")
		}
		return c.TenantID, path, nil
	default:
		return "", "", fmt.Errorf("unsupported object_type %q", objectType)
	}
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
 tenant_id text NOT NULL,
 scope text NOT NULL,
 key_sha256 text NOT NULL,
 request_sha256 text NOT NULL,
 response_sha256 text NOT NULL,
 object_type text NOT NULL,
 object_id text NOT NULL,
 created_at timestamptz NOT NULL,
 receipt_json jsonb NOT NULL,
 inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,scope,key_sha256)
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
