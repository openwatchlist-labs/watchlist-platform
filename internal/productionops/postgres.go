package productionops

import (
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
	"github.com/openwatchlist-labs/watchlist-platform/internal/vendoradapter"
)

type PSQLRunner struct {
	DSN, Path string
	Timeout   time.Duration
}

func NewPSQLRunner(dsn, path string, timeout time.Duration) (*PSQLRunner, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("PostgreSQL DSN is required")
	}
	if path == "" {
		path = "psql"
	}
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &PSQLRunner{dsn, path, timeout}, nil
}
func (p *PSQLRunner) Run(ctx context.Context, sql string) error {
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.Path, p.DSN, "-X", "-v", "ON_ERROR_STOP=1", "--no-psqlrc", "--quiet")
	cmd.Stdin = strings.NewReader(sql)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("psql: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
func pgText(s string) string {
	return "convert_from(decode('" + hex.EncodeToString([]byte(s)) + "','hex'),'UTF8')"
}
func pgJSON(b []byte) string {
	return "convert_from(decode('" + hex.EncodeToString(b) + "','hex'),'UTF8')::jsonb"
}

// runBound is the tenantsql.Runner this sink hands to tenantsql.WithTenant.
// Only internal/tenantsql can construct the Bound proof it requires, which
// is what makes every statement below reach Postgres through the seam
// (ADR-0001 SEC-1 §3).
func (p *PSQLRunner) runBound(ctx context.Context, _ tenantsql.Bound, sql string) error {
	return p.Run(ctx, sql)
}

// tenantBatch groups SQL fragments by resolved tenant so each becomes its
// own single-tenant transaction: tenantsql.WithTenant binds exactly one
// tenant per call, and these two sync jobs process a state directory that
// spans every tenant's pending records in one run. This changes the unit
// of atomicity from "the whole run" (the previous single BEGIN..COMMIT)
// to "one tenant's slice of the run" -- a direct consequence of the
// seam's one-tenant-per-transaction design, not an incidental behavior
// change; see the SyncVendorAdapterState/SyncOutbox doc comments.
type tenantBatch struct {
	byTenant map[string]string
	order    []string
}

func (b *tenantBatch) add(tenantID, stmt string) {
	if b.byTenant == nil {
		b.byTenant = map[string]string{}
	}
	if _, seen := b.byTenant[tenantID]; !seen {
		b.order = append(b.order, tenantID)
	}
	b.byTenant[tenantID] += stmt
}

func (b *tenantBatch) commit(ctx context.Context, p *PSQLRunner, lockSQL string) error {
	sort.Strings(b.order)
	for _, tenantID := range b.order {
		tenant, err := tenantctx.Resolve(reviewauth.Claims{TenantID: tenantID})
		if err != nil {
			return err
		}
		if err := tenantsql.WithTenant(ctx, tenant, lockSQL+b.byTenant[tenantID], p.runBound); err != nil {
			return err
		}
	}
	return nil
}

// SyncVendorAdapterState pushes the on-disk vendor-adapter backlog
// (records/receipts/audit) to Postgres. Records carry their own tenant_id
// (CreateAlertRequest.TenantID); receipts and audit events don't, so their
// tenant is resolved via the same object_id -> owning record join
// ADR-0001 SEC-1 §5 specifies for the vendor_adapter_idempotency/
// vendor_adapter_audit backfill (record_id, object_id respectively),
// using the records already read in this same batch -- there is no
// cross-run index, so a receipt or audit event whose record isn't in this
// run's "records" glob is logged and skipped rather than guessed at.
func SyncVendorAdapterState(ctx context.Context, p *PSQLRunner, state string) (map[string]int, error) {
	records, _ := filepath.Glob(filepath.Join(state, "records", "*.json"))
	receipts, _ := filepath.Glob(filepath.Join(state, "receipts", "*.json"))
	audits, _ := filepath.Glob(filepath.Join(state, "audit", "*.json"))
	sort.Strings(records)
	sort.Strings(receipts)
	sort.Strings(audits)
	recordTenant := map[string]string{}
	var batch tenantBatch
	for _, f := range records {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var e vendoradapter.Envelope
		if err = json.Unmarshal(b, &e); err != nil {
			return nil, err
		}
		tenantID := strings.TrimSpace(e.CreateAlertRequest.TenantID)
		if _, err := tenantctx.Resolve(reviewauth.Claims{TenantID: tenantID}); err != nil {
			fmt.Fprintf(os.Stderr, "productionops: SyncVendorAdapterState: cannot resolve tenant for record_id=%s: %v; skipping\n", e.RecordID, err)
			continue
		}
		recordTenant[e.RecordID] = tenantID
		stmt := tenantsql.Insert("vendor_adapter_record", []tenantsql.Col{
			{Name: "record_id", SQL: pgText(e.RecordID)},
			{Name: "adapter_id", SQL: pgText(e.AdapterID)},
			{Name: "adapter_version", SQL: pgText(e.AdapterVersion)},
			{Name: "profile_sha256", SQL: pgText(e.ProfileSHA256)},
			{Name: "source_sha256", SQL: pgText(e.SourceSHA256)},
			{Name: "envelope_sha256", SQL: pgText(e.EnvelopeSHA256)},
			{Name: "tenant_id", SQL: pgText(tenantID)},
			{Name: "source_alert_id", SQL: pgText(e.CreateAlertRequest.ExternalAlert.SourceAlertID)},
			{Name: "occurred_at", SQL: pgText(e.CreateAlertRequest.OccurredAt) + "::timestamptz"},
			{Name: "envelope_json", SQL: pgJSON(b)},
		}, "ON CONFLICT(record_id) DO NOTHING")
		batch.add(tenantID, stmt)
	}
	for _, f := range receipts {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var r vendoradapter.Receipt
		if err = json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		tenantID, ok := recordTenant[r.RecordID]
		if !ok {
			fmt.Fprintf(os.Stderr, "productionops: SyncVendorAdapterState: cannot resolve tenant for receipt scope=%s record_id=%s: no matching record in this batch; skipping\n", r.Scope, r.RecordID)
			continue
		}
		stmt := tenantsql.Insert("vendor_adapter_idempotency", []tenantsql.Col{
			{Name: "scope", SQL: pgText(r.Scope)},
			{Name: "idempotency_key", SQL: pgText(r.IdempotencyKey)},
			{Name: "source_sha256", SQL: pgText(r.SourceSHA256)},
			{Name: "record_id", SQL: pgText(r.RecordID)},
			{Name: "receipt_json", SQL: pgJSON(b)},
		}, "ON CONFLICT(scope,idempotency_key) DO NOTHING")
		batch.add(tenantID, stmt)
	}
	for _, f := range audits {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var a vendoradapter.AuditEvent
		if err = json.Unmarshal(b, &a); err != nil {
			return nil, err
		}
		tenantID, ok := recordTenant[a.ObjectID]
		if !ok {
			fmt.Fprintf(os.Stderr, "productionops: SyncVendorAdapterState: cannot resolve tenant for audit stream_id=%s sequence=%d object_id=%s: no matching record in this batch; skipping\n", a.StreamID, a.Sequence, a.ObjectID)
			continue
		}
		stmt := tenantsql.Insert("vendor_adapter_audit", []tenantsql.Col{
			{Name: "stream_id", SQL: pgText(a.StreamID)},
			{Name: "sequence", SQL: fmt.Sprint(a.Sequence)},
			{Name: "previous_audit_sha256", SQL: pgText(a.PreviousAuditSHA256)},
			{Name: "audit_sha256", SQL: pgText(a.AuditSHA256)},
			{Name: "occurred_at", SQL: pgText(a.OccurredAt) + "::timestamptz"},
			{Name: "action", SQL: pgText(a.Action)},
			{Name: "object_type", SQL: pgText(a.ObjectType)},
			{Name: "object_id", SQL: pgText(a.ObjectID)},
			{Name: "details", SQL: pgJSON(a.Details)},
		}, "ON CONFLICT(audit_sha256) DO NOTHING")
		batch.add(tenantID, stmt)
	}
	if err := batch.commit(ctx, p, "SELECT pg_advisory_xact_lock(hashtext('openwatchlist-phase9g-vendor-sync'));\n"); err != nil {
		return nil, err
	}
	return map[string]int{"records": len(records), "receipts": len(receipts), "audits": len(audits)}, nil
}

// SyncOutbox pushes the on-disk outbox backlog (messages/events) to
// Postgres. Messages carry their own tenant_id; events reference a
// message_id only, so tenant is resolved via the message processed in
// this same batch -- see SyncVendorAdapterState's doc comment for why
// there is no cross-run index and what happens when a lookup misses.
func SyncOutbox(ctx context.Context, p *PSQLRunner, state string) (map[string]int, error) {
	messages, _ := filepath.Glob(filepath.Join(state, "messages", "*.json"))
	events, _ := filepath.Glob(filepath.Join(state, "events", "*.json"))
	sort.Strings(messages)
	sort.Strings(events)
	messageTenant := map[string]string{}
	var batch tenantBatch
	for _, f := range messages {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var m OutboxMessage
		if err = json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		tenantID := strings.TrimSpace(m.TenantID)
		if _, err := tenantctx.Resolve(reviewauth.Claims{TenantID: tenantID}); err != nil {
			fmt.Fprintf(os.Stderr, "productionops: SyncOutbox: cannot resolve tenant for message_id=%s: %v; skipping\n", m.MessageID, err)
			continue
		}
		messageTenant[m.MessageID] = tenantID
		stmt := tenantsql.Insert("operational_outbox_message", []tenantsql.Col{
			{Name: "message_id", SQL: pgText(m.MessageID)},
			{Name: "topic", SQL: pgText(m.Topic)},
			{Name: "tenant_id", SQL: pgText(tenantID)},
			{Name: "idempotency_key", SQL: pgText(m.IdempotencyKey)},
			{Name: "payload_sha256", SQL: pgText(m.PayloadSHA256)},
			{Name: "message_sha256", SQL: pgText(m.MessageSHA256)},
			{Name: "max_attempts", SQL: fmt.Sprint(m.MaxAttempts)},
			{Name: "created_at", SQL: pgText(m.CreatedAt) + "::timestamptz"},
			{Name: "message_json", SQL: pgJSON(b)},
		}, "ON CONFLICT(message_id) DO NOTHING")
		batch.add(tenantID, stmt)
	}
	for _, f := range events {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var e OutboxEvent
		if err = json.Unmarshal(b, &e); err != nil {
			return nil, err
		}
		tenantID, ok := messageTenant[e.MessageID]
		if !ok {
			fmt.Fprintf(os.Stderr, "productionops: SyncOutbox: cannot resolve tenant for event stream_id=%s sequence=%d message_id=%s: no matching message in this batch; skipping\n", e.StreamID, e.Sequence, e.MessageID)
			continue
		}
		stmt := tenantsql.Insert("operational_outbox_event", []tenantsql.Col{
			{Name: "stream_id", SQL: pgText(e.StreamID)},
			{Name: "sequence", SQL: fmt.Sprint(e.Sequence)},
			{Name: "event_sha256", SQL: pgText(e.EventSHA256)},
			{Name: "previous_event_sha256", SQL: pgText(e.PreviousEventSHA256)},
			{Name: "message_id", SQL: pgText(e.MessageID)},
			{Name: "occurred_at", SQL: pgText(e.OccurredAt) + "::timestamptz"},
			{Name: "action", SQL: pgText(e.Action)},
			{Name: "attempt", SQL: fmt.Sprint(e.Attempt)},
			{Name: "event_json", SQL: pgJSON(b)},
		}, "ON CONFLICT(event_sha256) DO NOTHING")
		batch.add(tenantID, stmt)
	}
	if err := batch.commit(ctx, p, "SELECT pg_advisory_xact_lock(hashtext('openwatchlist-phase9g-outbox-sync'));\n"); err != nil {
		return nil, err
	}
	return map[string]int{"messages": len(messages), "events": len(events)}, nil
}
