package vendoradapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewauth"
	"github.com/openwatchlist-labs/watchlist-platform/internal/tenantctx"
	"github.com/openwatchlist-labs/watchlist-platform/internal/tenantsql"
)

type PostgresSink struct {
	DSN, PSQL string
	Timeout   time.Duration
}

func NewPostgresSink(dsn, psql string, timeout time.Duration) (*PostgresSink, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("PostgreSQL DSN is required")
	}
	if psql == "" {
		psql = "psql"
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &PostgresSink{dsn, psql, timeout}, nil
}
func (p *PostgresSink) run(ctx context.Context, sql string) error {
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.PSQL, p.DSN, "-v", "ON_ERROR_STOP=1", "-X", "-q", "-c", sql)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("psql: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runBound is the tenantsql.Runner this sink hands to tenantsql.WithTenant.
// Only internal/tenantsql can construct the Bound proof it requires, which
// is what makes every statement below reach Postgres through the seam
// (ADR-0001 SEC-1 §3).
func (p *PostgresSink) runBound(ctx context.Context, _ tenantsql.Bound, sql string) error {
	return p.run(ctx, sql)
}

func (p *PostgresSink) Ping(ctx context.Context) error { return p.run(ctx, "SELECT 1") }

// assertTenant is a narrowly-scoped interim for this sink's call site only
// (ADR-0003 SEC-1e, tracked as the sequencing dependency ADR-0003 §10
// flags for internal/vendoradapterapi). SEC-1b deleted
// tenantctx.Assert's body-fallback unconditionally
// (internal/tenantctx/tenantctx.go:81-85), but internal/vendoradapterapi
// has no auth middleware and never binds a tenant on ctx, so every write
// through this sink started failing closed with ErrNoBoundTenant. When
// ctx does carry a bound tenant -- the state SEC-1e will eventually put
// this surface into -- this defers to tenantctx.Assert unchanged,
// including its mismatch rejection. Only when ctx carries no bound tenant
// does it fall back to resolving the body-supplied tenant_id directly,
// mirroring tenantctx.Assert's pre-SEC-1b fallback behavior for this one
// caller. This must NOT be generalized back into tenantctx.Assert itself
// -- that would silently reopen the hole SEC-1b closed for
// alertcaseapi/screeningapi. Delete this function and call
// tenantctx.Assert directly once SEC-1e gives vendoradapterapi a bound
// tenant of its own.
func assertTenant(ctx context.Context, id string) (tenantctx.Tenant, error) {
	if _, ok := tenantctx.FromContext(ctx); ok {
		return tenantctx.Assert(ctx, id)
	}
	return tenantctx.Resolve(reviewauth.Claims{TenantID: id})
}

func (p *PostgresSink) Persist(ctx context.Context, e Envelope, r Receipt) error {
	tenant, err := assertTenant(ctx, e.CreateAlertRequest.TenantID)
	if err != nil {
		return err
	}
	eb, _ := json.Marshal(e)
	rb, _ := json.Marshal(r)
	body := tenantsql.Insert("vendor_adapter_record", []tenantsql.Col{
		{Name: "record_id", SQL: q(e.RecordID)},
		{Name: "adapter_id", SQL: q(e.AdapterID)},
		{Name: "adapter_version", SQL: q(e.AdapterVersion)},
		{Name: "profile_sha256", SQL: q(e.ProfileSHA256)},
		{Name: "source_sha256", SQL: q(e.SourceSHA256)},
		{Name: "envelope_sha256", SQL: q(e.EnvelopeSHA256)},
		{Name: "tenant_id", SQL: q(e.CreateAlertRequest.TenantID)},
		{Name: "source_alert_id", SQL: q(e.CreateAlertRequest.ExternalAlert.SourceAlertID)},
		{Name: "occurred_at", SQL: q(e.CreateAlertRequest.OccurredAt) + "::timestamptz"},
		{Name: "envelope_json", SQL: q(string(eb)) + "::jsonb"},
	}, "ON CONFLICT(record_id) DO NOTHING") +
		tenantsql.InsertCatchConflict("vendor_adapter_idempotency", []tenantsql.Col{
			{Name: "tenant_id", SQL: q(tenant.String())},
			{Name: "scope", SQL: q(r.Scope)},
			{Name: "idempotency_key", SQL: q(r.IdempotencyKey)},
			{Name: "source_sha256", SQL: q(r.SourceSHA256)},
			{Name: "record_id", SQL: q(r.RecordID)},
			{Name: "receipt_json", SQL: q(string(rb)) + "::jsonb"},
		})
	return tenantsql.WithTenant(ctx, tenant, body, p.runBound)
}
func q(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
