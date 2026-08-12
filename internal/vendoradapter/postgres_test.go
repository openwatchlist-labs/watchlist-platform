package vendoradapter

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertcase"
	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewauth"
	"github.com/openwatchlist-labs/watchlist-platform/internal/tenantctx"
)

// fakePSQLSink builds a PostgresSink whose PSQL binary is the shared
// fake-psql.sh fixture (test/fixtures/alert-case/fake-psql.sh: reads
// stdin, prints "ok", exits 0), so Persist exercises the real
// tenantctx.Assert / tenantsql.WithTenant path without a live database.
func fakePSQLSink(t *testing.T) *PostgresSink {
	t.Helper()
	root := repoRoot(t)
	sink, err := NewPostgresSink("postgres://fixture", filepath.Join(root, "test", "fixtures", "alert-case", "fake-psql.sh"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return sink
}

func testEnvelopeAndReceipt(tenant string) (Envelope, Receipt) {
	req := alertcase.CreateAlertRequest{
		TenantID:       tenant,
		SourceType:     "external_alert",
		CorrelationID:  "corr-1",
		IdempotencyKey: "idem-1",
		OccurredAt:     "2026-07-15T14:30:00Z",
		ExternalAlert:  &alertcase.ExternalAlert{SchemaVersion: alertcase.ExternalAlertSchemaV1, SourceSystemID: "sys", SourceAlertID: "alert-1", RawListName: "OFAC SDN", OccurredAt: "2026-07-15T14:30:00Z"},
	}
	e := Envelope{
		SchemaVersion:      EnvelopeSchemaV1,
		RecordID:           "vadp_test1",
		AdapterID:          "generic-json-v1",
		AdapterVersion:     "v1",
		Vendor:             "generic",
		ProfileSHA256:      "deadbeef",
		SourceRef:          "test",
		SourceSHA256:       "deadbeef",
		CreateAlertRequest: req,
		ConvertedAt:        "2026-07-15T14:30:00Z",
		EnvelopeSHA256:     "deadbeef",
	}
	r := Receipt{SchemaVersion: ReceiptSchemaV1, Scope: "ingest:generic-json-v1", IdempotencyKey: "idem-1", SourceSHA256: "deadbeef", RecordID: e.RecordID, CreatedAt: "2026-07-15T14:30:00Z"}
	return e, r
}

// TestPersistWithoutBoundTenantIsNotUnconditionallyRejected is the
// regression test for the SEC-1b fallback-removal hotfix. SEC-1b
// (internal/tenantctx/tenantctx.go:81-85) deleted tenantctx.Assert's
// body-fallback unconditionally, but internal/vendoradapterapi has no auth
// middleware and never binds a tenant on ctx (SEC-1e is the tracked,
// not-yet-landed fix for that). Before the hotfix, every call reaching
// this sink through vendoradapterapi therefore fails closed with
// ErrNoBoundTenant regardless of what the profile-derived tenant_id is.
// This must fail before the hotfix and pass after it.
func TestPersistWithoutBoundTenantIsNotUnconditionallyRejected(t *testing.T) {
	sink := fakePSQLSink(t)
	e, r := testEnvelopeAndReceipt("tenant-a")
	err := sink.Persist(context.Background(), e, r)
	if errors.Is(err, tenantctx.ErrNoBoundTenant) {
		t.Fatalf("Persist() with no bound tenant = %v, want the interim body-trust fallback to apply for this call site (ADR-0003 SEC-1e interim), not ErrNoBoundTenant", err)
	}
	if err != nil {
		t.Fatalf("Persist() with no bound tenant and a valid body tenant_id: unexpected error: %v", err)
	}
}

// TestPersistWithBoundTenantStillEnforcesMismatch guards against the
// interim fix widening into a general fallback: when ctx does carry a
// bound tenant (the state SEC-1e will eventually put vendoradapterapi
// into), a disagreeing body tenant_id must still be rejected exactly as
// tenantctx.Assert already specifies for alertcaseapi/screeningapi.
func TestPersistWithBoundTenantStillEnforcesMismatch(t *testing.T) {
	sink := fakePSQLSink(t)
	e, r := testEnvelopeAndReceipt("tenant-other")
	bound, err := tenantctx.Resolve(reviewauth.Claims{TenantID: "tenant-a"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := tenantctx.NewContext(context.Background(), bound)
	err = sink.Persist(ctx, e, r)
	if !errors.Is(err, tenantctx.ErrTenantMismatch) {
		t.Fatalf("Persist() with bound tenant-a and body tenant-other = %v, want ErrTenantMismatch", err)
	}
}
