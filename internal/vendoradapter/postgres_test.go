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

// TestPersistWithoutBoundTenantReturnsErrNoBoundTenant is the inversion of
// the PR #92 hotfix's own regression test (ADR-0006 §6, D6). PR #92's
// assertTenant fell back to resolving the body-supplied tenant_id directly
// when ctx carried no bound tenant, as an interim for
// internal/vendoradapterapi having no auth middleware. ADR-0006 D1 gives
// vendoradapterapi a bound tenant of its own, so that interim is deleted and
// Persist calls tenantctx.Assert directly: an unbound Persist must now fail
// closed with ErrNoBoundTenant, the same as every other sink
// (internal/tenantctx/tenantctx.go:81-85). Leaving this passing under the
// old, non-inverted assertion would mean the fallback was not actually
// removed.
func TestPersistWithoutBoundTenantReturnsErrNoBoundTenant(t *testing.T) {
	sink := fakePSQLSink(t)
	e, r := testEnvelopeAndReceipt("tenant-a")
	err := sink.Persist(context.Background(), e, r)
	if !errors.Is(err, tenantctx.ErrNoBoundTenant) {
		t.Fatalf("Persist() with no bound tenant = %v, want ErrNoBoundTenant (ADR-0006 D6: the PR #92 interim is deleted)", err)
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
