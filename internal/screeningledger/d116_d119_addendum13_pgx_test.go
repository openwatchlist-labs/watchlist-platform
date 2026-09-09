// ADR-0007 Addendum 13 D122 items 6 and 9's remaining pieces:
// D116's shared-tenancy refusal (Store.PurgeExpired must refuse under a
// signed TenancyShared policy, by name, not silently revert to D98's
// floor) and D119's own test that has never existed (the exclusive
// assertion fired against a schema that is GENUINELY shared -- the
// primary this whole suite runs against -- rather than one made
// single-tenant by DELETE, as newD110SingleTenantFixture's own clones
// are).
package screeningledger

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestPurgeExpiredRefusesUnderSharedTenancy is D122 item 6's shared-
// tenancy refusal: Store.PurgeExpired refuses outright under
// TenancyShared, by name, before it ever calls RecordPurge -- R49's own
// honest limit, stated at purge time. A fake recorder that would panic
// if invoked confirms RecordPurge is never reached.
func TestPurgeExpiredRefusesUnderSharedTenancy(t *testing.T) {
	store, err := NewStore(t.TempDir(), testKey(), uniqueID("d116-shared-refusal"))
	if err != nil {
		t.Fatal(err)
	}
	input := testAppendInput()
	if _, err := store.Append(input); err != nil {
		t.Fatal(err)
	}
	neverCalled := purgeRecorderFunc(func(context.Context, []string, map[string]snapshotObligation, string, string, string) ([]string, error) {
		t.Fatal("RecordPurge must never be called when PurgeExpired refuses under TenancyShared")
		return nil, nil
	})
	_, err = store.PurgeExpired(context.Background(), time.Now(), "operator", "reason", TenancyShared, neverCalled)
	if err == nil {
		t.Fatal("ADR-0007 Addendum 13 D116: expected PurgeExpired to refuse under TenancyShared")
	}
	if !strings.Contains(err.Error(), "D116") {
		t.Fatalf("expected the refusal to cite ADR-0007 Addendum 13 D116, got: %v", err)
	}
}

// TestPurgeExpiredRefusesAnUndeclaredTenancy confirms PurgeExpired
// refuses any tenancy value that is neither TenancyExclusive nor
// TenancyShared, rather than defaulting either way -- the same
// closed-set discipline D110's own tenancy field validation applies at
// the policy layer (DecodeUnsignedPolicy), enforced independently here
// at the one call site that actually consumes the value.
func TestPurgeExpiredRefusesAnUndeclaredTenancy(t *testing.T) {
	store, err := NewStore(t.TempDir(), testKey(), uniqueID("d116-undeclared-tenancy"))
	if err != nil {
		t.Fatal(err)
	}
	neverCalled := purgeRecorderFunc(func(context.Context, []string, map[string]snapshotObligation, string, string, string) ([]string, error) {
		t.Fatal("RecordPurge must never be called when PurgeExpired refuses an undeclared tenancy")
		return nil, nil
	})
	_, err = store.PurgeExpired(context.Background(), time.Now(), "operator", "reason", "", neverCalled)
	if err == nil {
		t.Fatal("ADR-0007 Addendum 13 D116: expected PurgeExpired to refuse an empty/undeclared tenancy")
	}
	if !strings.Contains(err.Error(), "D116") {
		t.Fatalf("expected the refusal to cite ADR-0007 Addendum 13 D116, got: %v", err)
	}
}

type purgeRecorderFunc func(ctx context.Context, eligibleSHA256 []string, obligations map[string]snapshotObligation, ledgerID, operator, reason string) ([]string, error)

func (f purgeRecorderFunc) RecordPurge(ctx context.Context, eligibleSHA256 []string, obligations map[string]snapshotObligation, ledgerID, operator, reason string) ([]string, error) {
	return f(ctx, eligibleSHA256, obligations, ledgerID, operator, reason)
}

// TestExclusiveTenancyFailsAgainstAGenuinelySharedSchema is D119's own
// test that has never existed (D122 item 9): every other exclusive-
// tenancy test in this package (TestSingleLedgerExclusiveVerifiesClean
// and its neighbors) runs against a newD50Clone made single-tenant by
// DELETE -- makeGenuinelySingleTenant, this same file -- which proves
// the assertion fires when it SHOULD NOT. This test fires it against
// the schema D110's own justification actually cites: the shared
// OWL_MIGRATOR_DATABASE_URL/OWL_TEST_DATABASE_URL primary this whole
// suite runs against, genuinely carrying many ledger_ids (re-confirmed
// live by TestR43PremiseFailsAgainstCurrentDatabase in this same file),
// with no clone and no DELETE. A ledger declaring TenancyExclusive
// there must fail, naming at least one foreign id and the relation it
// was found in.
func TestExclusiveTenancyFailsAgainstAGenuinelySharedSchema(t *testing.T) {
	ctx := context.Background()
	migratorDSN := requireMigratorDSN(t)
	anchorDSN := requireAnchorDatabaseURL(t)

	store, err := NewStore(t.TempDir(), testKey(), uniqueID("d119-shared-schema"))
	if err != nil {
		t.Fatal(err)
	}
	sink, err := NewPostgresSink(ctx, migratorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())
	anchorSink, err := NewAnchorSink(ctx, anchorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewAnchorSink: %v", err)
	}
	defer anchorSink.Close(context.Background())

	input := testAppendInput()
	input.CorrelationID = uniqueID("corr-d119-shared")
	input.IdempotencyKey = uniqueID("idem-d119-shared")
	input.RequestBytes = []byte(`{"unique":"` + uniqueID("d119-shared-req") + `"}`)
	input.ResponseBytes = []byte(`{"unique":"` + uniqueID("d119-shared-resp") + `"}`)
	result, err := store.Append(input)
	if err != nil {
		t.Fatal(err)
	}
	request, err := store.LoadSnapshot(result.Event.RequestSnapshotSHA256)
	if err != nil {
		t.Fatal(err)
	}
	response, err := store.LoadSnapshot(result.Event.ResponseSnapshotSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Persist(ctx, result.Event, request, response, ReplicationVerification{}); err != nil {
		t.Fatal(err)
	}

	kAnchor := make([]byte, 32)
	for i := range kAnchor {
		kAnchor[i] = byte(i + 201)
	}
	policy := testExclusivePolicy(store.ledgerID)
	report, err := store.VerifyPolicy(ctx, VerifyOptions{Policy: policy, Purges: sink, allowDeferredPurgeClaims: true})
	if err != nil {
		t.Fatalf("VerifyPolicy: %v", err)
	}
	if err := anchorSink.WriteAnchor(ctx, kAnchor, store.ledgerID, int64(report.Head.Sequence), report.Head.EventSHA256, report.AuditHead.EventSHA256, int64(report.AuditHead.Sequence), testPolicySHA256(t, policy)); err != nil {
		t.Fatalf("WriteAnchor: %v", err)
	}

	result2, err := store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: policy, Purges: sink},
		Anchors:       sink, Provisioning: sink, KAnchor: kAnchor, PolicySHA256: testPolicySHA256(t, policy),
	})
	if err == nil && result2.AnchorStatus == AnchorStatusVerified {
		t.Fatal("ADR-0007 Addendum 13 D119: expected exclusive tenancy to FAIL against the genuinely shared primary database (no clone, no DELETE) -- if this now verifies clean, the shared database may have been emptied of every other ledger's rows, invalidating this test's own precondition")
	}
	if err == nil {
		t.Fatalf("expected an error, got status=%v with no error", result2.AnchorStatus)
	}
	if !strings.Contains(err.Error(), "D110") {
		t.Fatalf("expected the failure to cite ADR-0007 Addendum 12 D110, got: %v", err)
	}
	t.Logf("A13D119 exclusive tenancy correctly failed against the genuinely shared schema: %v", err)
}
