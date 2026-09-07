// ADR-0007 Addendum 12 D109 test file (D112 item 6): P-D's crash-window
// reproduction, reproduced independently against a real disposable
// Postgres cluster before this addendum's design was written
// (0007:11714-11739), is not re-derived here from the ADR transcript --
// these tests build it fresh, through the real, unmodified
// Store.Append/PostgresSink.Persist/Store.Sync, exactly as that
// reproduction did.
package screeningledger

import (
	"context"
	"errors"
	"testing"
	"time"
)

// d109Fixture is shared scaffolding: one ledger, one already-anchored,
// already-clean state (a legitimate purge, fully verified), so every
// subtest below starts from a known-good baseline and diverges from it
// in exactly one, deliberate way. sharedRequest/sharedResponse are kept
// so a later event can be appended referencing the SAME content-
// addressed sha as the fixture's own pair.
type d109Fixture struct {
	store          *Store
	sink           *PostgresSink
	anchorSink     *AnchorSink
	kAnchor        []byte
	policy         VerificationPolicy
	policySHA256   string
	sha            string
	sharedRequest  []byte
	sharedResponse []byte
}

func newD109Fixture(t *testing.T, ctx context.Context, tag string) d109Fixture {
	t.Helper()
	dsn := requireMigratorDSN(t)
	anchorDSN := requireAnchorDatabaseURL(t)
	sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	t.Cleanup(func() { sink.Close(context.Background()) })
	anchorSink, err := NewAnchorSink(ctx, anchorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewAnchorSink: %v", err)
	}
	t.Cleanup(func() { anchorSink.Close(context.Background()) })
	store, err := NewStore(t.TempDir(), testKey(), uniqueID("d109-"+tag))
	if err != nil {
		t.Fatal(err)
	}
	kAnchor := make([]byte, 32)
	for i := range kAnchor {
		kAnchor[i] = byte(i + 131)
	}
	policy := testPolicy(store.ledgerID)
	policySHA256 := testPolicySHA256(t, policy)

	sharedRequest := []byte(`{"unique":"` + uniqueID(tag+"-req") + `"}`)
	sharedResponse := []byte(`{"unique":"` + uniqueID(tag+"-resp") + `"}`)
	mirror := func(result AppendResult) {
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
		// Mark replicated locally too -- ShortfallExplainedByUnreplicated
		// Events (D109) trusts store.IsReplicated as the discriminator
		// between "known backlog" and "genuinely wrong," so this helper
		// must keep local bookkeeping honest about what has actually
		// been mirrored, exactly as cmd/screening-ledger's own sync path
		// always has.
		if err := store.MarkReplicated(result.Event.EventID, ""); err != nil {
			t.Fatal(err)
		}
	}

	i1 := testAppendInput()
	i1.CorrelationID = uniqueID("corr-" + tag + "-1")
	i1.IdempotencyKey = uniqueID("idem-" + tag + "-1")
	i1.RequestBytes = sharedRequest
	i1.ResponseBytes = sharedResponse
	i1.OccurredAt = "2000-01-01T00:00:00Z"
	i1.Retention.RetentionDays = 3650
	r1, err := store.Append(i1)
	if err != nil {
		t.Fatal(err)
	}
	mirror(r1)

	i2 := testAppendInput()
	i2.CorrelationID = uniqueID("corr-" + tag + "-2")
	i2.IdempotencyKey = uniqueID("idem-" + tag + "-2")
	i2.RequestBytes = sharedRequest
	i2.ResponseBytes = sharedResponse
	i2.OccurredAt = "2000-01-01T00:00:00Z"
	i2.Retention.RetentionDays = 3650
	r2, err := store.Append(i2)
	if err != nil {
		t.Fatal(err)
	}
	mirror(r2)

	sha := r1.Event.RequestSnapshotSHA256

	purged, err := store.PurgeExpired(ctx, time.Now(), "legit-operator", "legit-reason", sink)
	if err != nil {
		t.Fatalf("legitimate PurgeExpired: %v", err)
	}
	if purged != 2 {
		t.Fatalf("expected 2 snapshots purged, got %d", purged)
	}
	report, err := store.VerifyPolicy(ctx, VerifyOptions{Policy: policy, Purges: sink, allowDeferredPurgeClaims: true})
	if err != nil {
		t.Fatalf("VerifyPolicy: %v", err)
	}
	if err := anchorSink.WriteAnchor(ctx, kAnchor, store.ledgerID, int64(report.Head.Sequence), report.Head.EventSHA256, report.AuditHead.EventSHA256, int64(report.AuditHead.Sequence), policySHA256); err != nil {
		t.Fatalf("WriteAnchor: %v", err)
	}
	pre, err := store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: policy, Purges: sink},
		Anchors:       sink, Provisioning: sink, KAnchor: kAnchor, PolicySHA256: policySHA256,
	})
	if err != nil || pre.AnchorStatus != AnchorStatusVerified {
		t.Fatalf("test construction error: expected the pre-crash state to verify clean, got status=%v err=%v", pre.AnchorStatus, err)
	}

	return d109Fixture{
		store: store, sink: sink, anchorSink: anchorSink, kAnchor: kAnchor,
		policy: policy, policySHA256: policySHA256, sha: sha,
		sharedRequest: sharedRequest, sharedResponse: sharedResponse,
	}
}

func (f d109Fixture) verifyOpts() AnchorOptions {
	return AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: f.policy, Purges: f.sink},
		Anchors:       f.sink, Provisioning: f.sink, KAnchor: f.kAnchor, PolicySHA256: f.policySHA256,
	}
}

// appendCrashWindowEvent appends a THIRD event referencing the SAME
// shared sha, locally only -- file written, never mirrored -- the
// crash window between Store.Append and sink.Persist.
func (f d109Fixture) appendCrashWindowEvent(t *testing.T, tag string) AppendResult {
	t.Helper()
	input := testAppendInput()
	input.CorrelationID = uniqueID("corr-" + tag)
	input.IdempotencyKey = uniqueID("idem-" + tag)
	input.RequestBytes = f.sharedRequest
	input.ResponseBytes = f.sharedResponse
	input.OccurredAt = "2000-01-01T00:00:00Z"
	input.Retention.RetentionDays = 3650
	result, err := f.store.Append(input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Event.RequestSnapshotSHA256 != f.sha {
		t.Fatalf("test construction error: expected the crash-window event to reference the shared sha %s, got %s", f.sha, result.Event.RequestSnapshotSHA256)
	}
	return result
}

// TestSyncRepairsThePartialMirrorItWouldOtherwiseRefuse is D112 item 6:
// the crash-window state (event appended to the chain, not yet
// mirrored) makes VerifyAnchored fail with the named count divergence,
// matching P-D's own transcript, and Store.Sync mirrors the missing
// event and the POST-MIRROR verification passes, reporting what it
// deferred.
func TestSyncRepairsThePartialMirrorItWouldOtherwiseRefuse(t *testing.T) {
	ctx := context.Background()
	f := newD109Fixture(t, ctx, "repair")

	crash := f.appendCrashWindowEvent(t, "repair-crash")
	if f.store.IsReplicated(crash.Event.EventID) {
		t.Fatal("test construction error: expected the crash-window event to be unreplicated")
	}

	// Today (without D109's own repair path applied via Store.Sync's
	// mirroring), VerifyAnchored alone fails with the named divergence
	// -- P-D's own transcript.
	_, err := f.store.VerifyAnchored(ctx, f.verifyOpts())
	if err == nil {
		t.Fatal("test construction error: expected the crash-window state to fail plain VerifyAnchored")
	}
	var divergence *MirrorChainCountDivergence
	if !errors.As(err, &divergence) {
		t.Fatalf("expected a *MirrorChainCountDivergence, got: %v", err)
	}

	result, err := f.store.Sync(ctx, f.sink, f.verifyOpts(), "test-operator")
	if err != nil {
		t.Fatalf("ADR-0007 Addendum 12 D109: expected Store.Sync to repair the crash window and verify clean, got err=%v", err)
	}
	if result.VerifyResult.AnchorStatus != AnchorStatusVerified {
		t.Fatalf("expected AnchorStatusVerified after Sync's repair, got %v", result.VerifyResult.AnchorStatus)
	}
	if result.DeferredReason == "" {
		t.Fatal("ADR-0007 Addendum 12 D109: expected Sync to REPORT the deferral, got an empty DeferredReason")
	}
	if result.SyncedEventCount != 1 {
		t.Fatalf("expected exactly 1 event mirrored (the crash-window one), got %d", result.SyncedEventCount)
	}
	if !f.store.IsReplicated(crash.Event.EventID) {
		t.Fatal("expected the crash-window event to be marked replicated after Sync")
	}
}

// TestSyncDeferralReportingDistinguishesFromCleanRun is D112 item 6's
// reporting assertion: a deferred run's DeferredReason is populated; an
// ordinary clean run's is empty. "I mirrored past a divergence I chose
// to defer" and "I verified clean" must not share an output (D12's
// rule).
func TestSyncDeferralReportingDistinguishesFromCleanRun(t *testing.T) {
	ctx := context.Background()
	f := newD109Fixture(t, ctx, "reporting")

	clean, err := f.store.Sync(ctx, f.sink, f.verifyOpts(), "test-operator")
	if err != nil {
		t.Fatalf("Sync on an already-clean ledger: %v", err)
	}
	if clean.DeferredReason != "" {
		t.Fatalf("expected an ordinary clean run to report NO deferral, got %q", clean.DeferredReason)
	}

	crash := f.appendCrashWindowEvent(t, "reporting-crash")
	_ = crash
	deferred, err := f.store.Sync(ctx, f.sink, f.verifyOpts(), "test-operator")
	if err != nil {
		t.Fatalf("Sync repairing the crash window: %v", err)
	}
	if deferred.DeferredReason == "" {
		t.Fatal("expected the repaired run to report ITS deferral")
	}
}

// TestSyncDoesNotDeferAMirrorRowTheChainDoesNotHave is D112 item 6's
// first required negative: a mirror row the chain does not have (the
// mirror is AHEAD, not behind) must still abort -- ShortfallExplainedBy
// UnreplicatedEvents only ever applies to a shortfall.
func TestSyncDoesNotDeferAMirrorRowTheChainDoesNotHave(t *testing.T) {
	ctx := context.Background()
	f := newD109Fixture(t, ctx, "ahead")

	// Directly INSERT a mirror row for a THIRD event the local chain
	// has never heard of, referencing the same shared sha -- the mirror
	// is now ahead of the chain for this snapshot.
	if _, err := f.sink.conn.Exec(ctx,
		`INSERT INTO screening_ledger_event(event_id,ledger_id,sequence,event_sha256,previous_event_sha256,occurred_at,route,http_status,request_sha256,response_sha256,request_snapshot_sha256,response_snapshot_sha256,retention_class,expires_at,event_json)
		 VALUES ($1,$2,99,$3,'',now(),'/screen',200,'req-sha','resp-sha',$4,$4,'screening-standard',now(),'{}'::jsonb)`,
		uniqueID("phantom-mirror-event"), f.store.ledgerID, uniqueID("phantom-event-sha"), f.sha,
	); err != nil {
		t.Fatal(err)
	}

	result, err := f.store.Sync(ctx, f.sink, f.verifyOpts(), "test-operator")
	if err == nil {
		t.Fatal("ADR-0007 Addendum 12 D109: expected Sync to ABORT when the mirror is ahead of the chain, not defer past it")
	}
	if result.DeferredReason != "" {
		t.Fatalf("expected no deferral for a mirror-ahead-of-chain divergence, got %q", result.DeferredReason)
	}
}

// TestSyncDoesNotDeferAMaxDisagreementOnAMirroredRow is D112 item 6's
// second required negative: a max disagreement on a row that IS
// mirrored (D97(c)'s own direction) must still abort -- the max-mismatch
// branch of forSnapshot stays a plain, untyped error, never the
// MirrorChainCountDivergence type Sync's discriminator checks for.
func TestSyncDoesNotDeferAMaxDisagreementOnAMirroredRow(t *testing.T) {
	ctx := context.Background()
	f := newD109Fixture(t, ctx, "maxdiverge")

	crash := f.appendCrashWindowEvent(t, "maxdiverge-crash")
	// Mirror it, but with a WRONG expires_at -- same row count, wrong
	// max.
	wrongExpires := time.Now().Add(999999 * time.Hour)
	if _, err := f.sink.conn.Exec(ctx,
		`INSERT INTO screening_ledger_event(event_id,ledger_id,sequence,event_sha256,previous_event_sha256,occurred_at,route,http_status,request_sha256,response_sha256,request_snapshot_sha256,response_snapshot_sha256,retention_class,expires_at,event_json)
		 VALUES ($1,$2,$3,$4,$5,$6::timestamptz,$7,$8,$9,$10,$11,$12,$13,$14,'{}'::jsonb)`,
		crash.Event.EventID, crash.Event.LedgerID, int64(crash.Event.Sequence), crash.Event.EventSHA256, crash.Event.PreviousEventSHA256,
		crash.Event.OccurredAt, crash.Event.Route, crash.Event.HTTPStatus, crash.Event.RequestSHA256, crash.Event.ResponseSHA256,
		crash.Event.RequestSnapshotSHA256, crash.Event.ResponseSnapshotSHA256, crash.Event.RetentionClass, wrongExpires,
	); err != nil {
		t.Fatal(err)
	}
	if err := f.store.MarkReplicated(crash.Event.EventID, ""); err != nil {
		t.Fatal(err)
	}

	result, err := f.store.Sync(ctx, f.sink, f.verifyOpts(), "test-operator")
	if err == nil {
		t.Fatal("ADR-0007 Addendum 12 D109: expected Sync to ABORT on a max-only disagreement on an already-mirrored row")
	}
	if result.DeferredReason != "" {
		t.Fatalf("expected no deferral for a max-mismatch divergence, got %q", result.DeferredReason)
	}
	var divergence *MirrorChainCountDivergence
	if errors.As(err, &divergence) {
		t.Fatalf("expected a max-mismatch error, NOT a *MirrorChainCountDivergence: %v", err)
	}
}

// TestSyncDoesNotDeferAShortfallCoveringAReplicatedEvent is D112 item
// 6's third required negative: a shortfall covering an event
// MarkReplicated already recorded as replicated is a genuinely
// different anomaly (the mirror row for a REPLICATED event went
// missing) and must still abort.
func TestSyncDoesNotDeferAShortfallCoveringAReplicatedEvent(t *testing.T) {
	ctx := context.Background()
	f := newD109Fixture(t, ctx, "phantomreplicated")

	crash := f.appendCrashWindowEvent(t, "phantomreplicated-crash")
	// Mark it replicated WITHOUT actually mirroring it -- store.
	// IsReplicated will report true for an event the mirror does not
	// have, which is exactly the "genuinely wrong" shape D109 excludes.
	if err := f.store.MarkReplicated(crash.Event.EventID, ""); err != nil {
		t.Fatal(err)
	}

	result, err := f.store.Sync(ctx, f.sink, f.verifyOpts(), "test-operator")
	if err == nil {
		t.Fatal("ADR-0007 Addendum 12 D109: expected Sync to ABORT when the shortfall covers an event already marked replicated")
	}
	if result.DeferredReason != "" {
		t.Fatalf("expected no deferral when IsReplicated disagrees with the mirror, got %q", result.DeferredReason)
	}
}

// TestStatusAndVerifyNeverDefer confirms status/verify -- unlike sync --
// call plain VerifyAnchored directly and never see Store.Sync's
// deferral at all, matching D109's own scope statement.
func TestStatusAndVerifyNeverDefer(t *testing.T) {
	ctx := context.Background()
	f := newD109Fixture(t, ctx, "statusverify")

	crash := f.appendCrashWindowEvent(t, "statusverify-crash")
	_ = crash

	_, err := f.store.VerifyAnchored(ctx, f.verifyOpts())
	if err == nil {
		t.Fatal("expected plain VerifyAnchored (what status/verify call) to fail on the crash-window state, with no deferral available to it")
	}
	var divergence *MirrorChainCountDivergence
	if !errors.As(err, &divergence) {
		t.Fatalf("expected a *MirrorChainCountDivergence, got: %v", err)
	}
}
