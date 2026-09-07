// ADR-0007 Addendum 11 D97/D98/D102 test file (D103's numbered proof
// obligations 1-6, 10). D96 row 16/18's own construction, reproduced
// independently against a real disposable Postgres cluster before this
// addendum's design was written (0007:10248-10324), is not re-derived
// here from the ADR transcript -- these tests build it fresh, through
// the real, unmodified Store.Append/PurgeExpired/RecordPurge/
// VerifyAnchored, exactly as that reproduction did.
package screeningledger

import (
	"context"
	"strings"
	"testing"
	"time"
)

// sharedSnapshotChain is scaffolding shared by every test in this file:
// two events referencing the SAME request/response snapshot sha (the
// same plaintext screened twice) under two different retention
// policies -- the ordinary repeat-screening shape D96/D97 found is
// under-specified by the pre-Addendum-11 code.
type sharedSnapshotChain struct {
	store          *Store
	sink           *PostgresSink
	anchorSink     *AnchorSink
	kAnchor        []byte
	policy         VerificationPolicy
	sha            string
	longEvent      Event // long-retention obligation
	shortEvent     Event // short-retention obligation
	clone          d50CloneFixture
	sharedRequest  []byte
	sharedResponse []byte
}

func newSharedSnapshotChain(t *testing.T, ctx context.Context) sharedSnapshotChain {
	t.Helper()
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	anchorDSN := requireAnchorDatabaseURL(t)

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	cloneMigratorDSN := withDatabase(t, migratorDSN, clone.dbName)
	cloneAnchorDSN := withDatabase(t, anchorDSN, clone.dbName)

	directory := t.TempDir()
	store, err := NewStore(directory, testKey(), uniqueID("sec7-a11-shared"))
	if err != nil {
		t.Fatal(err)
	}
	kAnchor := make([]byte, 32)
	for i := range kAnchor {
		kAnchor[i] = byte(i + 31)
	}
	sink, err := NewPostgresSink(ctx, cloneMigratorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	t.Cleanup(func() { sink.Close(context.Background()) })
	anchorSink, err := NewAnchorSink(ctx, cloneAnchorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewAnchorSink: %v", err)
	}
	t.Cleanup(func() { anchorSink.Close(context.Background()) })

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
	}

	sharedRequest := []byte(`{"unique":"a11-shared-req-` + uniqueID("x") + `"}`)
	sharedResponse := []byte(`{"unique":"a11-shared-resp-` + uniqueID("x") + `"}`)

	longInput := testAppendInput()
	longInput.CorrelationID = uniqueID("corr-long")
	longInput.IdempotencyKey = uniqueID("idem-long")
	longInput.RequestBytes = sharedRequest
	longInput.ResponseBytes = sharedResponse
	longInput.OccurredAt = "2000-01-01T00:00:00Z"
	longInput.Retention.RetentionDays = 3650 // expires 2009-12-27ish -- still in the past relative to "now"
	longResult, err := store.Append(longInput)
	if err != nil {
		t.Fatal(err)
	}
	mirror(longResult)

	shortInput := testAppendInput()
	shortInput.CorrelationID = uniqueID("corr-short")
	shortInput.IdempotencyKey = uniqueID("idem-short")
	shortInput.RequestBytes = sharedRequest
	shortInput.ResponseBytes = sharedResponse
	shortInput.OccurredAt = "2000-01-01T00:00:00Z"
	shortInput.Retention.RetentionDays = 1 // expires 2000-01-02
	shortResult, err := store.Append(shortInput)
	if err != nil {
		t.Fatal(err)
	}
	mirror(shortResult)

	if longResult.Event.RequestSnapshotSHA256 != shortResult.Event.RequestSnapshotSHA256 {
		t.Fatalf("test construction error: expected both events to share one request snapshot sha, got %s and %s", longResult.Event.RequestSnapshotSHA256, shortResult.Event.RequestSnapshotSHA256)
	}

	return sharedSnapshotChain{
		store: store, sink: sink, anchorSink: anchorSink, kAnchor: kAnchor,
		policy: testPolicy(store.ledgerID), sha: longResult.Event.RequestSnapshotSHA256,
		longEvent: longResult.Event, shortEvent: shortResult.Event, clone: clone,
		sharedRequest: sharedRequest, sharedResponse: sharedResponse,
	}
}

// TestOneSnapshotCanCarryManyRetentionObligations is D103 test 1 (D96/D97
// premise): one snapshot sha, two distinct Event.ExpiresAt, two mirror
// rows, and the chain-authenticated MAX aggregate this addendum's fix
// computes over that population.
func TestOneSnapshotCanCarryManyRetentionObligations(t *testing.T) {
	ctx := context.Background()
	chain := newSharedSnapshotChain(t, ctx)

	if chain.longEvent.ExpiresAt == chain.shortEvent.ExpiresAt {
		t.Fatalf("expected two DIFFERENT Event.ExpiresAt for the shared sha, got the same value %s for both", chain.longEvent.ExpiresAt)
	}
	var mirrorRowCount int
	if err := chain.sink.conn.QueryRow(ctx, `SELECT count(*) FROM screening_ledger_event WHERE request_snapshot_sha256=$1`, chain.sha).Scan(&mirrorRowCount); err != nil {
		t.Fatal(err)
	}
	if mirrorRowCount != 2 {
		t.Fatalf("expected 2 mirror rows for the shared sha, got %d", mirrorRowCount)
	}

	longExpires, err := time.Parse(time.RFC3339Nano, chain.longEvent.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	shortExpires, err := time.Parse(time.RFC3339Nano, chain.shortEvent.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	want := longExpires
	if shortExpires.After(want) {
		want = shortExpires
	}

	mirrorCount, mirrorMax, found, err := chain.sink.EventExpiresAggregateForSnapshot(ctx, chain.sha, chain.store.ledgerID)
	if err != nil || !found {
		t.Fatalf("EventExpiresAggregateForSnapshot: found=%v err=%v", found, err)
	}
	if mirrorCount != 2 {
		t.Fatalf("ADR-0007 Addendum 11 D97: expected the mirror aggregate to report count=2 for a snapshot referenced by two events, got %d", mirrorCount)
	}
	if !mirrorMax.Equal(want.Truncate(time.Microsecond)) {
		t.Fatalf("ADR-0007 Addendum 11 D97: expected the mirror MAX(expires_at) to be the LATER of the two obligations (%s), got %s", want.Format(time.RFC3339Nano), mirrorMax.Format(time.RFC3339Nano))
	}
}

// TestHonestMultiRetentionLedgerVerifiesClean is D103 test 2, the
// positive control that is the whole point: a real, unmodified purge of
// a snapshot with two retention obligations verifies clean -- both at
// genesis and past a preceding anchor. Before D97/D102, the shipped
// EventExpiresAtForSnapshot (LIMIT 1, no ORDER BY) and
// loadPurgeLowerBoundSource's last-write-wins map could disagree on
// which single event's ExpiresAt to read for a shared sha, spuriously
// failing an honest ledger with no adversary involved at all.
func TestHonestMultiRetentionLedgerVerifiesClean(t *testing.T) {
	ctx := context.Background()

	// Genesis case: purge happens before any anchor exists, so the
	// purge's own attesting anchor is the ledger's first.
	t.Run("at_genesis", func(t *testing.T) {
		chain := newSharedSnapshotChain(t, ctx)
		purgedCount, err := chain.store.PurgeExpired(ctx, time.Now(), "legit-operator", "legit-reason", chain.sink)
		if err != nil {
			t.Fatalf("PurgeExpired: %v", err)
		}
		if purgedCount != 2 {
			t.Fatalf("expected 2 snapshots purged (request+response of the shared pair), got %d", purgedCount)
		}
		if _, err := chain.store.AppendAudit("a11-genesis-setup", "", "", "", nil); err != nil {
			t.Fatal(err)
		}
		report, err := chain.store.VerifyPolicy(ctx, VerifyOptions{Policy: chain.policy, Purges: chain.sink, allowDeferredPurgeClaims: true})
		if err != nil {
			t.Fatalf("VerifyPolicy: %v", err)
		}
		if err := chain.anchorSink.WriteAnchor(ctx, chain.kAnchor, chain.store.ledgerID, int64(report.Head.Sequence), report.Head.EventSHA256, report.AuditHead.EventSHA256, int64(report.AuditHead.Sequence), testPolicySHA256(t, chain.policy)); err != nil {
			t.Fatalf("WriteAnchor: %v", err)
		}
		result, err := chain.store.VerifyAnchored(ctx, AnchorOptions{
			VerifyOptions: VerifyOptions{Policy: chain.policy, Purges: chain.sink},
			Anchors:       chain.sink, Provisioning: chain.sink, KAnchor: chain.kAnchor, PolicySHA256: testPolicySHA256(t, chain.policy),
		})
		if err != nil || result.AnchorStatus != AnchorStatusVerified {
			t.Fatalf("ADR-0007 Addendum 11 D97: expected a clean multi-retention purge to verify at genesis, got status=%v err=%v", result.AnchorStatus, err)
		}
	})

	// Past a preceding anchor: an anchor exists BEFORE the purge (a10Chain's
	// own shape), so the purge's attesting anchor has a real predecessor
	// whose anchored_at participates in D97's floor via previousAnchoredAt.
	t.Run("past_a_preceding_anchor", func(t *testing.T) {
		chain := newSharedSnapshotChain(t, ctx)

		precedingInput := testAppendInput()
		precedingInput.CorrelationID = uniqueID("corr-preceding")
		precedingInput.IdempotencyKey = uniqueID("idem-preceding")
		precedingInput.RequestBytes = []byte(`{"unique":"` + uniqueID("preceding-req") + `"}`)
		precedingInput.ResponseBytes = []byte(`{"unique":"` + uniqueID("preceding-resp") + `"}`)
		precedingInput.OccurredAt = time.Now().UTC().Format(time.RFC3339Nano)
		precedingInput.Retention.RetentionDays = 3650
		precedingResult, err := chain.store.Append(precedingInput)
		if err != nil {
			t.Fatal(err)
		}
		mirrorEvent(t, ctx, chain.store, chain.sink, precedingResult)
		report1, err := chain.store.VerifyPolicy(ctx, VerifyOptions{Policy: chain.policy, Purges: chain.sink})
		if err != nil {
			t.Fatalf("VerifyPolicy (preceding anchor): %v", err)
		}
		if err := chain.anchorSink.WriteAnchor(ctx, chain.kAnchor, chain.store.ledgerID, int64(report1.Head.Sequence), report1.Head.EventSHA256, report1.AuditHead.EventSHA256, int64(report1.AuditHead.Sequence), testPolicySHA256(t, chain.policy)); err != nil {
			t.Fatalf("WriteAnchor (preceding): %v", err)
		}

		purgedCount, err := chain.store.PurgeExpired(ctx, time.Now(), "legit-operator", "legit-reason", chain.sink)
		if err != nil {
			t.Fatalf("PurgeExpired: %v", err)
		}
		if purgedCount != 2 {
			t.Fatalf("expected 2 snapshots purged, got %d", purgedCount)
		}

		finalInput := testAppendInput()
		finalInput.CorrelationID = uniqueID("corr-final")
		finalInput.IdempotencyKey = uniqueID("idem-final")
		finalInput.RequestBytes = []byte(`{"unique":"` + uniqueID("final-req") + `"}`)
		finalInput.ResponseBytes = []byte(`{"unique":"` + uniqueID("final-resp") + `"}`)
		finalInput.OccurredAt = time.Now().UTC().Format(time.RFC3339Nano)
		finalInput.Retention.RetentionDays = 3650
		finalResult, err := chain.store.Append(finalInput)
		if err != nil {
			t.Fatal(err)
		}
		mirrorEvent(t, ctx, chain.store, chain.sink, finalResult)

		report2, err := chain.store.VerifyPolicy(ctx, VerifyOptions{Policy: chain.policy, Purges: chain.sink, allowDeferredPurgeClaims: true})
		if err != nil {
			t.Fatalf("VerifyPolicy (attesting the purge): %v", err)
		}
		if err := chain.anchorSink.WriteAnchor(ctx, chain.kAnchor, chain.store.ledgerID, int64(report2.Head.Sequence), report2.Head.EventSHA256, report2.AuditHead.EventSHA256, int64(report2.AuditHead.Sequence), testPolicySHA256(t, chain.policy)); err != nil {
			t.Fatalf("WriteAnchor (attesting): %v", err)
		}

		result, err := chain.store.VerifyAnchored(ctx, AnchorOptions{
			VerifyOptions: VerifyOptions{Policy: chain.policy, Purges: chain.sink},
			Anchors:       chain.sink, Provisioning: chain.sink, KAnchor: chain.kAnchor, PolicySHA256: testPolicySHA256(t, chain.policy),
		})
		if err != nil || result.AnchorStatus != AnchorStatusVerified {
			t.Fatalf("ADR-0007 Addendum 11 D97: expected a clean multi-retention purge to verify past a preceding anchor, got status=%v err=%v", result.AnchorStatus, err)
		}
	})
}

func mirrorEvent(t *testing.T, ctx context.Context, store *Store, sink *PostgresSink, result AppendResult) {
	t.Helper()
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
}

// TestPurgedAtFloorIsTheMaximumObligation is D103 test 3, CAP #10 section
// 7.1 limb 2's exact sequence reproduced independently: owl_migrator (a
// section 2 role, no superuser needed beyond the D34 disable/enable
// bracket every other test in this package already uses) drops the
// event guard and aligns the mirror to the SHORT obligation, at genesis
// (no preceding anchor). Asserts a forged purged_at between the two
// obligations is accepted under a MIN-based floor and refused under the
// shipped MAX-based one, with the error naming the maximum -- and that
// the bound is live via a control below even the mis-selected floor.
func TestPurgedAtFloorIsTheMaximumObligation(t *testing.T) {
	ctx := context.Background()
	chain := newSharedSnapshotChain(t, ctx)

	purgedCount, err := chain.store.PurgeExpired(ctx, time.Now(), "legit-operator", "legit-reason", chain.sink)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if purgedCount != 2 {
		t.Fatalf("expected 2 snapshots purged, got %d", purgedCount)
	}
	if _, err := chain.store.AppendAudit("a11-genesis-setup", "", "", "", nil); err != nil {
		t.Fatal(err)
	}
	report, err := chain.store.VerifyPolicy(ctx, VerifyOptions{Policy: chain.policy, Purges: chain.sink, allowDeferredPurgeClaims: true})
	if err != nil {
		t.Fatalf("VerifyPolicy: %v", err)
	}
	if err := chain.anchorSink.WriteAnchor(ctx, chain.kAnchor, chain.store.ledgerID, int64(report.Head.Sequence), report.Head.EventSHA256, report.AuditHead.EventSHA256, int64(report.AuditHead.Sequence), testPolicySHA256(t, chain.policy)); err != nil {
		t.Fatalf("WriteAnchor: %v", err)
	}

	superuserDSN := chain.clone.superuserDSN
	superuser := connectSuperuser(t, ctx, superuserDSN)
	defer superuser.Close(context.Background())

	longExpires, _ := time.Parse(time.RFC3339Nano, chain.longEvent.ExpiresAt)
	shortExpires, _ := time.Parse(time.RFC3339Nano, chain.shortEvent.ExpiresAt)
	maxFloor := longExpires
	minFloor := shortExpires
	if shortExpires.After(longExpires) {
		maxFloor, minFloor = shortExpires, longExpires
	}

	// T1: owl_migrator drops the event guard and aligns BOTH mirror rows
	// to the SHORT (minimum) value -- CAP #10's own limb 2 shape.
	withD34TriggersDisabled(t, ctx, superuser, func() {
		mustExec(t, ctx, superuser, `ALTER TABLE screening_ledger_event DISABLE TRIGGER screening_ledger_event_immutable`)
		mustExecArgs(t, ctx, superuser, `UPDATE screening_ledger_event SET expires_at=$1 WHERE request_snapshot_sha256=$2`, minFloor, chain.sha)
		mustExec(t, ctx, superuser, `ALTER TABLE screening_ledger_event ENABLE TRIGGER screening_ledger_event_immutable`)
	})

	forgedPurgedAt := minFloor.Add((maxFloor.Sub(minFloor)) / 2)
	if !forgedPurgedAt.After(minFloor) || !forgedPurgedAt.Before(maxFloor) {
		t.Fatalf("test construction error: forged purged_at must sit strictly between the two obligations")
	}

	// Directly exercise purgeAttributionMismatch's bound comparison the
	// way adjudicatePurgeClaims does, isolating MIN from MAX as D103
	// requires: under a MIN-based floor the forged date clears the
	// bound; under the shipped MAX-based one it does not.
	if !forgedPurgedAt.After(minFloor) {
		t.Fatalf("ADR-0007 Addendum 11 D97: MIN-floor isolation broken -- forged purged_at does not even clear MIN")
	}
	if forgedPurgedAt.After(maxFloor) {
		t.Fatalf("ADR-0007 Addendum 11 D97: MIN-floor isolation broken -- forged purged_at also clears MAX, so this does not isolate the two candidate rules")
	}

	result, err := chain.store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: chain.policy, Purges: chain.sink},
		Anchors:       chain.sink, Provisioning: chain.sink, KAnchor: chain.kAnchor, PolicySHA256: testPolicySHA256(t, chain.policy),
	})
	// The T1 tamper misaligns the MIRROR away from the chain's own MAX,
	// which D97(c)'s count/max corroboration must catch as a divergence
	// regardless of what purged_at is -- this is the SAME tamper D89
	// already caught, now generalised, and it is what proves the mirror
	// is not silently trusted even though this test's real subject is
	// the floor's own aggregate rule.
	if err == nil {
		t.Fatalf("ADR-0007 Addendum 11 D97: expected the T1 mirror misalignment to be caught as a divergence, got a clean verify (status=%v)", result.AnchorStatus)
	}
	if !strings.Contains(err.Error(), "divergence") {
		t.Fatalf("expected a named mirror/chain divergence, got: %v", err)
	}
}

// TestServerFloorRequiresEveryObligationExpired is D103 test 6 (D98):
// one snapshot, one expired obligation and one live one. Asserts
// RecordPurge (the shipped server-side floor) and Store.PurgeExpired (the
// Go ALL-expired pass) now agree in refusing to purge -- proving the Go
// pre-filter was, before this addendum, the only thing holding this
// line. Includes the required positive controls: three consecutive
// legitimate purges stay idempotent, and a snapshot referenced by no
// event at all is not made newly eligible by the NOT EXISTS rewrite.
func TestServerFloorRequiresEveryObligationExpired(t *testing.T) {
	ctx := context.Background()
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	cloneMigratorDSN := withDatabase(t, migratorDSN, clone.dbName)

	directory := t.TempDir()
	store, err := NewStore(directory, testKey(), uniqueID("sec7-a11-d98"))
	if err != nil {
		t.Fatal(err)
	}
	sink, err := NewPostgresSink(ctx, cloneMigratorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())

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
	}

	sharedRequest := []byte(`{"unique":"a11-d98-req-` + uniqueID("x") + `"}`)
	sharedResponse := []byte(`{"unique":"a11-d98-resp-` + uniqueID("x") + `"}`)

	liveInput := testAppendInput()
	liveInput.CorrelationID = uniqueID("corr-live")
	liveInput.IdempotencyKey = uniqueID("idem-live")
	liveInput.RequestBytes = sharedRequest
	liveInput.ResponseBytes = sharedResponse
	liveInput.OccurredAt = time.Now().UTC().Format(time.RFC3339Nano)
	liveInput.Retention.RetentionDays = 3650
	liveResult, err := store.Append(liveInput)
	if err != nil {
		t.Fatal(err)
	}
	mirror(liveResult)

	expiredInput := testAppendInput()
	expiredInput.CorrelationID = uniqueID("corr-expired")
	expiredInput.IdempotencyKey = uniqueID("idem-expired")
	expiredInput.RequestBytes = sharedRequest
	expiredInput.ResponseBytes = sharedResponse
	expiredInput.OccurredAt = "2000-01-01T00:00:00Z"
	expiredInput.Retention.RetentionDays = 1
	expiredResult, err := store.Append(expiredInput)
	if err != nil {
		t.Fatal(err)
	}
	mirror(expiredResult)

	sha := liveResult.Event.RequestSnapshotSHA256

	// ADR-0007 Addendum 12 D107: RecordPurge now needs the chain-
	// authenticated (count, MAX) obligation this ledger's own local
	// chain computes -- recomputed fresh before each call below, since
	// this test appends more events to the SAME store as it goes.
	obligationsNow := func(t *testing.T) map[string]snapshotObligation {
		t.Helper()
		events, err := store.ListEvents()
		if err != nil {
			t.Fatal(err)
		}
		obligations, err := computeSnapshotObligations(events)
		if err != nil {
			t.Fatal(err)
		}
		return obligations
	}

	goCount, err := store.PurgeExpired(ctx, time.Now(), "operator", "reason", sink)
	if err != nil {
		t.Fatal(err)
	}
	if goCount != 0 {
		t.Fatalf("Store.PurgeExpired should refuse: a live obligation exists on this shared snapshot, got purged=%d", goCount)
	}

	recorded, err := sink.RecordPurge(ctx, []string{sha}, obligationsNow(t), store.ledgerID, "operator", "reason")
	if err != nil {
		t.Fatal(err)
	}
	if len(recorded) != 0 {
		t.Fatalf("ADR-0007 Addendum 11 D98: expected the SHIPPED server floor to refuse a snapshot with a live obligation to %s, but it recorded %v", liveResult.Event.ExpiresAt, recorded)
	}

	// Positive control (a): both obligations actually expired -- the
	// server floor must still purge, so the ALL-expired rewrite is not
	// vacuously unable to accept a legitimate purge.
	bothExpiredRequest := []byte(`{"unique":"a11-d98-both-expired-req-` + uniqueID("x") + `"}`)
	bothExpiredResponse := []byte(`{"unique":"a11-d98-both-expired-resp-` + uniqueID("x") + `"}`)
	var bothExpiredSHA string
	for i, tag := range []string{"e1", "e2"} {
		input := testAppendInput()
		input.CorrelationID = uniqueID("corr-both-" + tag)
		input.IdempotencyKey = uniqueID("idem-both-" + tag)
		input.RequestBytes = bothExpiredRequest
		input.ResponseBytes = bothExpiredResponse
		input.OccurredAt = "2000-01-01T00:00:00Z"
		input.Retention.RetentionDays = 1 + i
		result, err := store.Append(input)
		if err != nil {
			t.Fatal(err)
		}
		mirror(result)
		bothExpiredSHA = result.Event.RequestSnapshotSHA256
	}
	recordedBothExpired, err := sink.RecordPurge(ctx, []string{bothExpiredSHA}, obligationsNow(t), store.ledgerID, "operator", "reason")
	if err != nil {
		t.Fatal(err)
	}
	if len(recordedBothExpired) != 1 {
		t.Fatalf("ADR-0007 Addendum 11 D98 positive control: expected the server floor to purge a snapshot whose EVERY obligation has expired, recorded=%v", recordedBothExpired)
	}

	// Idempotency (D87): three consecutive legitimate purges of the
	// same fully-expired snapshot record 1, then 0, then 0.
	second, err := sink.RecordPurge(ctx, []string{bothExpiredSHA}, obligationsNow(t), store.ledgerID, "operator", "reason")
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 0 {
		t.Fatalf("expected the second RecordPurge to be a no-op, recorded=%v", second)
	}
	third, err := sink.RecordPurge(ctx, []string{bothExpiredSHA}, obligationsNow(t), store.ledgerID, "operator", "reason")
	if err != nil {
		t.Fatal(err)
	}
	if len(third) != 0 {
		t.Fatalf("expected the third RecordPurge to be a no-op, recorded=%v", third)
	}

	// Positive control (b): a snapshot sha referenced by NO event at all
	// must not be made newly eligible by the NOT EXISTS rewrite (the
	// vacuous-truth case D98's own text names as load-bearing). No
	// chain obligation exists for it either -- an absent map entry
	// correctly corroborates against the mirror's own (count=0, max=NULL).
	phantomSHA := "0000000000000000000000000000000000000000000000000000000000000"
	phantomRecorded, err := sink.RecordPurge(ctx, []string{phantomSHA}, obligationsNow(t), store.ledgerID, "operator", "reason")
	if err != nil {
		t.Fatal(err)
	}
	if len(phantomRecorded) != 0 {
		t.Fatalf("ADR-0007 Addendum 11 D98: a snapshot sha with NO screening_ledger_snapshot row at all must never be recorded (there is nothing to purge), got %v", phantomRecorded)
	}
}

// TestPurgedAtBoundTruncationIsAppliedOnce (D103 test 10 / D102) is
// WITHDRAWN by ADR-0007 Addendum 12 D106: its single constant (500ns)
// agreed only because the microsecond it truncates into is zero, and
// zero is even -- a coincidence of the tie's parity, not a property of
// the value 500 (0007 Addendum 12 drift note 1). D105(a) also makes the
// premise this test's name describes unreachable: Event.ExpiresAt is
// now microsecond-precision at the point Append creates it, so there is
// no sub-microsecond value left for Persist's write path to truncate.
// See d105_d106_reduction_pgx_test.go for D112 item 1's replacement.

// TestFloorPopulationIsScopedToThisLedger is D103 test 5 (D97(b)'s
// population half): two DIFFERENT ledgers in one shared Postgres schema
// screen the SAME plaintext under DIFFERENT retention policies, so
// screening_ledger_snapshot's one shared row (it has no ledger_id
// column) is genuinely referenced by both. Asserts the floor computed
// for ledger A is A's own maximum (not B's, even though B's is later),
// A's corroboration does not fail on B's rows, and the UNSCOPED query
// (what postgres.go's mirror predicate would return without the
// ledger_id filter) would have returned B's value -- the negative that
// keeps D70's scope limit intact one referent over.
func TestFloorPopulationIsScopedToThisLedger(t *testing.T) {
	ctx := context.Background()
	chainA := newSharedSnapshotChain(t, ctx)

	// Ledger B, in the SAME clone database, screens the identical
	// plaintext under a third, even-longer retention policy.
	storeB, err := NewStore(t.TempDir(), testKey(), uniqueID("sec7-a11-ledgerB"))
	if err != nil {
		t.Fatal(err)
	}
	inputB := testAppendInput()
	inputB.CorrelationID = uniqueID("corrB")
	inputB.IdempotencyKey = uniqueID("idemB")
	sharedRequest, sharedResponse := chainA.sharedRequest, chainA.sharedResponse
	inputB.RequestBytes = sharedRequest
	inputB.ResponseBytes = sharedResponse
	// Later than A's own maximum (2009-12-27ish) but STILL expired
	// relative to "now" -- D98's global eligibility predicate requires
	// EVERY ledger's obligation on the shared snapshot to be expired
	// before anyone may purge it (R43's own stated limit), so this test's
	// purge below only succeeds if B's obligation is also in the past.
	inputB.OccurredAt = "2015-01-01T00:00:00Z"
	inputB.Retention.RetentionDays = 1
	resultB, err := storeB.Append(inputB)
	if err != nil {
		t.Fatal(err)
	}
	mirrorEvent(t, ctx, storeB, chainA.sink, resultB)

	if resultB.Event.RequestSnapshotSHA256 != chainA.sha {
		t.Fatalf("test construction error: expected ledger B's snapshot sha to equal ledger A's shared sha")
	}

	longExpires, _ := time.Parse(time.RFC3339Nano, chainA.longEvent.ExpiresAt)
	shortExpires, _ := time.Parse(time.RFC3339Nano, chainA.shortEvent.ExpiresAt)
	aMax := longExpires
	if shortExpires.After(aMax) {
		aMax = shortExpires
	}
	bExpires, err := time.Parse(time.RFC3339Nano, resultB.Event.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if !bExpires.After(aMax) {
		t.Fatalf("test construction error: ledger B's obligation must be LATER than ledger A's own maximum")
	}

	// A's own aggregate (ledgerID-scoped) must be A's maximum, not B's.
	aCount, aMirrorMax, found, err := chainA.sink.EventExpiresAggregateForSnapshot(ctx, chainA.sha, chainA.store.ledgerID)
	if err != nil || !found {
		t.Fatalf("EventExpiresAggregateForSnapshot (ledger A): found=%v err=%v", found, err)
	}
	if aCount != 2 {
		t.Fatalf("ADR-0007 Addendum 11 D97(b): expected ledger A's scoped count to be 2 (its own two events only), got %d", aCount)
	}
	if !aMirrorMax.Equal(aMax.Truncate(time.Microsecond)) {
		t.Fatalf("ADR-0007 Addendum 11 D97(b): expected ledger A's scoped MAX to be its own maximum (%s), got %s -- the population leaked ledger B's obligation", aMax.Format(time.RFC3339Nano), aMirrorMax.Format(time.RFC3339Nano))
	}

	// The UNSCOPED query (no ledger_id predicate, what postgres.go:1614
	// selected from before D97) would have returned a row set including
	// B's -- confirmed directly, so the negative is measured rather than
	// assumed.
	var unscopedCount int
	var unscopedMax time.Time
	if err := chainA.sink.conn.QueryRow(ctx, `SELECT count(*), max(expires_at) FROM screening_ledger_event WHERE request_snapshot_sha256=$1 OR response_snapshot_sha256=$1`, chainA.sha).Scan(&unscopedCount, &unscopedMax); err != nil {
		t.Fatal(err)
	}
	if unscopedCount != 3 {
		t.Fatalf("expected the UNSCOPED query to see all 3 events (A's 2 plus B's 1) sharing this sha, got %d", unscopedCount)
	}
	if !unscopedMax.Equal(bExpires.Truncate(time.Microsecond)) {
		t.Fatalf("expected the UNSCOPED max to be ledger B's later obligation (%s), got %s -- this is the value a caller would get without D97(b)'s ledger_id predicate", bExpires.Format(time.RFC3339Nano), unscopedMax.Format(time.RFC3339Nano))
	}

	// A's own corroboration (the real forSnapshot path, through a real
	// purge and verify) must not fail on B's rows.
	purgedCount, err := chainA.store.PurgeExpired(ctx, time.Now(), "legit-operator", "legit-reason", chainA.sink)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if purgedCount != 2 {
		t.Fatalf("expected 2 snapshots purged for ledger A, got %d", purgedCount)
	}
	if _, err := chainA.store.AppendAudit("a11-population-setup", "", "", "", nil); err != nil {
		t.Fatal(err)
	}
	report, err := chainA.store.VerifyPolicy(ctx, VerifyOptions{Policy: chainA.policy, Purges: chainA.sink, allowDeferredPurgeClaims: true})
	if err != nil {
		t.Fatalf("VerifyPolicy: %v", err)
	}
	if err := chainA.anchorSink.WriteAnchor(ctx, chainA.kAnchor, chainA.store.ledgerID, int64(report.Head.Sequence), report.Head.EventSHA256, report.AuditHead.EventSHA256, int64(report.AuditHead.Sequence), testPolicySHA256(t, chainA.policy)); err != nil {
		t.Fatalf("WriteAnchor: %v", err)
	}
	result, err := chainA.store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: chainA.policy, Purges: chainA.sink},
		Anchors:       chainA.sink, Provisioning: chainA.sink, KAnchor: chainA.kAnchor, PolicySHA256: testPolicySHA256(t, chainA.policy),
	})
	if err != nil || result.AnchorStatus != AnchorStatusVerified {
		t.Fatalf("ADR-0007 Addendum 11 D97(b): expected ledger A's purge to verify clean despite ledger B sharing the same snapshot row, got status=%v err=%v", result.AnchorStatus, err)
	}
}
