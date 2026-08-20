// ADR-0007 Addendum 2 D25 (F-C/F-F): the signed policy's min_anchor_sequence
// closes the CAP's §7.3/§7.4 anchor-table-wipe bypass without needing D26 --
// a policy floor >= 1 makes a full wipe (zero anchor rows) detectable, and
// a present-but-rolled-back anchor below the floor equally so. Both halves
// are normative per D25's own text; a fix that closes only the absent case
// has not discharged it.
package screeningledger

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestVerifyAnchoredRejectsAbsentAnchorBelowFloor is D25 point 1: CAP
// §7.3+§7.4's exact composed attack -- owl_ledger_ddl wipes the anchor
// table, restores the triggers, and the wipe is otherwise indistinguishable
// from a ledger that was never anchored. A signed policy committing to
// min_anchor_sequence >= 1 makes this detectable: an absent anchor is a
// failure regardless of mode or --allow-genesis, because the policy
// already asserts something stronger than either.
func TestVerifyAnchoredRejectsAbsentAnchorBelowFloor(t *testing.T) {
	migratorDSN := requireMigratorDSN(t)
	ctx := context.Background()

	store, kAnchor := anchorTestKeys(t, 1)
	policy := testPolicy(store.ledgerID)
	policy.MinAnchorSequence = 1 // asserts at least one anchor must exist

	readerSink, err := NewPostgresSink(ctx, migratorDSN, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer readerSink.Close(context.Background())

	// Genuinely no anchor row exists for this fresh ledger. Anchored mode,
	// --allow-genesis passed: before D25 this succeeds with
	// AnchorStatusAbsent (CAP §7.4's exact bypass shape). With the floor
	// set, it must fail instead.
	if _, err := store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: policy}, Anchors: readerSink, Provisioning: readerSink, KAnchor: kAnchor, AllowGenesis: true,
	}); err == nil {
		t.Fatal("expected a failure: no anchor row exists but the policy commits to min_anchor_sequence=1 (ADR-0007 Addendum 2 D25)")
	} else if !strings.Contains(err.Error(), "min_anchor_sequence") && !strings.Contains(err.Error(), "minimum anchor sequence") {
		t.Fatalf("expected the error to name the min_anchor_sequence floor, got: %v", err)
	}

	// Historical-unanchored mode does not bypass the floor either.
	unanchoredPolicy := policy
	unanchoredPolicy.AllowUnanchored = true
	if _, err := store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: unanchoredPolicy, Mode: VerificationModeHistoricalUnanchored}, Anchors: readerSink, Provisioning: readerSink, KAnchor: kAnchor,
	}); err == nil {
		t.Fatal("expected historical-unanchored mode to still fail against an absent anchor when the policy commits to min_anchor_sequence=1")
	}

	// Control: with no floor (min_anchor_sequence 0), --allow-genesis still
	// works exactly as before -- this is not a regression on the genuine
	// genesis path.
	genesisPolicy := policy
	genesisPolicy.MinAnchorSequence = 0
	result, err := store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: genesisPolicy}, Anchors: readerSink, Provisioning: readerSink, KAnchor: kAnchor, AllowGenesis: true,
	})
	if err != nil {
		t.Fatalf("expected --allow-genesis to still work with no floor set: %v", err)
	}
	if result.AnchorStatus != AnchorStatusAbsent {
		t.Fatalf("expected AnchorStatusAbsent for a genuine genesis with no floor, got %q", result.AnchorStatus)
	}
}

// TestVerifyAnchoredRejectsPresentAnchorBelowFloor is D25 point 2: a
// PRESENT anchor whose sequence is below the policy's floor is equally a
// failure -- distinct from AnchorStatusAbsent, because something was found
// and it disagrees with what the policy committed to. Models an
// owl_ledger_ddl rollback to an earlier saved row after dropping the
// immutability trigger, rather than a full wipe.
func TestVerifyAnchoredRejectsPresentAnchorBelowFloor(t *testing.T) {
	anchorDSN := requireAnchorDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ctx := context.Background()

	store, kAnchor := anchorTestKeys(t, 3)
	policy := testPolicy(store.ledgerID)
	policySHA256 := testPolicySHA256(t, policy)

	// The real event digest AT sequence 1 -- not the head's (the newest,
	// sequence-3 entry's) -- so an anchor genuinely committed to sequence
	// 1 cross-checks correctly against the live chain, and any failure
	// the tests below see is attributable to the D25 floor check alone,
	// not an unrelated digest mismatch. anchorTestKeys's plain Append
	// loop never writes an audit entry (AppendAudit's only call sites are
	// postgres_replicated/replay/export_bundle/purge_expired, none of
	// which this test exercises), so the audit chain stays empty
	// throughout -- report.AuditHead is its zero-sequence, empty-digest
	// value, exactly what a genuine anchor of this ledger's audit state
	// would also commit to.
	eventAtOne, err := store.eventAtSequence(1)
	if err != nil {
		t.Fatal(err)
	}
	report, err := store.VerifyPolicy(ctx, VerifyOptions{Policy: policy})
	if err != nil {
		t.Fatal(err)
	}

	anchorSink, err := NewAnchorSink(ctx, anchorDSN, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer anchorSink.Close(context.Background())
	// Anchor at sequence 1 (an early, real point in this chain's history).
	if err := anchorSink.WriteAnchor(ctx, kAnchor, store.ledgerID, 1, eventAtOne.EventSHA256, report.AuditHead.EventSHA256, int64(report.AuditHead.Sequence), policySHA256); err != nil {
		t.Fatalf("WriteAnchor: %v", err)
	}

	readerSink, err := NewPostgresSink(ctx, migratorDSN, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer readerSink.Close(context.Background())

	// A policy committing to a floor higher than the anchor actually
	// present (sequence 1) -- e.g. an operator who knows this ledger
	// should have reached at least sequence 2 before verifying.
	flooredPolicy := policy
	flooredPolicy.MinAnchorSequence = 2

	if _, err := store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: flooredPolicy}, Anchors: readerSink, Provisioning: readerSink, KAnchor: kAnchor, PolicySHA256: policySHA256,
	}); err == nil {
		t.Fatal("expected a failure: the present anchor (sequence 1) is below the policy's min_anchor_sequence (2) (ADR-0007 Addendum 2 D25)")
	} else if !strings.Contains(err.Error(), "below the signed policy's minimum anchor sequence") {
		t.Fatalf("expected an error naming the below-floor anchor sequence, got: %v", err)
	}

	// Control: a floor the present anchor actually satisfies passes this
	// specific check (though it may still fail other checks unrelated to
	// D25, which is fine -- this control only needs to show the floor
	// check itself is not spuriously rejecting a satisfying anchor).
	satisfiedPolicy := policy
	satisfiedPolicy.MinAnchorSequence = 1
	if _, err := store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: satisfiedPolicy}, Anchors: readerSink, Provisioning: readerSink, KAnchor: kAnchor, PolicySHA256: policySHA256,
	}); err != nil && strings.Contains(err.Error(), "below the signed policy's minimum anchor sequence") {
		t.Fatalf("floor check spuriously rejected an anchor that satisfies it: %v", err)
	}
}
