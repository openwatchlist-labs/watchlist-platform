// ADR-0007 Addendum 11 D101(a)/D101(b), D103 test 9 (the reporting
// half): the same database and the same rows, across all four of D93's
// own table paths, asserting the two `unavailable` rows report the
// explicit not-checked marker rather than the number 0 -- 0 today,
// before this addendum.
package screeningledger

import (
	"context"
	"testing"
)

func TestOutOfScopeCountIsNeverZeroForNotChecked(t *testing.T) {
	ctx := context.Background()
	chain := newA10Chain(t, ctx)

	ledgerDDLConn := chain.ledgerDDLConn(t, ctx)
	defer ledgerDDLConn.Close(context.Background())
	for i := 0; i < 3; i++ {
		if _, err := ledgerDDLConn.Exec(ctx,
			`INSERT INTO screening_ledger_retention_tombstone (snapshot_sha256, purged_at, operator, reason) VALUES ($1, now(), 'other-ledger-op', 'other-ledger-reason')`,
			uniqueID("d101-out-of-scope"),
		); err != nil {
			t.Fatalf("insert out-of-scope tombstone %d: %v", i, err)
		}
	}

	relaxedPolicy := chain.policy
	relaxedPolicy.AllowUnanchored = true

	// Row 1: anchored, Anchors+Purges set -- checked, with findings.
	anchoredResult, err := chain.store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: chain.policy, Purges: chain.sink, Mode: VerificationModeAnchored},
		Anchors:       chain.sink, Provisioning: chain.sink, KAnchor: chain.kAnchor, PolicySHA256: chain.policySHA256,
	})
	if err != nil {
		t.Fatalf("anchored VerifyAnchored: %v", err)
	}
	if anchoredResult.OutOfScopeRetentionTombstonesChecked != OutOfScopeCheckFindings {
		t.Fatalf("ADR-0007 Addendum 11 D101(a): expected anchored mode to report %q, got %q", OutOfScopeCheckFindings, anchoredResult.OutOfScopeRetentionTombstonesChecked)
	}
	if len(anchoredResult.OutOfScopeRetentionTombstones) < 3 {
		t.Fatalf("expected at least the 3 planted out-of-scope tombstones, got %d", len(anchoredResult.OutOfScopeRetentionTombstones))
	}

	// Row 2: unanchored (historical-unanchored), Anchors+Purges set --
	// also checked, per D93's own "runs in every mode" claim -- must
	// agree with row 1.
	unanchoredResult, err := chain.store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: relaxedPolicy, Purges: chain.sink, Mode: VerificationModeHistoricalUnanchored},
		Anchors:       chain.sink, Provisioning: chain.sink, KAnchor: chain.kAnchor, PolicySHA256: chain.policySHA256,
	})
	if err != nil {
		t.Fatalf("historical-unanchored VerifyAnchored: %v", err)
	}
	if unanchoredResult.OutOfScopeRetentionTombstonesChecked != OutOfScopeCheckFindings {
		t.Fatalf("ADR-0007 Addendum 11 D101(a): expected historical-unanchored mode (Anchors set) to report %q, got %q", OutOfScopeCheckFindings, unanchoredResult.OutOfScopeRetentionTombstonesChecked)
	}
	if len(unanchoredResult.OutOfScopeRetentionTombstones) != len(anchoredResult.OutOfScopeRetentionTombstones) {
		t.Fatalf("expected the two checked modes to agree on the same database: anchored=%d unanchored=%d", len(anchoredResult.OutOfScopeRetentionTombstones), len(unanchoredResult.OutOfScopeRetentionTombstones))
	}

	// Row 3: unanchored, Anchors=nil -- the connection is live (Purges is
	// still chain.sink), but VerifyAnchored returns early at the
	// opts.Anchors==nil branch, before the reporting pass ever runs. This
	// is D93's own table row 3, the sharp one: the database still holds
	// the same rows and the count must not read as 0.
	noAnchorsResult, err := chain.store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: relaxedPolicy, Purges: chain.sink, Mode: VerificationModeHistoricalUnanchored},
		Anchors:       nil, Provisioning: chain.sink, KAnchor: chain.kAnchor, PolicySHA256: chain.policySHA256,
	})
	if err != nil {
		t.Fatalf("unanchored, Anchors=nil: %v", err)
	}
	if noAnchorsResult.AnchorStatus != AnchorStatusUnavailable {
		t.Fatalf("expected AnchorStatusUnavailable, got %v", noAnchorsResult.AnchorStatus)
	}
	if noAnchorsResult.OutOfScopeRetentionTombstonesChecked != OutOfScopeCheckNotPerformed {
		t.Fatalf("ADR-0007 Addendum 11 D101(a)/(b): expected the not-checked marker when Anchors=nil despite a live Purges connection and the same rows still present, got %q (today's bug: this reads as 0, indistinguishable from a clean check)", noAnchorsResult.OutOfScopeRetentionTombstonesChecked)
	}
	if len(noAnchorsResult.OutOfScopeRetentionTombstones) != 0 {
		t.Fatalf("expected no tombstones reported when the pass never ran, got %d", len(noAnchorsResult.OutOfScopeRetentionTombstones))
	}

	// Row 4: unanchored, no database at all (Purges=nil too).
	noDatabaseResult, err := chain.store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: relaxedPolicy, Purges: nil, Mode: VerificationModeHistoricalUnanchored},
		Anchors:       nil, Provisioning: nil, KAnchor: chain.kAnchor, PolicySHA256: chain.policySHA256,
	})
	if err != nil {
		t.Fatalf("unanchored, no database at all: %v", err)
	}
	if noDatabaseResult.AnchorStatus != AnchorStatusUnavailable {
		t.Fatalf("expected AnchorStatusUnavailable, got %v", noDatabaseResult.AnchorStatus)
	}
	if noDatabaseResult.OutOfScopeRetentionTombstonesChecked != OutOfScopeCheckNotPerformed {
		t.Fatalf("ADR-0007 Addendum 11 D101(a)/(b): expected the not-checked marker with no database at all, got %q", noDatabaseResult.OutOfScopeRetentionTombstonesChecked)
	}
}
