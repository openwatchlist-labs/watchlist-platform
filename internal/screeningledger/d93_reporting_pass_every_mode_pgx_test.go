// ADR-0007 Addendum 10 D93/D95 test 7 (N-E, MEDIUM / N-F, LOW): the
// reporting pass (D82's out-of-scope tombstone report) now runs in
// every verification mode, and `sync` carries the same two fields
// `status`/`verify` already did.
package screeningledger

import (
	"context"
	"testing"
)

// TestOutOfScopeTombstonesAreReportedInEveryMode reproduces D93's own
// measurement: identical out-of-scope tombstone rows, reported in
// anchored mode and now ALSO reported in historical-unanchored mode
// against the same database -- and the negative that keeps D70's scope
// limit intact: rows INSIDE the known set still fail verification on
// divergence in anchored mode, and are still not adjudicated (only
// reported, if out of scope; simply invisible if in scope with no
// divergence) in unanchored mode.
func TestOutOfScopeTombstonesAreReportedInEveryMode(t *testing.T) {
	ctx := context.Background()
	chain := newA10Chain(t, ctx)

	ledgerDDLConn := chain.ledgerDDLConn(t, ctx)
	defer ledgerDDLConn.Close(context.Background())
	for i := 0; i < 3; i++ {
		if _, err := ledgerDDLConn.Exec(ctx,
			`INSERT INTO screening_ledger_retention_tombstone (snapshot_sha256, purged_at, operator, reason) VALUES ($1, now(), 'other-ledger-op', 'other-ledger-reason')`,
			uniqueID("d93-out-of-scope"),
		); err != nil {
			t.Fatalf("insert out-of-scope tombstone %d: %v", i, err)
		}
	}

	anchoredResult, err := chain.store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: chain.policy, Purges: chain.sink, Mode: VerificationModeAnchored},
		Anchors:       chain.sink, Provisioning: chain.sink, KAnchor: chain.kAnchor, PolicySHA256: chain.policySHA256,
	})
	if err != nil {
		t.Fatalf("anchored VerifyAnchored: %v", err)
	}

	relaxedPolicy := chain.policy
	relaxedPolicy.AllowUnanchored = true
	unanchoredResult, err := chain.store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: relaxedPolicy, Purges: chain.sink, Mode: VerificationModeHistoricalUnanchored},
		Anchors:       chain.sink, Provisioning: chain.sink, KAnchor: chain.kAnchor, PolicySHA256: chain.policySHA256,
	})
	if err != nil {
		t.Fatalf("historical-unanchored VerifyAnchored: %v", err)
	}

	// This clone's own TEMPLATE ancestor (the shared primary database
	// other tests in this package also exercise) may already carry other
	// out-of-scope tombstone rows -- not asserted to a fixed count, only
	// that the 3 planted here are among them (>= 3) and, the actual
	// point of D93, that anchored and historical-unanchored modes report
	// IDENTICALLY against the identical database.
	if len(anchoredResult.OutOfScopeRetentionTombstones) < 3 {
		t.Fatalf("expected at least the 3 out-of-scope tombstones planted here to be reported in anchored mode, got %d", len(anchoredResult.OutOfScopeRetentionTombstones))
	}
	if len(unanchoredResult.OutOfScopeRetentionTombstones) != len(anchoredResult.OutOfScopeRetentionTombstones) {
		t.Fatalf("ADR-0007 Addendum 10 D93: anchored mode reported %d out-of-scope tombstones but historical-unanchored mode reported %d against the identical database (today's bug: unanchored reports 0)", len(anchoredResult.OutOfScopeRetentionTombstones), len(unanchoredResult.OutOfScopeRetentionTombstones))
	}
}

// TestOutOfScopeTombstonesAreReportedInEveryMode_InScopeDivergenceStillFails
// is the negative D93 must not weaken: a tombstone row INSIDE this
// ledger's own known history that diverges from its attesting audit
// entry still fails verification in anchored mode -- the reporting pass
// widening does not touch the adjudicating pass's scope.
func TestOutOfScopeTombstonesAreReportedInEveryMode_InScopeDivergenceStillFails(t *testing.T) {
	ctx := context.Background()
	chain := newA10Chain(t, ctx)

	superuser := connectSuperuser(t, ctx, chain.superuserDSN)
	defer superuser.Close(context.Background())
	withD34TriggersDisabled(t, ctx, superuser, func() {
		mustExec(t, ctx, superuser, `ALTER TABLE screening_ledger_retention_tombstone DISABLE TRIGGER screening_ledger_retention_tombstone_immutable`)
		mustExecArgs(t, ctx, superuser, `UPDATE screening_ledger_retention_tombstone SET operator='forged' WHERE snapshot_sha256=$1`, chain.purgedSHA)
		mustExec(t, ctx, superuser, `ALTER TABLE screening_ledger_retention_tombstone ENABLE TRIGGER screening_ledger_retention_tombstone_immutable`)
	})

	if _, err := chain.verify(t, ctx); err == nil {
		t.Fatalf("ADR-0007 Addendum 10 D93: expected an in-scope tombstone attribution forgery to still fail anchored-mode verification")
	}
}
