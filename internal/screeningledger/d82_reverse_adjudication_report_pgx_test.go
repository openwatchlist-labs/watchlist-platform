// ADR-0007 Addendum 9 D82/D85 test 6 (M-E, CRITICAL): the reverse pass
// keeps its adjudicating population (rows in KnownSnapshotSHA256, failing
// verification on divergence exactly as D70 specified) and gains a
// second, unfiltered reporting population (every other row, named and
// counted in VerifyReport, never failing verification on its own). CAP
// #8 section 7.5's exact reproduction: a single INSERT as owl_ledger_ddl
// for a snapshot outside KnownSnapshotSHA256, no superuser, no trigger
// manipulation, no precondition at all -- the lowest-reachability
// CRITICAL in this arc.
package screeningledger

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestReverseAdjudicationReportsUnknownTombstones is D85 test 6: CAP #8
// section 7.5's exact single INSERT for a snapshot outside
// KnownSnapshotSHA256, asserting VerifyAnchored returns status=verified
// err=nil TODAY and that the row is named in VerifyReport after. Plus:
// rows INSIDE the known set still FAIL verification on divergence (D70
// unregressed), and a clean ledger reports nothing.
func TestReverseAdjudicationReportsUnknownTombstones(t *testing.T) {
	ctx := context.Background()
	chain := newD70Chain(t, ctx)

	// CAP #8 section 7.5's exact reproduction, as owl_ledger_ddl, no
	// superuser, no event-trigger manipulation, one INSERT. M-E's own
	// "TODAY" invisibility was independently reproduced against a real
	// Postgres cluster during this addendum's implementation (see the PR
	// description's pasted transcript) -- not re-derived here, the same
	// reason d77_body_digest_pgx_test.go does not re-run the shipped
	// installer's pre-fix behavior: this addendum's own D82 fix already
	// lands in the same change, so there is no unpatched VerifyAnchored
	// left to call.
	ledgerDDLConn, err := pgx.Connect(ctx, withDatabase(t, requireLedgerDDLDatabaseURL(t), chain.clone.dbName))
	if err != nil {
		t.Fatalf("connect as owl_ledger_ddl: %v", err)
	}
	defer ledgerDDLConn.Close(context.Background())
	fabricatedSHA := uniqueID("cap9unknown")
	if _, err := ledgerDDLConn.Exec(ctx,
		`INSERT INTO screening_ledger_retention_tombstone (snapshot_sha256, purged_at, operator, reason) VALUES ($1, '2020-01-01 00:00:00+00', 'compliance-bot', 'purged under 90d retention policy')`,
		fabricatedSHA,
	); err != nil {
		t.Fatalf("ADR-0007 Addendum 9 D76/D82: expected the fabricated INSERT to succeed as owl_ledger_ddl (D61's own declared matrix), no precondition at all: %v", err)
	}

	// AFTER (the shipped fix): verification still succeeds -- reporting
	// must not cause a false failure -- and the fabricated row is named,
	// counted, and carried in VerifyReport.
	result, err := chain.store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: chain.policy, Purges: chain.sink},
		Anchors:       chain.sink, Provisioning: chain.sink, KAnchor: chain.kAnchor, PolicySHA256: chain.policySHA256,
	})
	if err != nil || result.AnchorStatus != AnchorStatusVerified {
		t.Fatalf("ADR-0007 Addendum 9 D82: expected verification to still succeed (reporting must not cause a false failure), got status=%v err=%v", result.AnchorStatus, err)
	}
	// >= 1, not == 1: owl_ci is a shared, long-lived primary database
	// other tests in this suite also write tombstone rows into directly
	// (not through a disposable clone), and every screening_ledger_anchor
	// TEMPLATE clone -- including this one's -- inherits that entire
	// prior history. The reporting population is exactly "every row this
	// ledger's chain does not reference," which correctly includes rows
	// other tests legitimately left behind; asserting the fabricated row
	// specifically, by name, among whatever else this shared fixture
	// has accumulated is the meaningful check.
	found := false
	for _, r := range result.OutOfScopeRetentionTombstones {
		if r.SnapshotSHA256 == fabricatedSHA {
			found = true
		}
	}
	if !found {
		t.Fatalf("ADR-0007 Addendum 9 D82: expected the fabricated snapshot %q among the reported out-of-scope tombstones, got %d rows: %v", fabricatedSHA, len(result.OutOfScopeRetentionTombstones), result.OutOfScopeRetentionTombstones)
	}

	// D70 unregressed: a row INSIDE the known set still fails
	// verification on divergence -- reuse the exact orphan-tombstone
	// reproduction this addendum's predecessor already established.
	t.Run("d70_in_scope_divergence_still_fails", func(t *testing.T) {
		chain2 := newD70Chain(t, ctx)
		targetSHA := chain2.appendExtraKnownButUnpurgedSnapshot(t, ctx)
		ledgerDDLConn2, err := pgx.Connect(ctx, withDatabase(t, requireLedgerDDLDatabaseURL(t), chain2.clone.dbName))
		if err != nil {
			t.Fatal(err)
		}
		defer ledgerDDLConn2.Close(context.Background())
		if _, err := ledgerDDLConn2.Exec(ctx,
			`INSERT INTO screening_ledger_retention_tombstone (snapshot_sha256, purged_at, operator, reason) VALUES ($1, now(), 'attacker', 'fabricated, never purged locally')`,
			targetSHA,
		); err != nil {
			t.Fatal(err)
		}
		result2, err := chain2.store.VerifyAnchored(ctx, AnchorOptions{
			VerifyOptions: VerifyOptions{Policy: chain2.policy, Purges: chain2.sink},
			Anchors:       chain2.sink, Provisioning: chain2.sink, KAnchor: chain2.kAnchor, PolicySHA256: chain2.policySHA256,
		})
		if err == nil {
			t.Fatalf("ADR-0007 Addendum 8 D70: verify succeeded (status=%q) despite an in-scope orphan tombstone -- D82's reporting pass must not have swallowed this into the reporting-only branch", result2.AnchorStatus)
		}
	})

	// A clean ledger reports nothing.
	t.Run("clean_ledger_reports_nothing", func(t *testing.T) {
		chain3 := newD70Chain(t, ctx)
		// owl_ci is a shared, long-lived primary other tests in this
		// suite also write tombstone rows into directly, and every
		// TEMPLATE clone -- chain3's own included -- inherits that
		// entire prior history. Removing every row outside chain3's own
		// known-snapshot scope isolates "this chain reports nothing" from
		// "nothing else in this shared fixture ever wrote a tombstone
		// row," which is not a property this suite can promise on its
		// own account.
		report, err := chain3.store.VerifyPolicy(ctx, VerifyOptions{Policy: chain3.policy, Purges: chain3.sink, allowDeferredPurgeClaims: true})
		if err != nil {
			t.Fatalf("VerifyPolicy: %v", err)
		}
		superuser3, err := pgx.Connect(ctx, chain3.superuserDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer superuser3.Close(context.Background())
		// screening_ledger_retention_tombstone carries D16's row-immutability
		// trigger (DELETE is blocked for everyone, including this
		// superuser) -- disabled for exactly this one statement, the same
		// pattern this file's own forgery setups use.
		withD34TriggersDisabled(t, ctx, superuser3, func() {
			if _, err := superuser3.Exec(ctx, `ALTER TABLE screening_ledger_retention_tombstone DISABLE TRIGGER screening_ledger_retention_tombstone_immutable`); err != nil {
				t.Fatal(err)
			}
		})
		if _, err := superuser3.Exec(ctx, `DELETE FROM screening_ledger_retention_tombstone WHERE NOT (snapshot_sha256 = ANY($1))`, report.KnownSnapshotSHA256); err != nil {
			t.Fatalf("isolate chain3's clone from the shared fixture's accumulated history: %v", err)
		}
		withD34TriggersDisabled(t, ctx, superuser3, func() {
			if _, err := superuser3.Exec(ctx, `ALTER TABLE screening_ledger_retention_tombstone ENABLE TRIGGER screening_ledger_retention_tombstone_immutable`); err != nil {
				t.Fatal(err)
			}
		})

		clean, err := chain3.store.VerifyAnchored(ctx, AnchorOptions{
			VerifyOptions: VerifyOptions{Policy: chain3.policy, Purges: chain3.sink},
			Anchors:       chain3.sink, Provisioning: chain3.sink, KAnchor: chain3.kAnchor, PolicySHA256: chain3.policySHA256,
		})
		if err != nil || clean.AnchorStatus != AnchorStatusVerified {
			t.Fatalf("expected a clean chain to verify, got status=%v err=%v", clean.AnchorStatus, err)
		}
		if len(clean.OutOfScopeRetentionTombstones) != 0 {
			t.Fatalf("expected a clean ledger to report zero out-of-scope tombstones, got %d: %v", len(clean.OutOfScopeRetentionTombstones), clean.OutOfScopeRetentionTombstones)
		}
	})
}
