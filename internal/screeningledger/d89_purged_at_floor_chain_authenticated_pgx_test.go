// ADR-0007 Addendum 10 D89/D95 test 3 (N-A limb 1, CRITICAL): the
// genesis-case (and, per D89's own max() rule, every-case) lower bound
// is now the chain-authenticated Event.ExpiresAt, corroborated against
// the mirror's screening_ledger_event.expires_at -- never
// screening_ledger_snapshot.created_at, which D89 withdraws as a
// referent entirely (see d81_purged_at_bound_pgx_test.go's
// TestPurgedAtGenesisFallbackUsesChainAuthenticatedExpiresAt and
// backdated_created_at_no_longer_consulted subtest for the genesis-floor
// reproduction and the isolation from D87; this file covers what those
// do not: the mirror/chain reconciliation in both directions and clock
// skew tolerance).
package screeningledger

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestPurgedAtFloorIsChainAuthenticated_MirrorChainAgree is the positive
// D45's own rule requires: on a clean ledger, the chain's Event.ExpiresAt
// and the mirror's screening_ledger_event.expires_at agree, and a real
// purge verifies clean both at genesis and past a preceding anchor.
func TestPurgedAtFloorIsChainAuthenticated_MirrorChainAgree(t *testing.T) {
	ctx := context.Background()
	chain := newA10Chain(t, ctx)

	chainExpiresAt, err := time.Parse(time.RFC3339Nano, chain.purgedEvent.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	mirrorCount, mirrorMax, found, err := chain.sink.EventExpiresAggregateForSnapshot(ctx, chain.purgedSHA, chain.store.ledgerID)
	if err != nil || !found {
		t.Fatalf("EventExpiresAggregateForSnapshot: found=%v err=%v", found, err)
	}
	if mirrorCount != 1 {
		t.Fatalf("ADR-0007 Addendum 11 D97: expected exactly 1 mirror row for this ledger's single-obligation snapshot, got %d", mirrorCount)
	}
	if !mirrorMax.Equal(chainExpiresAt.Truncate(time.Microsecond)) {
		t.Fatalf("ADR-0007 Addendum 10 D89 / Addendum 11 D97: mirror MAX(expires_at) (%s) and chain expires_at (%s) should agree on a clean ledger", mirrorMax.Format(time.RFC3339Nano), chainExpiresAt.Format(time.RFC3339Nano))
	}

	// Past a preceding anchor (anchor 4 attests the purge, anchor 2
	// precedes it) -- a10Chain's own baseline.
	if result, err := chain.verify(t, ctx); err != nil || result.AnchorStatus != AnchorStatusVerified {
		t.Fatalf("expected a clean legitimately-anchored purge past a preceding anchor to verify, got status=%v err=%v", result.AnchorStatus, err)
	}
}

// TestPurgedAtFloorIsChainAuthenticated_MirrorDivergenceIsNamed is D89's
// own stated caution: the mirror value is corroboration, never promoted
// to authority, and a disagreement is a named failure rather than
// silently resolved either way. Alters ONLY the mirror's
// screening_ledger_event.expires_at, leaving the chain (and every other
// SEC-7 control) untouched.
func TestPurgedAtFloorIsChainAuthenticated_MirrorDivergenceIsNamed(t *testing.T) {
	ctx := context.Background()
	chain := newA10Chain(t, ctx)

	superuser := connectSuperuser(t, ctx, chain.superuserDSN)
	defer superuser.Close(context.Background())
	withD34TriggersDisabled(t, ctx, superuser, func() {
		mustExec(t, ctx, superuser, `ALTER TABLE screening_ledger_event DISABLE TRIGGER screening_ledger_event_immutable`)
		mustExecArgs(t, ctx, superuser, `UPDATE screening_ledger_event SET expires_at = expires_at + interval '1000 days' WHERE request_snapshot_sha256=$1`, chain.purgedSHA)
		mustExec(t, ctx, superuser, `ALTER TABLE screening_ledger_event ENABLE TRIGGER screening_ledger_event_immutable`)
	})

	result, err := chain.verify(t, ctx)
	if err == nil {
		t.Fatalf("ADR-0007 Addendum 10 D89: verify succeeded (status=%q) despite the mirror's screening_ledger_event.expires_at diverging from the chain's own Event.ExpiresAt", result.AnchorStatus)
	}
	if !strings.Contains(err.Error(), "D89") || !strings.Contains(err.Error(), "divergence") {
		t.Fatalf("expected a named mirror/chain divergence error citing ADR-0007 Addendum 10 D89, got: %v", err)
	}
}

// TestPurgedAtFloorIsChainAuthenticated_ClockSkewTolerant is D70's own
// false-failure generator, re-checked against D89's new bound: since
// both purged_at and expires_at are Postgres clock_timestamp() values
// compared against each other in the same statement
// (db/migrations/020's own predicate), skew between the Go test process'
// clock and Postgres's does not enter this comparison at all. Confirmed
// here by simply running the legitimate path while the two clocks are
// whatever they independently are -- this test would be flaky if any
// cross-clock comparison had crept in.
func TestPurgedAtFloorIsChainAuthenticated_ClockSkewTolerant(t *testing.T) {
	ctx := context.Background()
	chain := newA10Chain(t, ctx)
	for i := 0; i < 3; i++ {
		if result, err := chain.verify(t, ctx); err != nil || result.AnchorStatus != AnchorStatusVerified {
			t.Fatalf("run %d: expected a clean verify with no cross-clock flakiness, got status=%v err=%v", i, result.AnchorStatus, err)
		}
	}
}
