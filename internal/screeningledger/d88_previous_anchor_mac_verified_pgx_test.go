// ADR-0007 Addendum 10 D88/D95 test 2 (N-A limb 2, CRITICAL): the anchor
// PreviousAnchorAt returns is now MAC-verified under K_anchor before any
// value from it is used, and anchored_at is now inside anchorMAC's own
// input. Before this addendum: a spurious anchor row planted at a gap
// sequence, with a garbage MAC and a backdated anchored_at, was read by
// PreviousAnchorAt and trusted with no MAC check ever visiting it, and a
// genuine row with anchored_at moved verified regardless.
package screeningledger

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestPreviousAnchorIsMACVerified reproduces CAP #9's exact spurious gap
// anchor (N-A limb 2), plus the controls that isolate what is
// load-bearing: no spurious row (D81 already rejects), the referent left
// honest, and the anchorMAC half in isolation (anchored_at alone moved).
func TestPreviousAnchorIsMACVerified(t *testing.T) {
	ctx := context.Background()

	t.Run("spurious_gap_anchor_is_refused", func(t *testing.T) {
		chain := newA10Chain(t, ctx)

		// Control: rewrite purged_at to 1999 with no spurious anchor --
		// D81/D89's floor (the genuine preceding anchor's anchored_at,
		// which dominates max(expiresAt, previousAnchoredAt) here) already
		// rejects this.
		superuser := connectSuperuser(t, ctx, chain.superuserDSN)
		defer superuser.Close(context.Background())
		withD34TriggersDisabled(t, ctx, superuser, func() {
			mustExec(t, ctx, superuser, `ALTER TABLE screening_ledger_retention_tombstone DISABLE TRIGGER screening_ledger_retention_tombstone_immutable`)
			mustExecArgs(t, ctx, superuser, `UPDATE screening_ledger_retention_tombstone SET purged_at='1999-01-01' WHERE snapshot_sha256=$1`, chain.purgedSHA)
			mustExec(t, ctx, superuser, `ALTER TABLE screening_ledger_retention_tombstone ENABLE TRIGGER screening_ledger_retention_tombstone_immutable`)
		})
		if _, err := chain.verify(t, ctx); err == nil {
			t.Fatalf("test precondition failed: expected the control (backdated purged_at, no spurious anchor) to already be refused")
		}

		// Attack: plant a spurious anchor row at the gap sequence (3), as
		// owl_ledger_anchor -- a role granted only INSERT on this table,
		// exactly the privilege this uses.
		anchorConn := chain.anchorConn(t, ctx)
		defer anchorConn.Close(context.Background())
		if _, err := anchorConn.Exec(ctx,
			`INSERT INTO screening_ledger_anchor(ledger_id,sequence,event_sha256,audit_sha256,audit_sequence,policy_sha256,anchor_mac,anchored_at)
			 VALUES ($1,3,'deadbeef','deadbeef',2,$2,'not-a-real-mac','1990-01-01')`,
			chain.store.ledgerID, chain.policySHA256); err != nil {
			t.Fatalf("expected owl_ledger_anchor's declared INSERT privilege to allow planting the spurious row: %v", err)
		}

		result, err := chain.verify(t, ctx)
		if err == nil {
			t.Fatalf("ADR-0007 Addendum 10 D88: verify succeeded (status=%q) despite a spurious, garbage-MAC anchor at the gap sequence with a 1999-backdated tombstone", result.AnchorStatus)
		}
		if !strings.Contains(err.Error(), "D88") {
			t.Fatalf("expected the error to cite ADR-0007 Addendum 10 D88, got: %v", err)
		}
		if !strings.Contains(err.Error(), "3") {
			t.Fatalf("expected the error to name the failing sequence (3), got: %v", err)
		}
	})

	t.Run("honest_referent_still_verifies", func(t *testing.T) {
		// Positive: a clean, legitimately anchored ledger with a real
		// purge, no spurious row, no backdating, verifies clean.
		chain := newA10Chain(t, ctx)
		result, err := chain.verify(t, ctx)
		if err != nil || result.AnchorStatus != AnchorStatusVerified {
			t.Fatalf("expected a clean legitimately-anchored ledger to verify, got status=%v err=%v", result.AnchorStatus, err)
		}
	})

	t.Run("anchored_at_alone_moved_now_fails", func(t *testing.T) {
		// D88(b) in isolation: a genuine anchor row, otherwise correctly
		// MAC'd, with ONLY its anchored_at moved -- this is the assertion
		// that would fail if only D88(a) shipped (MAC verification alone
		// is not sufficient; anchored_at must be inside the MAC).
		chain := newA10Chain(t, ctx)
		superuser := connectSuperuser(t, ctx, chain.superuserDSN)
		defer superuser.Close(context.Background())
		withD34TriggersDisabled(t, ctx, superuser, func() {
			mustExec(t, ctx, superuser, `ALTER TABLE screening_ledger_anchor DISABLE TRIGGER screening_ledger_anchor_immutable`)
			mustExecArgs(t, ctx, superuser, `UPDATE screening_ledger_anchor SET anchored_at='1990-01-01' WHERE ledger_id=$1 AND sequence=2`, chain.store.ledgerID)
			mustExec(t, ctx, superuser, `ALTER TABLE screening_ledger_anchor ENABLE TRIGGER screening_ledger_anchor_immutable`)
		})

		// The forged purge attribution the moved anchor is meant to make
		// possible: purged_at rewritten to just after the (now-1990)
		// anchor 2, which the pre-D88 code would have accepted as the
		// preceding bound.
		ledgerDDLConn := chain.ledgerDDLConn(t, ctx)
		defer ledgerDDLConn.Close(context.Background())
		withD34TriggersDisabled(t, ctx, superuser, func() {
			mustExec(t, ctx, superuser, `ALTER TABLE screening_ledger_retention_tombstone DISABLE TRIGGER screening_ledger_retention_tombstone_immutable`)
			mustExecArgs(t, ctx, superuser, `UPDATE screening_ledger_retention_tombstone SET purged_at='1990-06-01' WHERE snapshot_sha256=$1`, chain.purgedSHA)
			mustExec(t, ctx, superuser, `ALTER TABLE screening_ledger_retention_tombstone ENABLE TRIGGER screening_ledger_retention_tombstone_immutable`)
		})

		result, err := chain.verify(t, ctx)
		if err == nil {
			t.Fatalf("ADR-0007 Addendum 10 D88(b): verify succeeded (status=%q) despite anchor sequence 2 having its anchored_at moved to 1990", result.AnchorStatus)
		}
		if !strings.Contains(err.Error(), "D88") {
			t.Fatalf("expected the error to cite ADR-0007 Addendum 10 D88, got: %v", err)
		}
	})
}

// connectSuperuser is a small shared helper -- several D88/D89 tests need
// a raw superuser connection to forge state directly against Postgres.
func connectSuperuser(t *testing.T, ctx context.Context, superuserDSN string) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(ctx, superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	return conn
}

func mustExecArgs(t *testing.T, ctx context.Context, conn *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := conn.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}
