// ADR-0007 Addendum 13 D120 test file (D122 item 10's reporting
// assertion): "SyncedEventCount survives the deferred-then-failed
// path." Needs a live Postgres, unlike d120_missing_set_test.go's
// DSN-free discriminator suite, because the deferred-then-failed path
// only exists once rows have genuinely been written into
// screening_ledger_event -- a table an immutability trigger then makes
// permanent -- and a second, unrelated divergence is what makes the
// SAME re-verification fail anyway.
//
// The scenario is built deterministically, on top of the existing
// d109Fixture (already established, already verified clean before this
// test touches it), using a fact confirmed by direct construction
// rather than assumed: forSnapshot (anchor.go) checks the mirror/chain
// ROW COUNT before it ever checks MAX(expires_at), so a mirror row that
// already exists but carries a wrong expires_at is invisible to
// VerifyAnchored as long as a genuine count shortfall is ALSO present
// for the same snapshot (the count check returns first, forSnapshot,
// anchor.go:599 vs :602). Fixing the count shortfall -- Sync's own
// mirroring loop does exactly this -- makes the SAME snapshot's
// pre-existing max corruption visible on the very next VerifyAnchored
// call: a second, unrelated, and correctly-typed failure on the
// deferred-then-failed path, built with no goroutines, no timing and no
// retry loop. Two crash-window events are appended after the fixture's
// clean baseline: one with a directly-inserted wrong-valued mirror row
// (marked replicated, so Sync's loop leaves it alone), one genuinely
// unmirrored (the shortfall Sync's loop actually repairs).
package screeningledger

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestSyncedEventCountSurvivesTheDeferredThenFailedPath is D122 item
// 10's reporting assertion, and CLAUDE.md rule 5's failing-test-first
// requirement applied to sync.go's own fix: against the pre-fix
// return (SyncResult{VerifyResult: verifyResult, DeferredReason:
// deferredReason}, dropping SyncedEventCount to its zero value), this
// test fails -- ground truth is 1 row genuinely mirrored into an
// immutable-by-trigger table, but Sync reports 0. Against the fix
// (sync.go's deferred-then-failed return also carrying
// SyncedEventCount: synced), it passes.
func TestSyncedEventCountSurvivesTheDeferredThenFailedPath(t *testing.T) {
	ctx := context.Background()
	f := newD109Fixture(t, ctx, "synccount")

	// crashWrong: appended after the clean baseline, mirrored directly
	// (bypassing Persist, since screening_ledger_event rows are
	// append-only and an UPDATE on an already-correct row would be
	// rejected by the row trigger) with a deliberately WRONG
	// expires_at, then marked replicated -- it has a mirror row, so it
	// will NOT be in Sync's "missing" set and will NOT be retried by
	// Sync's loop.
	crashWrong := f.appendCrashWindowEvent(t, "synccount-wrongmax")
	wrongExpires := time.Now().Add(999999 * time.Hour)
	if _, err := f.sink.conn.Exec(ctx,
		`INSERT INTO screening_ledger_event(event_id,ledger_id,sequence,event_sha256,previous_event_sha256,occurred_at,route,http_status,request_sha256,response_sha256,request_snapshot_sha256,response_snapshot_sha256,retention_class,expires_at,event_json)
		 VALUES ($1,$2,$3,$4,$5,$6::timestamptz,$7,$8,$9,$10,$11,$12,$13,$14,'{}'::jsonb)`,
		crashWrong.Event.EventID, crashWrong.Event.LedgerID, int64(crashWrong.Event.Sequence), crashWrong.Event.EventSHA256, crashWrong.Event.PreviousEventSHA256,
		crashWrong.Event.OccurredAt, crashWrong.Event.Route, crashWrong.Event.HTTPStatus, crashWrong.Event.RequestSHA256, crashWrong.Event.ResponseSHA256,
		crashWrong.Event.RequestSnapshotSHA256, crashWrong.Event.ResponseSnapshotSHA256, crashWrong.Event.RetentionClass, wrongExpires,
	); err != nil {
		t.Fatalf("inserting crashWrong's deliberately-wrong mirror row: %v", err)
	}
	if err := f.store.MarkReplicated(crashWrong.Event.EventID, ""); err != nil {
		t.Fatal(err)
	}

	// crashMissing: appended after the clean baseline, genuinely NOT
	// mirrored at all -- the accounted-for shortfall D109 exists to
	// defer and repair.
	crashMissing := f.appendCrashWindowEvent(t, "synccount-missing")
	if f.store.IsReplicated(crashMissing.Event.EventID) {
		t.Fatal("test construction error: expected crashMissing to be unreplicated")
	}

	// Confirm the FIRST (pre-Sync) failure is exactly the typed count
	// divergence -- crashWrong's max corruption must still be masked by
	// crashMissing's count shortfall.
	_, err := f.store.VerifyAnchored(ctx, f.verifyOpts())
	if err == nil {
		t.Fatal("test construction error: expected the pre-Sync state to fail VerifyAnchored")
	}
	var divergence *MirrorChainCountDivergence
	if !errors.As(err, &divergence) {
		t.Fatalf("test construction error: expected the FIRST failure to be a *MirrorChainCountDivergence (count check fires before the max check can see crashWrong's corruption), got: %v", err)
	}

	var mirrorRowCountBefore int
	if err := f.sink.conn.QueryRow(ctx, `SELECT count(*) FROM screening_ledger_event WHERE event_id=$1`, crashMissing.Event.EventID).Scan(&mirrorRowCountBefore); err != nil {
		t.Fatal(err)
	}
	if mirrorRowCountBefore != 0 {
		t.Fatalf("test construction error: expected crashMissing's event_id to have zero mirror rows before Sync, got %d", mirrorRowCountBefore)
	}

	result, syncErr := f.store.Sync(ctx, f.sink, f.verifyOpts(), "test-operator")

	var mirrorRowCountAfter int
	if err := f.sink.conn.QueryRow(ctx, `SELECT count(*) FROM screening_ledger_event WHERE event_id=$1`, crashMissing.Event.EventID).Scan(&mirrorRowCountAfter); err != nil {
		t.Fatal(err)
	}

	if syncErr == nil {
		t.Fatal("test construction error: expected the SECOND (post-mirror) VerifyAnchored to fail for the unrelated max-corruption reason -- got a clean Sync instead, scenario did not reproduce")
	}
	var divergence2 *MirrorChainCountDivergence
	if errors.As(syncErr, &divergence2) {
		t.Fatalf("test construction error: expected the post-mirror failure to be the UNRELATED max-mismatch error, not another count divergence: %v", syncErr)
	}
	if result.DeferredReason == "" {
		t.Fatal("test construction error: expected Sync to have recorded a deferral before hitting the second, unrelated failure")
	}
	// Ground truth: crashMissing's row was genuinely, permanently
	// written into screening_ledger_event before the second
	// VerifyAnchored ever ran -- the row-immutability trigger means it
	// cannot be un-written by the failure that follows.
	if mirrorRowCountAfter != 1 {
		t.Fatalf("test construction error: expected crashMissing's row to have been genuinely mirrored (ground truth), got count=%d", mirrorRowCountAfter)
	}

	// THE ASSERTION THIS TEST EXISTS TO MAKE (D122 item 10).
	if result.SyncedEventCount != 1 {
		t.Fatalf("ADR-0007 Addendum 13 D120: SyncedEventCount must survive the deferred-then-failed path -- ground truth is 1 row genuinely mirrored into an immutable table (verified above), but Sync reported SyncedEventCount=%d", result.SyncedEventCount)
	}
}
