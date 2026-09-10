// ADR-0007 Addendum 14 D126 (F-B, HIGH) test file (D131 item 4). D120's
// own six shapes (d120_missing_set_test.go) contain no shape in which
// the mirror holds a row the chain does not -- exactly the shape a
// planted (owl_migrator INSERT) mirror row produces, and the shape this
// file reproduces end to end through the real, unmodified
// Store.Sync/ShortfallExplainedByUnreplicatedEvents, not manufactured.
package screeningledger

import (
	"context"
	"errors"
	"testing"
)

// TestSyncRefusesWhenAPlantedMirrorRowShrinksTheApparentShortfall is
// D126/D131 item 4's planted-row state: two chain events referencing
// the shared sha are genuinely unmirrored (the missing set truly has 2
// members), but a THIRD, planted mirror row for an event_id this
// ledger's chain does not have makes the server-side mirror COUNT
// agree more closely with the chain count than the true missing set
// does -- shortfall=1, |missing|=2. The shipped (pre-Addendum-14) rule
// (missing>0) would have deferred; D126's rule (|missing|==shortfall)
// refuses.
func TestSyncRefusesWhenAPlantedMirrorRowShrinksTheApparentShortfall(t *testing.T) {
	ctx := context.Background()
	f := newD109Fixture(t, ctx, "planted")

	crash1 := f.appendCrashWindowEvent(t, "planted-crash-1")
	crash2 := f.appendCrashWindowEvent(t, "planted-crash-2")
	if f.store.IsReplicated(crash1.Event.EventID) || f.store.IsReplicated(crash2.Event.EventID) {
		t.Fatal("test construction error: expected both crash-window events to be unreplicated")
	}

	// Plant a mirror row for an event_id this ledger's local chain has
	// never heard of, referencing the SAME sha and ledger -- the shape
	// an owl_migrator INSERT (or any process writing directly to the
	// mirror) produces. This inflates the real screening_ledger_event
	// COUNT for this sha+ledger from 2 to 3, without covering either
	// crash-window event.
	if _, err := f.sink.conn.Exec(ctx,
		`INSERT INTO screening_ledger_event(event_id,ledger_id,sequence,event_sha256,previous_event_sha256,occurred_at,route,http_status,request_sha256,response_sha256,request_snapshot_sha256,response_snapshot_sha256,retention_class,expires_at,event_json)
		 VALUES ($1,$2,999,$3,'',now(),'/screen',200,'req-sha','resp-sha',$4,$4,'screening-standard',now(),'{}'::jsonb)`,
		uniqueID("d126-planted-mirror-event"), f.store.ledgerID, uniqueID("d126-planted-event-sha"), f.sha,
	); err != nil {
		t.Fatal(err)
	}

	// Confirm the construction: a genuine divergence exists (chain=4,
	// mirror=3 for this sha -- neither early-return condition in
	// ShortfallExplainedByUnreplicatedEvents fires), and the shipped
	// rule (missing>0 alone) would have deferred it while D126's rule
	// refuses.
	_, err := f.store.VerifyAnchored(ctx, f.verifyOpts())
	if err == nil {
		t.Fatal("test construction error: expected the planted-row state to fail plain VerifyAnchored")
	}
	var divergence *MirrorChainCountDivergence
	if !errors.As(err, &divergence) {
		t.Fatalf("expected a *MirrorChainCountDivergence, got: %v", err)
	}
	if divergence.ChainCount != 4 || divergence.MirrorCount != 3 {
		t.Fatalf("test construction error: expected chain=4 mirror=3, got chain=%d mirror=%d", divergence.ChainCount, divergence.MirrorCount)
	}
	shortfall := divergence.ChainCount - divergence.MirrorCount
	explained, missing, err := f.store.ShortfallExplainedByUnreplicatedEvents(ctx, f.sink, divergence)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 2 {
		t.Fatalf("test construction error: expected the missing set to have 2 members (both crash-window events), got %d: %v", len(missing), missing)
	}
	if shortfall != 1 {
		t.Fatalf("test construction error: expected shortfall=1, got %d", shortfall)
	}
	shippedRuleWouldDefer := len(missing) > 0
	if !shippedRuleWouldDefer {
		t.Fatal("test construction error: expected the shipped (missing>0) rule to defer on this state")
	}
	if explained {
		t.Fatal("ADR-0007 Addendum 14 D126: expected the FIXED discriminator to REFUSE (|missing|=2 != shortfall=1), it deferred instead")
	}

	// The end-to-end positive: Store.Sync itself aborts on this state,
	// defers nothing, and mirrors neither crash-window event.
	result, err := f.store.Sync(ctx, f.sink, f.verifyOpts(), "test-operator")
	if err == nil {
		t.Fatal("ADR-0007 Addendum 14 D126: expected Store.Sync to ABORT on the planted-row state, not defer past it")
	}
	if result.DeferredReason != "" {
		t.Fatalf("expected no deferral for the planted-row state, got %q", result.DeferredReason)
	}
	if f.store.IsReplicated(crash1.Event.EventID) || f.store.IsReplicated(crash2.Event.EventID) {
		t.Fatal("expected neither crash-window event to be mirrored/marked replicated after Sync aborted")
	}
}
