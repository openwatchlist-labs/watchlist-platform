// ADR-0007 Addendum 12 D107 test file (D112 item 4): P-E's exact
// reproduction, reproduced independently against a real disposable
// Postgres cluster before this addendum's design was written
// (0007:11536-11631), is not re-derived here from the ADR transcript --
// these tests build it fresh, through the real, unmodified
// PostgresSink.RecordPurge/PurgeExpired/Store.PurgeExpired, exactly as
// that reproduction did.
package screeningledger

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestServerFloorRefusesWhenTheChainAndMirrorDisagree is D112 item 4:
// the P-E state -- one snapshot, one expired obligation mirrored, one
// live obligation NOT mirrored -- asserting RecordPurge records it
// TODAY (before D107) and refuses after, naming both aggregates, and
// that Store.PurgeExpired refuses in both. Table-driven over all four
// lying directions (count and max, each under- and overstated), each a
// refusal, plus the three required positives, plus both overloads.
func TestServerFloorRefusesWhenTheChainAndMirrorDisagree(t *testing.T) {
	ctx := context.Background()

	// --- The P-E case itself: one snapshot, one expired obligation
	// mirrored, one live (2046) obligation NOT mirrored. ---
	t.Run("P-E_unmirrored_live_obligation_refused", func(t *testing.T) {
		dsn := requireMigratorDSN(t)
		sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
		if err != nil {
			t.Fatalf("NewPostgresSink: %v", err)
		}
		defer sink.Close(context.Background())
		store, err := NewStore(t.TempDir(), testKey(), uniqueID("d107-pe"))
		if err != nil {
			t.Fatal(err)
		}

		sharedRequest := []byte(`{"unique":"` + uniqueID("d107-pe-req") + `"}`)
		sharedResponse := []byte(`{"unique":"` + uniqueID("d107-pe-resp") + `"}`)
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

		expired := testAppendInput()
		expired.CorrelationID = uniqueID("corr-pe-expired")
		expired.IdempotencyKey = uniqueID("idem-pe-expired")
		expired.RequestBytes = sharedRequest
		expired.ResponseBytes = sharedResponse
		expired.OccurredAt = "2000-01-01T00:00:00Z"
		expired.Retention.RetentionDays = 1
		expiredResult, err := store.Append(expired)
		if err != nil {
			t.Fatal(err)
		}
		mirror(expiredResult)
		sha := expiredResult.Event.RequestSnapshotSHA256

		// Now, the honest chain-authenticated obligation (before the
		// live event exists) matches the mirror -- an honest RecordPurge
		// call succeeds.
		obligations, err := computeSnapshotObligations([]Event{expiredResult.Event})
		if err != nil {
			t.Fatal(err)
		}
		recorded, err := sink.RecordPurge(ctx, []string{sha}, obligations, store.ledgerID, "legit-operator", "legit-reason")
		if err != nil {
			t.Fatalf("honest RecordPurge (no live obligation yet): %v", err)
		}
		if len(recorded) != 1 {
			t.Fatalf("expected the honest, fully-expired snapshot to be recorded, got %v", recorded)
		}

		// P-E's own construction, on a FRESH shared snapshot (this one
		// is now tombstoned): live obligation appended locally, NEVER
		// mirrored.
		sharedRequest2 := []byte(`{"unique":"` + uniqueID("d107-pe2-req") + `"}`)
		sharedResponse2 := []byte(`{"unique":"` + uniqueID("d107-pe2-resp") + `"}`)
		expired2 := testAppendInput()
		expired2.CorrelationID = uniqueID("corr-pe2-expired")
		expired2.IdempotencyKey = uniqueID("idem-pe2-expired")
		expired2.RequestBytes = sharedRequest2
		expired2.ResponseBytes = sharedResponse2
		expired2.OccurredAt = "2000-01-01T00:00:00Z"
		expired2.Retention.RetentionDays = 1
		expired2Result, err := store.Append(expired2)
		if err != nil {
			t.Fatal(err)
		}
		mirror(expired2Result)
		sha2 := expired2Result.Event.RequestSnapshotSHA256

		live := testAppendInput()
		live.CorrelationID = uniqueID("corr-pe2-live")
		live.IdempotencyKey = uniqueID("idem-pe2-live")
		live.RequestBytes = sharedRequest2
		live.ResponseBytes = sharedResponse2
		live.OccurredAt = time.Now().UTC().Format(time.RFC3339Nano)
		live.Retention.RetentionDays = 90000 // ~2046, matching P-E's own transcript
		liveResult, err := store.Append(live)
		if err != nil {
			t.Fatal(err)
		}
		// Deliberately NOT mirrored -- the crash/backlog window P-E models.

		chainObligations, err := computeSnapshotObligations([]Event{expired2Result.Event, liveResult.Event})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("A12PROBE P-E case: chain now has count=%d max=%s (one obligation UNMIRRORED)", chainObligations[sha2].count, chainObligations[sha2].max.Format(time.RFC3339Nano))
		recorded2, err := sink.RecordPurge(ctx, []string{sha2}, chainObligations, store.ledgerID, "legit-operator", "legit-reason")
		if err == nil {
			t.Fatalf("ADR-0007 Addendum 12 D107: expected RecordPurge to REFUSE the P-E case (unmirrored live obligation), got recorded=%v", recorded2)
		}
		if !strings.Contains(err.Error(), "D116") {
			t.Fatalf("expected the refusal to cite ADR-0007 Addendum 13 D116, got: %v", err)
		}

		// Store.PurgeExpired (the Go orchestration) refuses too -- the
		// chain-side ALL-expired-over-the-chain check itself already
		// finds the live obligation and never even calls RecordPurge for
		// sha2, so nothing is recorded for it either way.
		purgedCount, err := store.PurgeExpired(ctx, time.Now(), "legit-operator", "legit-reason", TenancyExclusive, sink)
		if err != nil {
			t.Fatalf("Store.PurgeExpired: %v", err)
		}
		var tombstoned int
		if err := sink.conn.QueryRow(ctx, `SELECT count(*) FROM screening_ledger_retention_tombstone WHERE snapshot_sha256=$1`, sha2).Scan(&tombstoned); err != nil {
			t.Fatal(err)
		}
		if tombstoned != 0 {
			t.Fatalf("expected sha2 to remain untombstoned (live obligation unmirrored), got %d tombstone rows; Store.PurgeExpired purged=%d", tombstoned, purgedCount)
		}
	})

	// --- The four lying directions, all against the array-form overload. ---
	t.Run("lying_directions", func(t *testing.T) {
		dsn := requireMigratorDSN(t)
		sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
		if err != nil {
			t.Fatalf("NewPostgresSink: %v", err)
		}
		defer sink.Close(context.Background())
		store, err := NewStore(t.TempDir(), testKey(), uniqueID("d107-lying"))
		if err != nil {
			t.Fatal(err)
		}

		sharedRequest := []byte(`{"unique":"` + uniqueID("d107-lying-req") + `"}`)
		sharedResponse := []byte(`{"unique":"` + uniqueID("d107-lying-resp") + `"}`)
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

		var events []Event
		for i, tag := range []string{"e1", "e2"} {
			input := testAppendInput()
			input.CorrelationID = uniqueID("corr-lying-" + tag)
			input.IdempotencyKey = uniqueID("idem-lying-" + tag)
			input.RequestBytes = sharedRequest
			input.ResponseBytes = sharedResponse
			input.OccurredAt = "2000-01-01T00:00:00Z"
			input.Retention.RetentionDays = 1 + i
			result, err := store.Append(input)
			if err != nil {
				t.Fatal(err)
			}
			mirror(result)
			events = append(events, result.Event)
		}
		sha := events[0].RequestSnapshotSHA256

		honest, err := computeSnapshotObligations(events)
		if err != nil {
			t.Fatal(err)
		}
		honestObligation := honest[sha]
		t.Logf("A12PROBE honest obligation: count=%d max=%s", honestObligation.count, honestObligation.max.Format(time.RFC3339Nano))

		cases := []struct {
			name  string
			count int
			max   time.Time
		}{
			{"understates_count", honestObligation.count - 1, honestObligation.max},
			{"overstates_count", honestObligation.count + 1, honestObligation.max},
			{"understates_max", honestObligation.count, honestObligation.max.Add(-24 * time.Hour)},
			{"overstates_max", honestObligation.count, honestObligation.max.Add(24 * time.Hour)},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				lying := map[string]snapshotObligation{sha: {count: c.count, max: c.max}}
				recorded, err := sink.RecordPurge(ctx, []string{sha}, lying, store.ledgerID, "operator", "reason")
				if err == nil {
					t.Fatalf("ADR-0007 Addendum 12 D107: expected a lying %s to be REFUSED, got recorded=%v", c.name, recorded)
				}
				if !strings.Contains(err.Error(), "D116") {
					t.Fatalf("expected the refusal to cite ADR-0007 Addendum 13 D116, got: %v", err)
				}
				t.Logf("A12PROBE lying caller: %s -> REFUSED: %v", c.name, err)
			})
		}

		// Positive: the HONEST obligation for this same snapshot reaches
		// D98's eligibility predicate rather than being refused by
		// D107's corroboration -- both e1 and e2 are long expired
		// relative to "now" (both dated 2000-01-01), so an honest
		// caller's purge succeeds.
		recorded, err := sink.RecordPurge(ctx, []string{sha}, honest, store.ledgerID, "operator", "reason")
		if err != nil {
			t.Fatalf("honest RecordPurge should reach D98's eligibility check, not fail on corroboration: %v", err)
		}
		if len(recorded) != 1 {
			t.Fatalf("expected the honest, fully-expired snapshot to be recorded, got %v", recorded)
		}
	})

	// --- Positive: a legitimate purge still succeeds. ---
	t.Run("legitimate_purge_still_succeeds", func(t *testing.T) {
		dsn := requireMigratorDSN(t)
		sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
		if err != nil {
			t.Fatalf("NewPostgresSink: %v", err)
		}
		defer sink.Close(context.Background())
		store, err := NewStore(t.TempDir(), testKey(), uniqueID("d107-legit"))
		if err != nil {
			t.Fatal(err)
		}
		purgedCount, err := store.PurgeExpired(ctx, time.Now(), "legit-operator", "legit-reason", TenancyExclusive, sink)
		if err != nil {
			t.Fatalf("Store.PurgeExpired on a fresh, empty ledger: %v", err)
		}
		if purgedCount != 0 {
			t.Fatalf("expected 0 (nothing to purge on a fresh ledger), got %d", purgedCount)
		}

		input := testAppendInput()
		input.CorrelationID = uniqueID("corr-legit")
		input.IdempotencyKey = uniqueID("idem-legit")
		input.RequestBytes = []byte(`{"unique":"` + uniqueID("legit-req") + `"}`)
		input.ResponseBytes = []byte(`{"unique":"` + uniqueID("legit-resp") + `"}`)
		input.OccurredAt = "2000-01-01T00:00:00Z"
		input.Retention.RetentionDays = 1
		result, err := store.Append(input)
		if err != nil {
			t.Fatal(err)
		}
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
		purgedCount, err = store.PurgeExpired(ctx, time.Now(), "legit-operator", "legit-reason", TenancyExclusive, sink)
		if err != nil {
			t.Fatalf("Store.PurgeExpired: %v", err)
		}
		if purgedCount != 2 {
			t.Fatalf("expected 2 (request+response), got %d", purgedCount)
		}
	})

	// --- Positive: three consecutive legitimate purges are idempotent. ---
	t.Run("three_consecutive_purges_idempotent", func(t *testing.T) {
		dsn := requireMigratorDSN(t)
		sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
		if err != nil {
			t.Fatalf("NewPostgresSink: %v", err)
		}
		defer sink.Close(context.Background())
		store, err := NewStore(t.TempDir(), testKey(), uniqueID("d107-idempotent"))
		if err != nil {
			t.Fatal(err)
		}
		input := testAppendInput()
		input.CorrelationID = uniqueID("corr-idempotent")
		input.IdempotencyKey = uniqueID("idem-idempotent")
		input.RequestBytes = []byte(`{"unique":"` + uniqueID("idempotent-req") + `"}`)
		input.ResponseBytes = []byte(`{"unique":"` + uniqueID("idempotent-resp") + `"}`)
		input.OccurredAt = "2000-01-01T00:00:00Z"
		input.Retention.RetentionDays = 1
		result, err := store.Append(input)
		if err != nil {
			t.Fatal(err)
		}
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
		counts := make([]int, 3)
		for i := range counts {
			n, err := store.PurgeExpired(ctx, time.Now(), "legit-operator", "legit-reason", TenancyExclusive, sink)
			if err != nil {
				t.Fatalf("run %d: %v", i, err)
			}
			counts[i] = n
		}
		if counts[0] != 2 || counts[1] != 0 || counts[2] != 0 {
			t.Fatalf("expected [2,0,0], got %v", counts)
		}
	})

	// --- Positive: a snapshot referenced by no event at all is still not eligible. ---
	t.Run("vacuous_not_eligible", func(t *testing.T) {
		dsn := requireMigratorDSN(t)
		sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
		if err != nil {
			t.Fatalf("NewPostgresSink: %v", err)
		}
		defer sink.Close(context.Background())
		// ADR-0007 Addendum 13 D116: p_ledger_id is now a checked claim --
		// it must resolve to a ledger with rows, refused by name
		// otherwise. A wholly phantom ledger_id (never written) would
		// now be refused at that check before ever reaching the sha
		// corroboration this sub-test means to exercise, so a REAL
		// ledger with one unrelated event is seeded first; phantomSHA
		// itself is still referenced by nothing.
		realLedgerID := uniqueID("d107-vacuous-real-ledger")
		if _, err := sink.conn.Exec(ctx,
			`INSERT INTO screening_ledger_event(event_id,ledger_id,sequence,event_sha256,previous_event_sha256,occurred_at,route,http_status,request_sha256,response_sha256,request_snapshot_sha256,response_snapshot_sha256,retention_class,expires_at,event_json)
			 VALUES ($1,$2,1,$3,'',now(),'/screen',200,'req-sha','resp-sha',$4,$4,'screening-standard',now()+interval '1 day','{}'::jsonb)`,
			uniqueID("d107-vacuous-real-event"), realLedgerID, uniqueID("d107-vacuous-real-event-sha"), uniqueID("d107-vacuous-real-sha"),
		); err != nil {
			t.Fatalf("seed a real, unrelated event so realLedgerID has rows: %v", err)
		}
		phantomSHA := "0000000000000000000000000000000000000000000000000000000000001"
		recorded, err := sink.RecordPurge(ctx, []string{phantomSHA}, map[string]snapshotObligation{}, realLedgerID, "operator", "reason")
		if err != nil {
			t.Fatal(err)
		}
		if len(recorded) != 0 {
			t.Fatalf("ADR-0007 Addendum 11 D98: a snapshot sha referenced by no event at all must never be recorded, got %v", recorded)
		}
	})

	// --- Both overloads: the time-floor overload's own corroboration. ---
	// ADR-0007 Addendum 13 D116 row (b) (F-B's own time-floor shape): a
	// ledger_id with zero mirror rows is now refused by name regardless
	// of what it claims -- including the vacuous (0, NULL) claim this
	// test used to require ACCEPTED, which is exactly the shape F-B rode
	// (a foreign, never-written ledger_id truthfully claiming "nothing",
	// satisfying the leading refusal for a sha it never asked about).
	// D122 item 6's own row (b): "time-floor, absent ledger_id + (0,NULL)
	// -> records today and refuses after."
	t.Run("time_floor_overload_refuses_a_rowless_ledger_any_claim", func(t *testing.T) {
		dsn := requireMigratorDSN(t)
		sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
		if err != nil {
			t.Fatalf("NewPostgresSink: %v", err)
		}
		defer sink.Close(context.Background())
		ledgerID := uniqueID("d107-timefloor-ledger")
		// Lying: this ledger has 0 mirror rows, not 1.
		err = sink.PurgeExpired(ctx, ledgerID, 1, time.Now(), "operator", "reason")
		if err == nil {
			t.Fatal("ADR-0007 Addendum 13 D116: expected the time-floor overload to refuse a lying total (this ledger has 0 mirror rows, not 1)")
		}
		if !strings.Contains(err.Error(), "D116") {
			t.Fatalf("expected the refusal to cite ADR-0007 Addendum 13 D116, got: %v", err)
		}
		// The formerly-honest (0, NULL) claim -- F-B's own bypass shape --
		// is refused too, because ledgerID itself has never written a row.
		err = sink.PurgeExpired(ctx, ledgerID, 0, time.Time{}, "operator", "reason")
		if err == nil {
			t.Fatal("ADR-0007 Addendum 13 D116: expected a (0, NULL) claim against a ledger with zero mirror rows to be refused (F-B's own bypass shape), got success")
		}
		if !strings.Contains(err.Error(), "D116") {
			t.Fatalf("expected the refusal to cite ADR-0007 Addendum 13 D116, got: %v", err)
		}
	})

	// --- Positive: a genuinely honest total against a REAL, populated
	// ledger still succeeds -- the non-vacuity check must not refuse a
	// legitimate purge, only a claim from a ledger that never wrote
	// anything. ---
	t.Run("time_floor_overload_accepts_an_honest_total_against_a_real_ledger", func(t *testing.T) {
		dsn := requireMigratorDSN(t)
		sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
		if err != nil {
			t.Fatalf("NewPostgresSink: %v", err)
		}
		defer sink.Close(context.Background())
		realLedgerID := uniqueID("d107-timefloor-real-ledger")
		expired := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
		sha := uniqueID("d107-timefloor-real-sha")
		if _, err := sink.conn.Exec(ctx,
			`INSERT INTO screening_ledger_snapshot(snapshot_sha256,kind,created_at,expires_at,retention_class,envelope_json) VALUES ($1,'request',$2::timestamptz,$2::timestamptz,'screening-standard','{}'::jsonb)`,
			sha, expired,
		); err != nil {
			t.Fatalf("seed snapshot: %v", err)
		}
		if _, err := sink.conn.Exec(ctx,
			`INSERT INTO screening_ledger_event(event_id,ledger_id,sequence,event_sha256,previous_event_sha256,occurred_at,route,http_status,request_sha256,response_sha256,request_snapshot_sha256,response_snapshot_sha256,retention_class,expires_at,event_json)
			 VALUES ($1,$2,1,$3,'',$4::timestamptz,'/screen',200,'req-sha','resp-sha',$5,$5,'screening-standard',$4::timestamptz,'{}'::jsonb)`,
			uniqueID("d107-timefloor-real-event"), realLedgerID, uniqueID("d107-timefloor-real-event-sha"), expired, sha,
		); err != nil {
			t.Fatalf("seed event: %v", err)
		}
		// The true GLOBAL total (this test's own one row, plus whatever
		// else the shared database carries) is queried live rather than
		// assumed to be exactly 1, matching the same live-query fix
		// postgres_pgx_test.go's own direct time-floor tests use.
		var trueCount int64
		var trueMax time.Time
		if err := sink.conn.QueryRow(ctx, `SELECT count(*), max(expires_at) FROM screening_ledger_event`).Scan(&trueCount, &trueMax); err != nil {
			t.Fatalf("query the true global aggregate: %v", err)
		}
		if err := sink.PurgeExpired(ctx, realLedgerID, int(trueCount), trueMax, "operator", "reason"); err != nil {
			t.Fatalf("expected an honest total against a real, populated ledger to be accepted, got: %v", err)
		}
	})
}
