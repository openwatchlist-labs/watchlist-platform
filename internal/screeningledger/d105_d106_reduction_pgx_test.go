// ADR-0007 Addendum 12 D105/D106 test file (D112 items 1-3): P-A's
// reduction fix, reproduced independently against a real disposable
// Postgres cluster before this addendum's design was written
// (0007:11329-11411), is not re-derived here from the ADR transcript --
// these tests build it fresh, through the real, unmodified
// Store.Append/PostgresSink.Persist, exactly as that reproduction did.
package screeningledger

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// nsExpiresProbe appends one event through the real Store.Append with an
// OccurredAt carrying the given nanosecond remainder, mirrors it through
// the real PostgresSink.Persist, and returns the chain's own
// (truncated) ExpiresAt and the mirror's actually-stored value.
func nsExpiresProbe(t *testing.T, ctx context.Context, store *Store, sink *PostgresSink, ns int) (chainTruncated, mirrorStored time.Time) {
	t.Helper()
	input := testAppendInput()
	input.CorrelationID = uniqueID("corr-d105")
	input.IdempotencyKey = uniqueID("idem-d105")
	input.RequestBytes = []byte(`{"unique":"` + uniqueID("d105-req") + `"}`)
	input.ResponseBytes = []byte(`{"unique":"` + uniqueID("d105-resp") + `"}`)
	input.OccurredAt = fmt.Sprintf("2000-01-01T00:00:00.%09dZ", ns)
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
	chainExpires, err := time.Parse(time.RFC3339Nano, result.Event.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if chainExpires.Nanosecond()%1000 != 0 {
		t.Fatalf("ADR-0007 Addendum 12 D105(a): expected Event.ExpiresAt to already be microsecond-precision at creation, got %s", result.Event.ExpiresAt)
	}
	if err := sink.conn.QueryRow(ctx, `SELECT expires_at FROM screening_ledger_event WHERE event_id=$1`, result.Event.EventID).Scan(&mirrorStored); err != nil {
		t.Fatal(err)
	}
	return chainExpires.Truncate(time.Microsecond), mirrorStored
}

// naiveTextLiteralCastWouldHaveStored directly executes the PRE-D105(b)
// mirror write path -- a text literal through ::timestamptz, the
// server's own half-to-even parser -- against the raw, UNTRUNCATED
// instant, so the withdrawn mechanism's actual output is measured, not
// asserted, on every table row below. This is how "differ before" is
// checked without reverting the fix under test.
func naiveTextLiteralCastWouldHaveStored(t *testing.T, ctx context.Context, sink *PostgresSink, raw time.Time) time.Time {
	t.Helper()
	var stored time.Time
	if err := sink.conn.QueryRow(ctx, `SELECT $1::timestamptz`, raw.Format(time.RFC3339Nano)).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	return stored
}

// TestReductionAgreesAtEveryBoundaryAndTie is D112 item 1 (D105/D106),
// the replacement for the withdrawn TestPurgedAtBoundTruncationIsApplied
// Once: table-driven over both sides of the boundary AND both parities
// of the tie -- {1,499,500,501,999} plus {1500,2500,3500,4500}, the
// second set is what D106 exists for (500 and 2500 agree under the
// withdrawn mechanism because their truncated microsecond is even;
// 1500 and 3500 do not, and a suite containing only the first set
// cannot tell those apart).
func TestReductionAgreesAtEveryBoundaryAndTie(t *testing.T) {
	ctx := context.Background()
	dsn := requireMigratorDSN(t)
	sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())
	store, err := NewStore(t.TempDir(), testKey(), uniqueID("d105-boundary"))
	if err != nil {
		t.Fatal(err)
	}

	base := time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		ns                 int
		wantDifferedBefore bool
	}{
		{ns: 1, wantDifferedBefore: false},
		{ns: 499, wantDifferedBefore: false},
		{ns: 500, wantDifferedBefore: false}, // remainder=500, truncated us=0 (EVEN) -- agreed even under the withdrawn mechanism
		{ns: 501, wantDifferedBefore: true},
		{ns: 999, wantDifferedBefore: true},
		{ns: 1500, wantDifferedBefore: true},  // remainder=500, truncated us=1 (ODD) -- D106's own point
		{ns: 2500, wantDifferedBefore: false}, // truncated us=2 (EVEN)
		{ns: 3500, wantDifferedBefore: true},  // truncated us=3 (ODD)
		{ns: 4500, wantDifferedBefore: false}, // truncated us=4 (EVEN)
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("ns=%d", c.ns), func(t *testing.T) {
			chainTrunc, mirrorStored := nsExpiresProbe(t, ctx, store, sink, c.ns)
			if !chainTrunc.Equal(mirrorStored) {
				t.Fatalf("ADR-0007 Addendum 12 D105: expected the chain bound and the mirror value to be EQUAL AFTER the fix, got chain=%s mirror=%s", chainTrunc.Format(time.RFC3339Nano), mirrorStored.Format(time.RFC3339Nano))
			}

			raw := base.Add(time.Duration(c.ns) * time.Nanosecond)
			naive := naiveTextLiteralCastWouldHaveStored(t, ctx, sink, raw)
			naiveDiffered := !raw.Truncate(time.Microsecond).Equal(naive)
			if naiveDiffered != c.wantDifferedBefore {
				t.Fatalf("ADR-0007 Addendum 12 D106: expected the WITHDRAWN text-literal-cast mechanism to differ-from-Truncate=%v at ns=%d, measured %v (naive_stored=%s truncate=%s)", c.wantDifferedBefore, c.ns, naiveDiffered, naive.Format(time.RFC3339Nano), raw.Truncate(time.Microsecond).Format(time.RFC3339Nano))
			}
		})
	}
}

// TestReductionSweepHasZeroDisagreements is D112 item 1's randomised
// sweep over [1,999], seed logged, asserting the fixed mechanism (chain
// Truncate vs. the actual mirror value written through Persist) has
// ZERO disagreements -- as opposed to the withdrawn mechanism's own
// measured 499/999 (Addendum 12's own P-A reproduction).
func TestReductionSweepHasZeroDisagreements(t *testing.T) {
	ctx := context.Background()
	dsn := requireMigratorDSN(t)
	sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())
	store, err := NewStore(t.TempDir(), testKey(), uniqueID("d105-sweep"))
	if err != nil {
		t.Fatal(err)
	}

	seed := time.Now().UnixNano()
	t.Logf("ADR-0007 Addendum 12 D112 item 1: sweep seed=%d", seed)
	rng := rand.New(rand.NewSource(seed))
	const samples = 200
	seen := map[int]bool{}
	disagree := 0
	for len(seen) < samples {
		ns := rng.Intn(999) + 1
		if seen[ns] {
			continue
		}
		seen[ns] = true
		chainTrunc, mirrorStored := nsExpiresProbe(t, ctx, store, sink, ns)
		if !chainTrunc.Equal(mirrorStored) {
			disagree++
			t.Errorf("ADR-0007 Addendum 12 D105: disagreement at ns=%d: chain=%s mirror=%s", ns, chainTrunc.Format(time.RFC3339Nano), mirrorStored.Format(time.RFC3339Nano))
		}
	}
	if disagree != 0 {
		t.Fatalf("expected zero disagreements over %d sampled values (seed=%d), got %d", samples, seed, disagree)
	}
}

// TestHonestNanosecondLedgerVerifiesClean is D112 item 2: the two runs
// D105's own reproduction used -- .0000005 and .0000009 -- through the
// real Append/Persist/PurgeExpired/WriteAnchor/VerifyAnchored, both now
// verifying clean (before D105, .0000009 failed with a named
// mirror/chain divergence for a history nobody touched). Plus the
// multi-obligation shape D97 exists for, and the whole-microsecond
// positive control.
func TestHonestNanosecondLedgerVerifiesClean(t *testing.T) {
	ctx := context.Background()
	dsn := requireMigratorDSN(t)
	anchorDSN := requireAnchorDatabaseURL(t)

	run := func(t *testing.T, occurredAtSuffix string) {
		sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
		if err != nil {
			t.Fatalf("NewPostgresSink: %v", err)
		}
		defer sink.Close(context.Background())
		anchorSink, err := NewAnchorSink(ctx, anchorDSN, 10*time.Second)
		if err != nil {
			t.Fatalf("NewAnchorSink: %v", err)
		}
		defer anchorSink.Close(context.Background())
		store, err := NewStore(t.TempDir(), testKey(), uniqueID("d105-honest"))
		if err != nil {
			t.Fatal(err)
		}
		kAnchor := make([]byte, 32)
		for i := range kAnchor {
			kAnchor[i] = byte(i + 91)
		}
		policy := testPolicy(store.ledgerID)

		input := testAppendInput()
		input.CorrelationID = uniqueID("corr-honest")
		input.IdempotencyKey = uniqueID("idem-honest")
		input.RequestBytes = []byte(`{"unique":"` + uniqueID("honest-req") + `"}`)
		input.ResponseBytes = []byte(`{"unique":"` + uniqueID("honest-resp") + `"}`)
		input.OccurredAt = "2000-01-01T00:00:00" + occurredAtSuffix
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

		purged, err := store.PurgeExpired(ctx, time.Now(), "legit-operator", "legit-reason", sink)
		if err != nil {
			t.Fatalf("PurgeExpired: %v", err)
		}
		if purged != 2 {
			t.Fatalf("expected 2 snapshots purged (request+response), got %d", purged)
		}
		report, err := store.VerifyPolicy(ctx, VerifyOptions{Policy: policy, Purges: sink, allowDeferredPurgeClaims: true})
		if err != nil {
			t.Fatalf("VerifyPolicy: %v", err)
		}
		if err := anchorSink.WriteAnchor(ctx, kAnchor, store.ledgerID, int64(report.Head.Sequence), report.Head.EventSHA256, report.AuditHead.EventSHA256, int64(report.AuditHead.Sequence), testPolicySHA256(t, policy)); err != nil {
			t.Fatalf("WriteAnchor: %v", err)
		}
		result2, err := store.VerifyAnchored(ctx, AnchorOptions{
			VerifyOptions: VerifyOptions{Policy: policy, Purges: sink},
			Anchors:       sink, Provisioning: sink, KAnchor: kAnchor, PolicySHA256: testPolicySHA256(t, policy),
		})
		if err != nil || result2.AnchorStatus != AnchorStatusVerified {
			t.Fatalf("ADR-0007 Addendum 12 D105: expected an honest nanosecond-precision ledger to verify clean, got status=%v err=%v", result2.AnchorStatus, err)
		}
	}

	t.Run("ns_0000005", func(t *testing.T) { run(t, ".0000005Z") })
	t.Run("ns_0000009", func(t *testing.T) { run(t, ".0000009Z") })
	t.Run("whole_microsecond_positive_control", func(t *testing.T) { run(t, "Z") })
}

// TestHonestMultiSubMicrosecondObligationVerifiesClean is D112 item 2's
// "plus the multi-obligation shape D97 exists for": two events on one
// shared sha with different sub-microsecond OccurredAt values that
// truncate to DIFFERENT microseconds, so MAX(Event.ExpiresAt) after
// truncation is not simply "the only value" -- a single-event fixture
// cannot reach this case.
func TestHonestMultiSubMicrosecondObligationVerifiesClean(t *testing.T) {
	ctx := context.Background()
	dsn := requireMigratorDSN(t)
	anchorDSN := requireAnchorDatabaseURL(t)
	sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())
	anchorSink, err := NewAnchorSink(ctx, anchorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewAnchorSink: %v", err)
	}
	defer anchorSink.Close(context.Background())
	store, err := NewStore(t.TempDir(), testKey(), uniqueID("d105-multi"))
	if err != nil {
		t.Fatal(err)
	}
	kAnchor := make([]byte, 32)
	for i := range kAnchor {
		kAnchor[i] = byte(i + 101)
	}
	policy := testPolicy(store.ledgerID)

	sharedRequest := []byte(`{"unique":"` + uniqueID("multi-req") + `"}`)
	sharedResponse := []byte(`{"unique":"` + uniqueID("multi-resp") + `"}`)
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

	i1 := testAppendInput()
	i1.CorrelationID = uniqueID("corr-multi-1")
	i1.IdempotencyKey = uniqueID("idem-multi-1")
	i1.RequestBytes = sharedRequest
	i1.ResponseBytes = sharedResponse
	i1.OccurredAt = "2000-01-01T00:00:00.000000501Z" // truncates to microsecond 0
	i1.Retention.RetentionDays = 1
	r1, err := store.Append(i1)
	if err != nil {
		t.Fatal(err)
	}
	mirror(r1)

	i2 := testAppendInput()
	i2.CorrelationID = uniqueID("corr-multi-2")
	i2.IdempotencyKey = uniqueID("idem-multi-2")
	i2.RequestBytes = sharedRequest
	i2.ResponseBytes = sharedResponse
	i2.OccurredAt = "2000-01-01T00:00:00.000001999Z" // truncates to microsecond 1, strictly later
	i2.Retention.RetentionDays = 1
	r2, err := store.Append(i2)
	if err != nil {
		t.Fatal(err)
	}
	mirror(r2)

	if r1.Event.ExpiresAt == r2.Event.ExpiresAt {
		t.Fatalf("test construction error: expected the two truncated ExpiresAt values to differ, got %s for both", r1.Event.ExpiresAt)
	}

	purged, err := store.PurgeExpired(ctx, time.Now(), "legit-operator", "legit-reason", sink)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if purged != 2 {
		t.Fatalf("expected 2 snapshots purged, got %d", purged)
	}
	report, err := store.VerifyPolicy(ctx, VerifyOptions{Policy: policy, Purges: sink, allowDeferredPurgeClaims: true})
	if err != nil {
		t.Fatalf("VerifyPolicy: %v", err)
	}
	if err := anchorSink.WriteAnchor(ctx, kAnchor, store.ledgerID, int64(report.Head.Sequence), report.Head.EventSHA256, report.AuditHead.EventSHA256, int64(report.AuditHead.Sequence), testPolicySHA256(t, policy)); err != nil {
		t.Fatalf("WriteAnchor: %v", err)
	}
	result, err := store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: policy, Purges: sink},
		Anchors:       sink, Provisioning: sink, KAnchor: kAnchor, PolicySHA256: testPolicySHA256(t, policy),
	})
	if err != nil || result.AnchorStatus != AnchorStatusVerified {
		t.Fatalf("ADR-0007 Addendum 12 D105/D97: expected a multi-sub-microsecond-obligation purge to verify clean, got status=%v err=%v", result.AnchorStatus, err)
	}
}

// TestPersistBindsTypedExpiresAtParameter is D112 item 3: a unit-level
// assertion that Persist binds a typed time.Time for expires_at (no
// ::timestamptz cast survives on the event insert), that an unparseable
// Event.ExpiresAt produces a NAMED error rather than a value the server
// interprets, and the pgx-binary fact D105(b) depends on: a time.Time
// bound as a parameter round-trips as its OWN truncation, at every tie
// -- pinned here so a later reader does not re-derive it.
func TestPersistBindsTypedExpiresAtParameter(t *testing.T) {
	ctx := context.Background()
	dsn := requireMigratorDSN(t)
	sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())
	store, err := NewStore(t.TempDir(), testKey(), uniqueID("d105-typed"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("unparseable_ExpiresAt_is_a_named_error", func(t *testing.T) {
		input := testAppendInput()
		input.CorrelationID = uniqueID("corr-bad")
		input.IdempotencyKey = uniqueID("idem-bad")
		input.RequestBytes = []byte(`{"unique":"` + uniqueID("bad-req") + `"}`)
		input.ResponseBytes = []byte(`{"unique":"` + uniqueID("bad-resp") + `"}`)
		result, err := store.Append(input)
		if err != nil {
			t.Fatal(err)
		}
		result.Event.ExpiresAt = "not-a-timestamp"
		request, err := store.LoadSnapshot(result.Event.RequestSnapshotSHA256)
		if err != nil {
			t.Fatal(err)
		}
		response, err := store.LoadSnapshot(result.Event.ResponseSnapshotSHA256)
		if err != nil {
			t.Fatal(err)
		}
		err = sink.Persist(ctx, result.Event, request, response, ReplicationVerification{})
		if err == nil {
			t.Fatal("ADR-0007 Addendum 12 D105(b): expected Persist to refuse an unparseable Event.ExpiresAt with a named error, not send it to the server for interpretation")
		}
	})

	t.Run("pgx_binary_bind_round_trips_as_truncation_at_every_tie", func(t *testing.T) {
		base := time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC)
		ties := []int{500, 1500, 2500, 3500, 4500}
		for _, ns := range ties {
			v := base.Add(time.Duration(ns) * time.Nanosecond)
			var roundTripped time.Time
			if err := sink.conn.QueryRow(ctx, `SELECT $1::timestamptz`, v.Truncate(time.Microsecond)).Scan(&roundTripped); err != nil {
				t.Fatal(err)
			}
			if !roundTripped.Equal(v.Truncate(time.Microsecond)) {
				t.Fatalf("ADR-0007 Addendum 12 D105(b): expected a typed time.Time parameter bind to round-trip as its own Go Truncate at ns=%d, got %s want %s", ns, roundTripped.Format(time.RFC3339Nano), v.Truncate(time.Microsecond).Format(time.RFC3339Nano))
			}
		}
	})
}
