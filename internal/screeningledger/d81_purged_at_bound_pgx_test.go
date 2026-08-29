// ADR-0007 Addendum 9 D81/D85 test 5 (M-B, HIGH): purged_at gains a
// lower bound in the same clock domain the upper bound already uses --
// the anchor immediately preceding the one being verified, or, at
// genesis, the purged snapshot's own screening_ledger_snapshot.created_at.
// D70 bounded purged_at above and left it unbounded below; CAP #8
// measured a tombstone backdated to 1999, or to year 1, verifying clean.
package screeningledger

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// forgePurgedAtAndVerify neuters the tombstone guard, sets purged_at to
// the given value on chain.purgedSHA, restores the guard, and returns
// VerifyAnchored's error (nil means accepted).
func forgePurgedAtAndVerify(t *testing.T, ctx context.Context, chain d70Chain, superuser *pgx.Conn, purgedAt time.Time) error {
	t.Helper()
	withD34TriggersDisabled(t, ctx, superuser, func() {
		if _, err := superuser.Exec(ctx, `DROP TRIGGER screening_ledger_retention_tombstone_immutable ON screening_ledger_retention_tombstone`); err != nil {
			t.Fatal(err)
		}
		if _, err := superuser.Exec(ctx, `CREATE TRIGGER screening_ledger_retention_tombstone_immutable BEFORE DELETE OR UPDATE ON screening_ledger_retention_tombstone FOR EACH ROW WHEN (false) EXECUTE FUNCTION screening_ledger_reject_mutation()`); err != nil {
			t.Fatal(err)
		}
	})
	ledgerDDLConn, err := pgx.Connect(ctx, withDatabase(t, requireLedgerDDLDatabaseURL(t), chain.clone.dbName))
	if err != nil {
		t.Fatal(err)
	}
	defer ledgerDDLConn.Close(context.Background())
	if _, err := ledgerDDLConn.Exec(ctx, `UPDATE screening_ledger_retention_tombstone SET purged_at=$1 WHERE snapshot_sha256=$2`, purgedAt, chain.purgedSHA); err != nil {
		t.Fatalf("neutered-guard UPDATE of purged_at: %v", err)
	}
	chain.restoreGuardTrigger(t, ctx, superuser)

	_, verifyErr := chain.store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: chain.policy, Purges: chain.sink},
		Anchors:       chain.sink, Provisioning: chain.sink, KAnchor: chain.kAnchor, PolicySHA256: chain.policySHA256,
	})
	return verifyErr
}

// TestPurgedAtIsBoundedOnBothSides is D85 test 5: the boundary measured
// at microsecond resolution -- equal accepted, +1us rejected, -1us
// accepted (D70's existing upper bound, unregressed); and a purged_at
// before the preceding anchor's anchored_at rejected. Plus CAP #8's own
// end-to-end case: a tombstone backdated to 1999 with attribution intact
// verifies clean today and fails after.
func TestPurgedAtIsBoundedOnBothSides(t *testing.T) {
	ctx := context.Background()
	chain := newD70Chain(t, ctx)

	superuser, err := pgx.Connect(ctx, chain.superuserDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer superuser.Close(context.Background())

	// The two anchors newD70Chain wrote: genesis (before the purge) and
	// the post-purge anchor that actually attests to chain.purgedSHA's
	// purge. The preceding anchor for THIS purge's lower bound is
	// genesis's own anchored_at.
	var genesisAnchoredAt, postPurgeAnchoredAt time.Time
	if err := superuser.QueryRow(ctx, `SELECT anchored_at FROM screening_ledger_anchor WHERE ledger_id=$1 ORDER BY sequence ASC LIMIT 1`, chain.store.ledgerID).Scan(&genesisAnchoredAt); err != nil {
		t.Fatal(err)
	}
	if err := superuser.QueryRow(ctx, `SELECT anchored_at FROM screening_ledger_anchor WHERE ledger_id=$1 ORDER BY sequence DESC LIMIT 1`, chain.store.ledgerID).Scan(&postPurgeAnchoredAt); err != nil {
		t.Fatal(err)
	}
	if !postPurgeAnchoredAt.After(genesisAnchoredAt) {
		t.Fatalf("test precondition failed: expected the post-purge anchor to be after genesis, got post=%s genesis=%s", postPurgeAnchoredAt, genesisAnchoredAt)
	}

	cases := []struct {
		name      string
		purgedAt  time.Time
		wantError bool
	}{
		{name: "equal_to_anchored_at", purgedAt: postPurgeAnchoredAt, wantError: false},
		{name: "plus_1us", purgedAt: postPurgeAnchoredAt.Add(time.Microsecond), wantError: true},
		{name: "minus_1us", purgedAt: postPurgeAnchoredAt.Add(-time.Microsecond), wantError: false},
		{name: "backdated_1999", purgedAt: time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC), wantError: true},
		{name: "backdated_year_1", purgedAt: time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC), wantError: true},
		{name: "at_preceding_anchor_exactly", purgedAt: genesisAnchoredAt, wantError: true},
		{name: "just_after_preceding_anchor", purgedAt: genesisAnchoredAt.Add(time.Microsecond), wantError: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := forgePurgedAtAndVerify(t, ctx, chain, superuser, tc.purgedAt)
			if tc.wantError && err == nil {
				t.Fatalf("ADR-0007 Addendum 9 D81: expected purged_at=%s to be rejected (bound is (%s, %s]), got accepted", tc.purgedAt.Format(time.RFC3339Nano), genesisAnchoredAt.Format(time.RFC3339Nano), postPurgeAnchoredAt.Format(time.RFC3339Nano))
			}
			if !tc.wantError && err != nil {
				t.Fatalf("expected purged_at=%s to be accepted (bound is (%s, %s]), got: %v", tc.purgedAt.Format(time.RFC3339Nano), genesisAnchoredAt.Format(time.RFC3339Nano), postPurgeAnchoredAt.Format(time.RFC3339Nano), err)
			}
		})
	}
}

// TestPurgedAtGenesisFallbackUsesSnapshotCreatedAt is D81's genesis case:
// where no anchor precedes the one being verified (this ledger's very
// first anchor), the lower bound falls back to the purged snapshot's own
// screening_ledger_snapshot.created_at -- a purge cannot predate the
// thing it purges.
func TestPurgedAtGenesisFallbackUsesSnapshotCreatedAt(t *testing.T) {
	ctx := context.Background()
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	anchorDSN := requireAnchorDatabaseURL(t)

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	cloneMigratorDSN := withDatabase(t, migratorDSN, clone.dbName)
	cloneAnchorDSN := withDatabase(t, anchorDSN, clone.dbName)

	directory := t.TempDir()
	store, err := NewStore(directory, testKey(), uniqueID("sec7-d81-genesis"))
	if err != nil {
		t.Fatal(err)
	}
	input := testAppendInput()
	input.CorrelationID = uniqueID("corr")
	input.IdempotencyKey = uniqueID("idem")
	input.RequestBytes = []byte(`{"unique":"` + uniqueID("req") + `"}`)
	input.ResponseBytes = []byte(`{"unique":"` + uniqueID("resp") + `"}`)
	input.OccurredAt = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	input.Retention.RetentionDays = 1
	result, err := store.Append(input)
	if err != nil {
		t.Fatal(err)
	}

	kAnchor := make([]byte, 32)
	for i := range kAnchor {
		kAnchor[i] = byte(i + 11)
	}

	sink, err := NewPostgresSink(ctx, cloneMigratorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())

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

	if _, err := store.AppendAudit("d81-setup", "", "", "", nil); err != nil {
		t.Fatal(err)
	}

	// The purge happens BEFORE any anchor ever exists for this ledger --
	// the genesis anchor, written below, is the ONLY anchor and is
	// therefore the one attesting to this purge, with no predecessor.
	purgedCount, err := store.PurgeExpired(ctx, time.Now(), "legit-operator", "legit-reason", sink)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if purgedCount != 2 {
		t.Fatalf("expected 2 snapshots purged, got %d", purgedCount)
	}

	policy := testPolicy(store.ledgerID)
	policySHA256 := testPolicySHA256(t, policy)
	genesisReport, err := store.VerifyPolicy(ctx, VerifyOptions{Policy: policy, Purges: sink, allowDeferredPurgeClaims: true})
	if err != nil {
		t.Fatalf("VerifyPolicy: %v", err)
	}

	anchorSink, err := NewAnchorSink(ctx, cloneAnchorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewAnchorSink: %v", err)
	}
	defer anchorSink.Close(context.Background())
	if err := anchorSink.WriteAnchor(ctx, kAnchor, store.ledgerID, int64(genesisReport.Head.Sequence), genesisReport.Head.EventSHA256, genesisReport.AuditHead.EventSHA256, int64(genesisReport.AuditHead.Sequence), policySHA256); err != nil {
		t.Fatalf("WriteAnchor (genesis): %v", err)
	}

	// Baseline: clean and verified (the real front door -- D45's own
	// positive rule -- and no preceding anchor exists for it).
	if r, err := store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: policy, Purges: sink},
		Anchors:       sink, Provisioning: sink, KAnchor: kAnchor, PolicySHA256: policySHA256, AllowGenesis: true,
	}); err != nil || r.AnchorStatus != AnchorStatusVerified {
		t.Fatalf("expected a clean verified genesis anchor after a legitimate purge with no preceding anchor, got status=%v err=%v", r.AnchorStatus, err)
	}

	var createdAt time.Time
	if err := sink.conn.QueryRow(ctx, `SELECT created_at FROM screening_ledger_snapshot WHERE snapshot_sha256=$1`, result.Event.RequestSnapshotSHA256).Scan(&createdAt); err != nil {
		t.Fatal(err)
	}

	superuser, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer superuser.Close(context.Background())

	chain := d70Chain{
		store: store, sink: sink, kAnchor: kAnchor, policy: policy, policySHA256: policySHA256,
		purgedSHA: result.Event.RequestSnapshotSHA256, clone: clone,
		scriptPath: d62ScriptPath(t), superuserDSN: clone.superuserDSN,
	}

	t.Run("backdated_before_snapshot_created_at_rejected", func(t *testing.T) {
		err := forgePurgedAtAndVerify(t, ctx, chain, superuser, createdAt.Add(-time.Hour))
		if err == nil {
			t.Fatalf("ADR-0007 Addendum 9 D81: expected a purged_at before the purged snapshot's own created_at (%s) to be rejected with no preceding anchor to bound it", createdAt)
		}
	})
	t.Run("just_after_snapshot_created_at_accepted", func(t *testing.T) {
		err := forgePurgedAtAndVerify(t, ctx, chain, superuser, createdAt.Add(time.Microsecond))
		if err != nil {
			t.Fatalf("expected a purged_at just after the purged snapshot's created_at (%s) to be accepted, got: %v", createdAt, err)
		}
	})
}
