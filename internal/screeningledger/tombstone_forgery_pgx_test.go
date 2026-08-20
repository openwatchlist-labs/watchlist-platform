// ADR-0007 Addendum 2 D27/D28 (F-D, MEDIUM): the CAP's exact live
// finding, reproduced as a committed regression against a real Postgres.
// CAP §7.7: "as owl_migrator, INSERT INTO
// screening_ledger_retention_tombstone(...) -- ALLOWED", forging a
// tombstone for a snapshot never actually purged, which made
// IsPurgeRecorded return true for it and skipped the last key-dependent
// check the event chain still had. D27 moves the table to owl_ledger_ddl
// ownership and makes the write path a SECURITY DEFINER function that
// re-validates the expiry floor server-side; D28 makes the local purge
// path refuse without an independent recorder and resolves the
// legal-holds divergence (local narrows, server floors).
package screeningledger

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestTombstoneDirectInsertForgeryBlocked is D27's required reproduction:
// confirm today, against the real committed schema, that the CAP's exact
// forgery attempt -- a direct INSERT into screening_ledger_retention_
// tombstone as owl_migrator -- now fails, rather than succeeding as it
// did before this fix.
func TestTombstoneDirectInsertForgeryBlocked(t *testing.T) {
	migratorDSN := requireMigratorDSN(t)
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, migratorDSN)
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	defer conn.Close(context.Background())

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`INSERT INTO screening_ledger_retention_tombstone(snapshot_sha256,purged_at,operator,reason) VALUES ($1,now(),'adversary','never actually purged')`,
		uniqueID("sec7-forged-tombstone"),
	)
	if err == nil {
		t.Fatal("CAP §7.7's exact forgery: owl_migrator INSERT into screening_ledger_retention_tombstone succeeded; D27's ownership/definer-function fix is not holding")
	}
	if code := pgErrorCode(err); code != "42501" {
		t.Fatalf("expected SQLSTATE 42501 (insufficient_privilege), got %q: %v", code, err)
	}
}

// TestRecordPurgeFloorsAgainstServerExpiry is D28's server-floors half:
// the definer function must not tombstone a snapshot that is not
// actually expired, even when the caller (the local eligible-candidate
// set) claims it is. Models a caller with a skewed or wrong local clock,
// or an adversarial caller passing sha256 values that were never
// determined eligible at all.
func TestRecordPurgeFloorsAgainstServerExpiry(t *testing.T) {
	sink, ctx := newTestSink(t)
	dsn := requireMigratorDSN(t)
	verify := verifyConn(t, ctx, dsn)
	defer verify.Close(ctx)

	expiredSHA := uniqueID("snapshot-expired")
	notExpiredSHA := uniqueID("snapshot-not-expired")
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	now := time.Now()

	for sha, expires := range map[string]string{expiredSHA: past, notExpiredSHA: future} {
		if _, err := verify.Exec(ctx,
			`INSERT INTO screening_ledger_snapshot(snapshot_sha256,kind,created_at,expires_at,retention_class,envelope_json) VALUES ($1,'request',$2::timestamptz,$3::timestamptz,'screening-standard','{}'::jsonb)`,
			sha, past, expires,
		); err != nil {
			t.Fatalf("seed snapshot %s: %v", sha, err)
		}
		// ADR-0007 Addendum 3 D32: the expiry floor now reads
		// screening_ledger_event.expires_at (joined through
		// request_snapshot_sha256/response_snapshot_sha256), not
		// screening_ledger_snapshot.expires_at -- a referencing event row
		// is required for the predicate to find this snapshot at all.
		eventID := uniqueID("event-for-" + sha)
		if _, err := verify.Exec(ctx,
			`INSERT INTO screening_ledger_event(event_id,ledger_id,sequence,event_sha256,previous_event_sha256,occurred_at,route,http_status,request_sha256,response_sha256,request_snapshot_sha256,response_snapshot_sha256,retention_class,expires_at,event_json)
			 VALUES ($1,$2,1,$3,'',$4::timestamptz,'/screen',200,'req-sha','resp-sha',$5,$5,'screening-standard',$6::timestamptz,'{}'::jsonb)`,
			eventID, uniqueID("ledger-for-"+sha), uniqueID("event-sha-for-"+sha), past, sha, expires,
		); err != nil {
			t.Fatalf("seed referencing event for snapshot %s: %v", sha, err)
		}
	}

	// The caller claims BOTH are eligible -- exactly what an adversary,
	// or a caller with a wrong local clock, would do.
	recorded, err := sink.RecordPurge(ctx, []string{expiredSHA, notExpiredSHA}, now, "test-operator", "retention expiration")
	if err != nil {
		t.Fatalf("RecordPurge: %v", err)
	}

	recordedSet := map[string]bool{}
	for _, sha := range recorded {
		recordedSet[sha] = true
	}
	if !recordedSet[expiredSHA] {
		t.Fatalf("expected the genuinely expired snapshot to be recorded, got recorded=%v", recorded)
	}
	if recordedSet[notExpiredSHA] {
		t.Fatalf("server-side floor did not hold: a snapshot that is not actually expired was recorded as purged (ADR-0007 Addendum 2 D28), recorded=%v", recorded)
	}

	var notExpiredPurgedAt *time.Time
	if err := verify.QueryRow(ctx, `SELECT purged_at FROM screening_ledger_snapshot WHERE snapshot_sha256=$1`, notExpiredSHA).Scan(&notExpiredPurgedAt); err != nil {
		t.Fatal(err)
	}
	if notExpiredPurgedAt != nil {
		t.Fatal("the not-yet-expired snapshot's purged_at was set despite failing the server floor")
	}

	var tombstoneCount int
	if err := verify.QueryRow(ctx, `SELECT count(*) FROM screening_ledger_retention_tombstone WHERE snapshot_sha256=$1`, notExpiredSHA).Scan(&tombstoneCount); err != nil {
		t.Fatal(err)
	}
	if tombstoneCount != 0 {
		t.Fatal("a tombstone was recorded for a snapshot that is not actually expired")
	}
}

// fakeHoldingRecorder is a PurgeRecorder that records everything it is
// asked to record, so TestPurgeExpiredHonorsLegalHolds can assert on
// exactly what Store.PurgeExpired's local pass decided was eligible
// (legal holds already filtered out) BEFORE it ever reached a recorder --
// D28's "local narrows" half, verifiable independent of a live database.
type fakeHoldingRecorder struct {
	sawEligible []string
}

func (f *fakeHoldingRecorder) RecordPurge(_ context.Context, eligibleSHA256 []string, _ time.Time, _, _ string) ([]string, error) {
	f.sawEligible = append([]string{}, eligibleSHA256...)
	return eligibleSHA256, nil
}

// TestPurgeExpiredRequiresRecorder is D28's fail-closed half: a purge
// whose independence cannot be recorded must not happen at all -- no
// nil-recorder fallback, no envelope mutation.
func TestPurgeExpiredRequiresRecorder(t *testing.T) {
	directory := t.TempDir()
	store, err := NewStore(directory, testKey(), "ledger-purge-no-recorder")
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.Append(testAppendInput())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.PurgeExpired(context.Background(), time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC), "operator", "reason", nil); err == nil {
		t.Fatal("expected PurgeExpired to refuse with a nil PurgeRecorder (ADR-0007 Addendum 2 D28)")
	}

	env, err := store.LoadSnapshot(result.Event.RequestSnapshotSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if env.PurgedAt != "" {
		t.Fatal("PurgeExpired mutated an envelope despite refusing to run without a recorder")
	}
}

// TestPurgeExpiredHonorsLegalHolds is D28's local-narrows half: an event
// under legal hold must never even be offered to the recorder as
// eligible, regardless of what the recorder would do with it -- the
// server-side function has no filesystem to consult holds/ against, so
// this exclusion has to happen locally, before the recorder is ever
// called.
func TestPurgeExpiredHonorsLegalHolds(t *testing.T) {
	directory := t.TempDir()
	store, err := NewStore(directory, testKey(), "ledger-purge-holds")
	if err != nil {
		t.Fatal(err)
	}
	held, err := store.Append(testAppendInput())
	if err != nil {
		t.Fatal(err)
	}
	holdPath := directory + "/holds/" + held.Event.EventID
	if err := os.WriteFile(holdPath, []byte("legal hold\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	recorder := &fakeHoldingRecorder{}
	count, err := store.PurgeExpired(context.Background(), time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC), "operator", "reason", recorder)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("legal hold did not prevent purge: %d", count)
	}
	for _, sha := range recorder.sawEligible {
		if sha == held.Event.RequestSnapshotSHA256 || sha == held.Event.ResponseSnapshotSHA256 {
			t.Fatalf("a snapshot under legal hold was offered to the recorder as eligible: %s (ADR-0007 Addendum 2 D28 local-narrows)", sha)
		}
	}
}
