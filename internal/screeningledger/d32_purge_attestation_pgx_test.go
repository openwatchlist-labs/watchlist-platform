// ADR-0007 Addendum 3 D32 (G-C, CRITICAL): CAP #2 §7.3's exact chain,
// reproduced end to end -- tamper one snapshot of four, mark it purged
// locally, tombstone it through the real sanctioned SECURITY DEFINER
// front door (screening_ledger_purge_snapshots), and confirm verify
// used to report "status":"ok" at exit 0 on the result. D32 replaces
// the server-side predicate's trust in caller-controlled inputs with an
// externally-authenticated fact: a purge is legitimate only if a
// verified, anchored audit-chain entry attests to it.
package screeningledger

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestPurgeRequiresAnchoredAttestation is D32's required reproduction.
// The starting chain is built by the real, unmodified Store.Append (two
// events, four genuine encrypted snapshots on disk, genuinely mirrored
// to Postgres); the genesis anchor is written for real over a live
// AnchorSink connection. One snapshot is then tampered (its ciphertext
// destroyed) and marked purged locally with NO audit-chain attestation
// -- the exact gap the CAP's front-door tombstone left. VerifyAnchored
// must fail; it must not accept the forgery the way the pre-D32
// verifier did.
func TestPurgeRequiresAnchoredAttestation(t *testing.T) {
	migratorDSN := requireMigratorDSN(t)
	anchorDSN := requireAnchorDatabaseURL(t)
	ctx := context.Background()

	// anchorTestKeys builds events from testAppendInput()'s fixed literal
	// content, which every other pgx test in this shared, persistent
	// database also uses -- its snapshot rows may already be marked
	// purged by an earlier test's run. This test needs a snapshot it
	// knows is fresh, so it builds its own store with unique content per
	// event instead.
	directory := t.TempDir()
	store, err := NewStore(directory, testKey(), uniqueID("sec7-d32-attestation"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		input := testAppendInput()
		input.CorrelationID = uniqueID("corr")
		input.IdempotencyKey = uniqueID("idem")
		input.RequestBytes = []byte(`{"request_id":"req","unique":"` + uniqueID("req") + `"}`)
		input.ResponseBytes = []byte(`{"request_id":"req","unique":"` + uniqueID("resp") + `"}`)
		if _, err := store.Append(input); err != nil {
			t.Fatal(err)
		}
	}
	kAnchor := make([]byte, 32)
	for i := range kAnchor {
		kAnchor[i] = byte(i + 3)
	}

	sink, err := NewPostgresSink(ctx, migratorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())
	if err := sink.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	events, err := store.ListEvents()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events (4 snapshots), got %d", len(events))
	}
	for _, event := range events {
		request, err := store.LoadSnapshot(event.RequestSnapshotSHA256)
		if err != nil {
			t.Fatal(err)
		}
		response, err := store.LoadSnapshot(event.ResponseSnapshotSHA256)
		if err != nil {
			t.Fatal(err)
		}
		if err := sink.Persist(ctx, event, request, response, ReplicationVerification{}); err != nil {
			t.Fatalf("Persist: %v", err)
		}
	}

	policy := testPolicy(store.ledgerID)
	policySHA256 := testPolicySHA256(t, policy)

	// Honest baseline, before genesis: must verify clean.
	report, err := store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: policy, Purges: sink},
		Anchors:       sink, Provisioning: sink, KAnchor: kAnchor, PolicySHA256: policySHA256, AllowGenesis: true,
	})
	if err != nil {
		t.Fatalf("honest baseline must verify clean before genesis anchor: %v", err)
	}
	if report.AnchorStatus != AnchorStatusAbsent {
		t.Fatalf("expected AnchorStatusAbsent before genesis, got %q", report.AnchorStatus)
	}

	anchorSink, err := NewAnchorSink(ctx, anchorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewAnchorSink: %v", err)
	}
	defer anchorSink.Close(context.Background())
	if err := anchorSink.WriteAnchor(ctx, kAnchor, store.ledgerID, int64(report.Head.Sequence), report.Head.EventSHA256, report.AuditHead.EventSHA256, int64(report.AuditHead.Sequence), policySHA256); err != nil {
		t.Fatalf("WriteAnchor: %v", err)
	}

	// Post-genesis: still clean, still verified.
	if r, err := store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: policy, Purges: sink},
		Anchors:       sink, Provisioning: sink, KAnchor: kAnchor, PolicySHA256: policySHA256,
	}); err != nil || r.AnchorStatus != AnchorStatusVerified {
		t.Fatalf("expected a clean verified anchor before tampering, got status=%v err=%v", r.AnchorStatus, err)
	}

	// CAP #2 §7.3: tamper one snapshot of four (destroy its ciphertext),
	// mark it purged locally -- but with no audit-chain attestation for
	// this specific purge anywhere. This models the adversary's exact
	// move: forge locally, tombstone through the sanctioned front door,
	// never through Store.PurgeExpired's real attestation path.
	targetSHA := events[0].RequestSnapshotSHA256
	env, err := store.LoadSnapshot(targetSHA)
	if err != nil {
		t.Fatal(err)
	}
	env.CiphertextBase64 = "forged-ciphertext-does-not-decrypt"
	env.PurgedAt = time.Now().UTC().Format(time.RFC3339Nano)
	env.PurgeReason = "adversary"
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(store.snapshotPath(targetSHA), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	// Tombstone it through the real, sanctioned SECURITY DEFINER front
	// door. The referencing event's own expires_at genuinely predates
	// "now" (testAppendInput's fixed OccurredAt of 2026-07-14 plus a
	// 1-day retention), so D32's own server-side-floor hardening (D32's
	// "hardening that rides along," not the fix) legitimately treats
	// this snapshot as expired -- exactly the CAP's point: the front
	// door itself is not the defect; the missing attestation is.
	recorded, err := sink.RecordPurge(ctx, []string{targetSHA}, time.Now(), "adversary", "front door")
	if err != nil {
		t.Fatalf("RecordPurge (the real sanctioned front door): %v", err)
	}
	if len(recorded) != 1 || recorded[0] != targetSHA {
		t.Fatalf("expected the front door to record exactly %s, got %v", targetSHA, recorded)
	}

	// The moment of the finding: VerifyAnchored must fail. Before D32,
	// this exact sequence exited 0 with "status":"ok".
	result, err := store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: policy, Purges: sink},
		Anchors:       sink, Provisioning: sink, KAnchor: kAnchor, PolicySHA256: policySHA256,
	})
	if err == nil {
		t.Fatalf("CAP #2 §7.3's exact forgery: verify succeeded (status=%q) on a ledger with a tampered, purged-but-unattested snapshot (ADR-0007 Addendum 3 D32)", result.AnchorStatus)
	}
	if !strings.Contains(err.Error(), "no audit entry attests") {
		t.Fatalf("expected the error to name the missing audit attestation (ADR-0007 Addendum 3 D32), got: %v", err)
	}
}

// TestPurgeSnapshotsIgnoresCallerTimestamp is D32's hardening half:
// screening_ledger_purge_snapshots must ignore the caller-supplied
// timestamp entirely and use clock_timestamp() server-side -- CAP #2
// §7.3's "p_before => 'infinity'" attack, which tombstoned snapshots
// with a real expiry ten years out. This is explicitly hardening, not
// the fix (D32's own text): it raises the cost of forgery without
// closing it, since the same caller still owns the referencing event's
// expires_at. The real fix (attestation) is TestPurgeRequiresAnchoredAttestation
// above.
func TestPurgeSnapshotsIgnoresCallerTimestamp(t *testing.T) {
	sink, ctx := newTestSink(t)
	dsn := requireMigratorDSN(t)
	verify := verifyConn(t, ctx, dsn)
	defer verify.Close(ctx)

	sha := uniqueID("snapshot-not-yet-expired")
	notYetExpired := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := verify.Exec(ctx,
		`INSERT INTO screening_ledger_snapshot(snapshot_sha256,kind,created_at,expires_at,retention_class,envelope_json) VALUES ($1,'request',now(),$2::timestamptz,'screening-standard','{}'::jsonb)`,
		sha, notYetExpired,
	); err != nil {
		t.Fatalf("seed not-yet-expired snapshot: %v", err)
	}
	eventID := uniqueID("event-for-" + sha)
	if _, err := verify.Exec(ctx,
		`INSERT INTO screening_ledger_event(event_id,ledger_id,sequence,event_sha256,previous_event_sha256,occurred_at,route,http_status,request_sha256,response_sha256,request_snapshot_sha256,response_snapshot_sha256,retention_class,expires_at,event_json)
		 VALUES ($1,$2,1,$3,'',now(),'/screen',200,'req-sha','resp-sha',$4,$4,'screening-standard',$5::timestamptz,'{}'::jsonb)`,
		eventID, uniqueID("ledger-for-"+sha), uniqueID("event-sha-for-"+sha), sha, notYetExpired,
	); err != nil {
		t.Fatalf("seed referencing event: %v", err)
	}

	// The caller claims the far future -- exactly what CAP #2 §7.3's
	// "'infinity'" argument modeled. Under the pre-D32 predicate this
	// tombstones the snapshot regardless of its real expiry. Go's
	// time.Time cannot literally encode SQL 'infinity', but any value the
	// caller supplies must be equally ignored -- this uses a timestamp
	// decades out, which is exactly what the old predicate would have
	// accepted and the new one must not.
	callerClaimedNow := time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)
	recorded, err := sink.RecordPurge(ctx, []string{sha}, callerClaimedNow, "adversary", "front door")
	if err != nil {
		t.Fatalf("RecordPurge: %v", err)
	}
	if len(recorded) != 0 {
		t.Fatalf("ADR-0007 Addendum 3 D32 hardening did not hold: a caller-supplied timestamp was honored, recorded=%v", recorded)
	}

	var purgedAt *time.Time
	if err := verify.QueryRow(ctx, `SELECT purged_at FROM screening_ledger_snapshot WHERE snapshot_sha256=$1`, sha).Scan(&purgedAt); err != nil {
		t.Fatal(err)
	}
	if purgedAt != nil {
		t.Fatal("the not-yet-expired snapshot's purged_at was set despite D32's server-side clock_timestamp() floor")
	}
}

// TestVerifyPolicyFailsClosedOnUnadjudicatedClaims is D32's collect/
// adjudicate split, the direct-caller half: a caller of VerifyPolicy
// (anything other than VerifyAnchored) that does not and cannot opt
// into deferral must get an error, not a report carrying unresolved
// PurgeClaims -- "I collected this for someone else to judge" and "I
// judged it" must not share a return value. No live Postgres needed:
// any non-nil PurgeChecker is enough to trigger the deferred-collection
// path in anchored mode.
type alwaysRecordedPurgeChecker struct{}

func (alwaysRecordedPurgeChecker) IsPurgeRecorded(context.Context, string) (bool, error) {
	return true, nil
}

func TestVerifyPolicyFailsClosedOnUnadjudicatedClaims(t *testing.T) {
	directory := t.TempDir()
	store, err := NewStore(directory, testKey(), "ledger-unadjudicated-claims")
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.Append(testAppendInput())
	if err != nil {
		t.Fatal(err)
	}

	env, err := store.LoadSnapshot(result.Event.RequestSnapshotSHA256)
	if err != nil {
		t.Fatal(err)
	}
	env.PurgedAt = time.Now().UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(store.snapshotPath(result.Event.RequestSnapshotSHA256), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	policy := testPolicy("ledger-unadjudicated-claims")
	_, err = store.VerifyPolicy(context.Background(), VerifyOptions{Policy: policy, Purges: alwaysRecordedPurgeChecker{}})
	if err == nil {
		t.Fatal("expected VerifyPolicy to fail closed on an unadjudicated purge claim when called directly, not through VerifyAnchored (ADR-0007 Addendum 3 D32)")
	}
	if !strings.Contains(err.Error(), "anchored adjudication") {
		t.Fatalf("expected the error to name the anchored-adjudication requirement, got: %v", err)
	}
}
