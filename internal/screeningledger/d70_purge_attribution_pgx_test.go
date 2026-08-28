// ADR-0007 Addendum 8 D70/D75 test 2 (L-B, CRITICAL, the data half): the
// retention claim's attribution is adjudicated against the anchored
// attestation, in both directions -- forward (the tombstone row's
// operator/reason must equal the attesting audit entry's, purged_at
// compared only as an ordering bound against the anchor's own
// anchored_at) and reverse (every tombstone row for a snapshot this
// ledger's chain references must correspond to an anchored purge_expired
// attestation, closing the route the forward walk structurally cannot:
// a tombstone written directly against Postgres for a snapshot never
// marked purged locally).
//
// Runs entirely against a disposable CREATE DATABASE ... TEMPLATE clone
// (newD50Clone): this file's own forgeries neuter and restore the guard
// trigger on screening_ledger_retention_tombstone, which is DDL nothing
// in this suite may risk performing against the shared primary database
// other pgx tests in this package also use.
package screeningledger

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// preD70AdjudicatePurgeClaims reconstructs D32's original condition 3
// (mere existence of a tombstone row) exactly as it read immediately
// before ADR-0007 Addendum 8 D70 turned it into an
// operator/reason/purged_at comparison against the attesting audit
// entry -- PurgeRecord's presence is checked, its fields never read, and
// there is no reverse-direction scan at all.
func (s *Store) preD70AdjudicatePurgeClaims(ctx context.Context, claims []PurgeClaim, anchoredAuditSequence int64, purges PurgeChecker) error {
	if len(claims) == 0 {
		return nil
	}
	attesting, err := s.attestingAuditEntries()
	if err != nil {
		return err
	}
	for _, claim := range claims {
		entry, attested := attesting[claim.SnapshotSHA256]
		if !attested {
			return fmt.Errorf("snapshot %s is marked purged locally but no audit entry attests to it", claim.SnapshotSHA256)
		}
		if int64(entry.Sequence) > anchoredAuditSequence {
			return fmt.Errorf("snapshot %s's purge attestation is not yet anchored", claim.SnapshotSHA256)
		}
		if purges == nil {
			return fmt.Errorf("snapshot %s's purge cannot be corroborated: no independent purge-record source is configured", claim.SnapshotSHA256)
		}
		record, err := purges.PurgeRecord(ctx, claim.SnapshotSHA256)
		if err != nil {
			return err
		}
		if record == nil {
			return fmt.Errorf("snapshot %s is attested and anchored but has no independent tombstone record", claim.SnapshotSHA256)
		}
		// pre-D70: existence alone was sufficient -- operator, reason and
		// purged_at are never read.
	}
	return nil
}

// d70Chain builds a real, single-event ledger against a disposable
// clone, mirrors it to Postgres, performs one legitimate anchored purge
// through the real Store.PurgeExpired/RecordPurge path, and anchors past
// it -- the clean baseline every forgery below is layered onto, reused
// by both the forward and reverse tests.
type d70Chain struct {
	store        *Store
	sink         *PostgresSink
	anchorSink   *AnchorSink
	kAnchor      []byte
	policy       VerificationPolicy
	policySHA256 string
	purgedSHA    string
	clone        d50CloneFixture
	migratorDSN  string
	ledgerAnchor string
	scriptPath   string
	superuserDSN string
}

func newD70Chain(t *testing.T, ctx context.Context) d70Chain {
	t.Helper()
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	anchorDSN := requireAnchorDatabaseURL(t)

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	cloneMigratorDSN := withDatabase(t, migratorDSN, clone.dbName)
	cloneAnchorDSN := withDatabase(t, anchorDSN, clone.dbName)

	directory := t.TempDir()
	store, err := NewStore(directory, testKey(), uniqueID("sec7-d70"))
	if err != nil {
		t.Fatal(err)
	}
	// Event 1: far in the past, so its snapshots are genuinely expired
	// against clock_timestamp() (D32's server-side floor) the moment
	// they exist. Genesis-anchored before the purge, so the genesis
	// anchor's own audit_sequence (0) is never asked to cross-check a
	// chain with real audit entries -- only the SECOND anchor, written
	// after event 2 and the purge, does that.
	input1 := testAppendInput()
	input1.CorrelationID = uniqueID("corr")
	input1.IdempotencyKey = uniqueID("idem")
	input1.RequestBytes = []byte(`{"unique":"` + uniqueID("req") + `"}`)
	input1.ResponseBytes = []byte(`{"unique":"` + uniqueID("resp") + `"}`)
	input1.OccurredAt = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	input1.Retention.RetentionDays = 1
	result1, err := store.Append(input1)
	if err != nil {
		t.Fatal(err)
	}

	kAnchor := make([]byte, 32)
	for i := range kAnchor {
		kAnchor[i] = byte(i + 7)
	}

	sink, err := NewPostgresSink(ctx, cloneMigratorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	t.Cleanup(func() { sink.Close(context.Background()) })

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
	mirror(result1)

	policy := testPolicy(store.ledgerID)
	policySHA256 := testPolicySHA256(t, policy)

	// A throwaway audit entry before genesis, so the genesis anchor's
	// own AuditSequence is 1, not 0 -- auditEntryAtSequence has no
	// special case for "sequence 0 means no entries yet, don't look
	// anything up," so anchoring at audit_sequence 0 and later
	// re-verifying against a chain that has since grown looks up a
	// nonexistent sequence-0 entry. Real deployments avoid this the same
	// way: a ledger's very first anchor is rarely written before any
	// audit action has ever happened.
	if _, err := store.AppendAudit("d70-setup", "", "", "", nil); err != nil {
		t.Fatal(err)
	}

	// Genesis anchor, before the purge.
	genesisReport, err := store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: policy, Purges: sink},
		Anchors:       sink, Provisioning: sink, KAnchor: kAnchor, PolicySHA256: policySHA256, AllowGenesis: true,
	})
	if err != nil {
		t.Fatalf("genesis VerifyAnchored: %v", err)
	}

	anchorSink, err := NewAnchorSink(ctx, cloneAnchorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewAnchorSink: %v", err)
	}
	t.Cleanup(func() { anchorSink.Close(context.Background()) })
	if err := anchorSink.WriteAnchor(ctx, kAnchor, store.ledgerID, int64(genesisReport.Head.Sequence), genesisReport.Head.EventSHA256, genesisReport.AuditHead.EventSHA256, int64(genesisReport.AuditHead.Sequence), policySHA256); err != nil {
		t.Fatalf("WriteAnchor (genesis): %v", err)
	}

	// Event 2: recent, not expired -- advances the event sequence so a
	// second anchor row (same ledger_id, sequence=2) does not collide
	// with the genesis row's primary key (ledger_id, sequence=1).
	input2 := testAppendInput()
	input2.CorrelationID = uniqueID("corr")
	input2.IdempotencyKey = uniqueID("idem")
	input2.RequestBytes = []byte(`{"unique":"` + uniqueID("req2") + `"}`)
	input2.ResponseBytes = []byte(`{"unique":"` + uniqueID("resp2") + `"}`)
	// testAppendInput()'s default OccurredAt (2026-07-14) plus its
	// default RetentionDays (1) is already expired by the time this
	// suite runs -- explicit, current, long-retained here so event 2
	// survives the purge below.
	input2.OccurredAt = time.Now().UTC().Format(time.RFC3339Nano)
	input2.Retention.RetentionDays = 3650
	result2, err := store.Append(input2)
	if err != nil {
		t.Fatal(err)
	}
	mirror(result2)

	// The legitimate purge, through the real front door: local pass
	// (legal holds, none here), RecordPurge (server floor + tombstone
	// write), AppendAudit -- exactly Store.PurgeExpired's own sequence
	// (replay.go). Purges both snapshots of event 1 (retention_days=1,
	// occurred 2000-01-01, both expired); event 2 is untouched.
	purgedCount, err := store.PurgeExpired(ctx, time.Now(), "legit-operator", "legit-reason", sink)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if purgedCount != 2 {
		t.Fatalf("expected exactly 2 snapshots purged (event 1's request+response, retention_days=1, occurred 2000-01-01), got %d", purgedCount)
	}

	// Anchor again, at event sequence 2, past the purge_expired audit
	// entry. VerifyPolicy (not VerifyAnchored) here, deliberately: the
	// genesis anchor above still commits to audit_sequence 1, which is
	// now BEHIND the purge_expired entry (audit_sequence 2) -- calling
	// VerifyAnchored at this point would defer-and-adjudicate the purge
	// claims against the STALE genesis anchor and correctly refuse them
	// as "not yet anchored," which is D32's condition 2 working exactly
	// as intended, not a bug. WriteAnchor below is what actually commits
	// past it; allowDeferredPurgeClaims (unexported, settable only
	// in-package) mirrors VerifyAnchored's own deferral so VerifyPolicy
	// alone does not fail closed on the two now-deferred purge claims
	// (ADR-0007 Addendum 3 D32's collect/adjudicate split).
	postPurgeReport, err := store.VerifyPolicy(ctx, VerifyOptions{Policy: policy, Purges: sink, allowDeferredPurgeClaims: true})
	if err != nil {
		t.Fatalf("VerifyPolicy after legitimate purge should still verify clean: %v", err)
	}
	if err := anchorSink.WriteAnchor(ctx, kAnchor, store.ledgerID, int64(postPurgeReport.Head.Sequence), postPurgeReport.Head.EventSHA256, postPurgeReport.AuditHead.EventSHA256, int64(postPurgeReport.AuditHead.Sequence), policySHA256); err != nil {
		t.Fatalf("WriteAnchor (post-purge): %v", err)
	}

	return d70Chain{
		store: store, sink: sink, anchorSink: anchorSink, kAnchor: kAnchor,
		policy: policy, policySHA256: policySHA256, purgedSHA: result1.Event.RequestSnapshotSHA256,
		clone: clone, migratorDSN: cloneMigratorDSN, ledgerAnchor: cloneAnchorDSN,
		scriptPath: d62ScriptPath(t), superuserDSN: clone.superuserDSN,
	}
}

// TestPurgeAttributionIsAdjudicatedAgainstTheAnchoredAttestation is D75
// test 2's forward direction: a legitimate purge, anchored, verifies
// clean; then operator/reason are rewritten in the tombstone with the
// guard trigger neutered, and VerifyAnchored must fail after (proving
// the pre-D70 reconstruction succeeds on the exact same state first, per
// D42/D47's convention).
func TestPurgeAttributionIsAdjudicatedAgainstTheAnchoredAttestation(t *testing.T) {
	ctx := context.Background()
	chain := newD70Chain(t, ctx)

	// Baseline: clean and verified.
	if r, err := chain.store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: chain.policy, Purges: chain.sink},
		Anchors:       chain.sink, Provisioning: chain.sink, KAnchor: chain.kAnchor, PolicySHA256: chain.policySHA256,
	}); err != nil || r.AnchorStatus != AnchorStatusVerified {
		t.Fatalf("expected a clean verified anchor after a legitimate purge, got status=%v err=%v", r.AnchorStatus, err)
	}

	// Neuter the guard trigger and rewrite the tombstone's attribution
	// directly against Postgres -- the forgery L-B demonstrates.
	superuser, err := pgx.Connect(ctx, chain.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())
	withD34TriggersDisabled(t, ctx, superuser, func() {
		if _, err := superuser.Exec(ctx, `DROP TRIGGER screening_ledger_retention_tombstone_immutable ON screening_ledger_retention_tombstone`); err != nil {
			t.Fatalf("drop the guard trigger: %v", err)
		}
		if _, err := superuser.Exec(ctx, `
			CREATE TRIGGER screening_ledger_retention_tombstone_immutable
			  BEFORE DELETE OR UPDATE ON screening_ledger_retention_tombstone
			  FOR EACH ROW WHEN (false) EXECUTE FUNCTION screening_ledger_reject_mutation()`); err != nil {
			t.Fatalf("neuter the guard trigger with WHEN (false): %v", err)
		}
	})
	ledgerDDLConn, err := pgx.Connect(ctx, withDatabase(t, requireLedgerDDLDatabaseURL(t), chain.clone.dbName))
	if err != nil {
		t.Fatalf("connect as owl_ledger_ddl: %v", err)
	}
	defer ledgerDDLConn.Close(context.Background())
	if _, err := ledgerDDLConn.Exec(ctx,
		`UPDATE screening_ledger_retention_tombstone SET operator='someone-else', reason='forged' WHERE snapshot_sha256=$1`,
		chain.purgedSHA,
	); err != nil {
		t.Fatalf("expected the neutered guard to allow the forging UPDATE: %v", err)
	}

	// Restore the guard trigger to its declared, legitimate state and
	// resync the registries -- D69 already refuses the neutered trigger
	// by itself, so this test isolates D70 by leaving only the
	// tombstone row's forged attribution.
	chain.restoreGuardTrigger(t, ctx, superuser)

	deferredOpts := VerifyOptions{Policy: chain.policy, Purges: chain.sink, allowDeferredPurgeClaims: true}
	report, err := chain.store.VerifyPolicy(ctx, deferredOpts)
	if err != nil {
		t.Fatalf("VerifyPolicy (deferred): %v", err)
	}
	if len(report.PurgeClaims) != 2 {
		t.Fatalf("expected exactly 2 deferred purge claims (request+response), got %d", len(report.PurgeClaims))
	}
	latest, found, err := chain.sink.LatestAnchor(ctx, chain.store.ledgerID)
	if err != nil || !found {
		t.Fatalf("LatestAnchor: found=%v err=%v", found, err)
	}

	if err := chain.store.preD70AdjudicatePurgeClaims(ctx, report.PurgeClaims, latest.AuditSequence, chain.sink); err != nil {
		t.Fatalf("ADR-0007 Addendum 8 D70: expected the pre-Addendum-8 reconstruction to accept the forged attribution (existence alone was sufficient), got: %v -- this must reproduce the gap, not a probe that never exercised it", err)
	}

	result, err := chain.store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: chain.policy, Purges: chain.sink},
		Anchors:       chain.sink, Provisioning: chain.sink, KAnchor: chain.kAnchor, PolicySHA256: chain.policySHA256,
	})
	if err == nil {
		t.Fatalf("ADR-0007 Addendum 8 D70: verify succeeded (status=%q) on a ledger with a forged tombstone attribution", result.AnchorStatus)
	}
	if !strings.Contains(err.Error(), "D70") {
		t.Fatalf("expected the error to cite ADR-0007 Addendum 8 D70, got: %v", err)
	}
	if !strings.Contains(err.Error(), "forged retention attribution") {
		t.Fatalf("expected the error to name the attribution mismatch, got: %v", err)
	}
}

// TestPurgeAttributionRejectsPurgedAtAfterAnchor is D70's purged_at
// ordering-bound half: a tombstone row whose purged_at postdates the
// anchor that attests to it is refused, even with operator/reason
// intact.
func TestPurgeAttributionRejectsPurgedAtAfterAnchor(t *testing.T) {
	ctx := context.Background()
	chain := newD70Chain(t, ctx)

	superuser, err := pgx.Connect(ctx, chain.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())
	withD34TriggersDisabled(t, ctx, superuser, func() {
		if _, err := superuser.Exec(ctx, `DROP TRIGGER screening_ledger_retention_tombstone_immutable ON screening_ledger_retention_tombstone`); err != nil {
			t.Fatal(err)
		}
		if _, err := superuser.Exec(ctx, `
			CREATE TRIGGER screening_ledger_retention_tombstone_immutable
			  BEFORE DELETE OR UPDATE ON screening_ledger_retention_tombstone
			  FOR EACH ROW WHEN (false) EXECUTE FUNCTION screening_ledger_reject_mutation()`); err != nil {
			t.Fatal(err)
		}
	})
	ledgerDDLConn, err := pgx.Connect(ctx, withDatabase(t, requireLedgerDDLDatabaseURL(t), chain.clone.dbName))
	if err != nil {
		t.Fatalf("connect as owl_ledger_ddl: %v", err)
	}
	defer ledgerDDLConn.Close(context.Background())
	// operator/reason left intact; only purged_at moved into the future,
	// after the anchor that attests to this purge.
	if _, err := ledgerDDLConn.Exec(ctx,
		`UPDATE screening_ledger_retention_tombstone SET purged_at = now() + interval '1 hour' WHERE snapshot_sha256=$1`,
		chain.purgedSHA,
	); err != nil {
		t.Fatalf("neutered-guard UPDATE of purged_at: %v", err)
	}
	chain.restoreGuardTrigger(t, ctx, superuser)

	result, err := chain.store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: chain.policy, Purges: chain.sink},
		Anchors:       chain.sink, Provisioning: chain.sink, KAnchor: chain.kAnchor, PolicySHA256: chain.policySHA256,
	})
	if err == nil {
		t.Fatalf("ADR-0007 Addendum 8 D70: verify succeeded (status=%q) on a tombstone whose purged_at postdates its attesting anchor", result.AnchorStatus)
	}
	if !strings.Contains(err.Error(), "D70") || !strings.Contains(err.Error(), "postdate") {
		t.Fatalf("expected an ordering-bound error citing ADR-0007 Addendum 8 D70, got: %v", err)
	}
}

// TestPurgeAttributionReverseDirectionCatchesOrphanTombstones is D75
// test 2's reverse direction: a tombstone row for a snapshot never
// marked purged locally -- via a direct SQL purge (screening_ledger_
// purge_snapshots called directly as owl_migrator, bypassing
// Store.PurgeExpired's audit-writing front door entirely) and via a
// direct INSERT as owl_ledger_ddl -- is a named failure, closing the
// route the forward walk structurally cannot see (it is driven by which
// snapshots the LOCAL envelope already claims are purged).
func TestPurgeAttributionReverseDirectionCatchesOrphanTombstones(t *testing.T) {
	ctx := context.Background()

	t.Run("direct_screening_ledger_purge_snapshots_call", func(t *testing.T) {
		chain := newD70Chain(t, ctx)
		targetSHA := chain.appendExtraKnownButUnpurgedSnapshot(t, ctx)

		migratorConn, err := pgx.Connect(ctx, chain.migratorDSN)
		if err != nil {
			t.Fatalf("connect as owl_migrator: %v", err)
		}
		defer migratorConn.Close(context.Background())
		if _, err := migratorConn.Exec(ctx, `SELECT screening_ledger_purge_snapshots($1::text[], now(), 'attacker-direct', 'no-audit-trail')`, []string{targetSHA}); err != nil {
			t.Fatalf("direct definer-function call as owl_migrator: %v", err)
		}

		assertOrphanTombstoneRefused(t, ctx, chain)
	})

	t.Run("direct_insert_as_owl_ledger_ddl", func(t *testing.T) {
		chain := newD70Chain(t, ctx)
		targetSHA := chain.appendExtraKnownButUnpurgedSnapshot(t, ctx)

		ledgerDDLConn, err := pgx.Connect(ctx, withDatabase(t, requireLedgerDDLDatabaseURL(t), chain.clone.dbName))
		if err != nil {
			t.Fatalf("connect as owl_ledger_ddl: %v", err)
		}
		defer ledgerDDLConn.Close(context.Background())
		if _, err := ledgerDDLConn.Exec(ctx,
			`INSERT INTO screening_ledger_retention_tombstone (snapshot_sha256, purged_at, operator, reason) VALUES ($1, now(), 'attacker', 'fabricated, never purged locally')`,
			targetSHA,
		); err != nil {
			t.Fatalf("direct INSERT as owl_ledger_ddl: %v", err)
		}

		assertOrphanTombstoneRefused(t, ctx, chain)
	})
}

// appendExtraKnownButUnpurgedSnapshot appends a real, third local event
// (expired, so it WOULD be eligible for a legitimate purge) through
// Store.Append and mirrors it to Postgres through the real Persist path
// -- so its request snapshot sha256 is genuinely known both locally
// (VerifyReport.KnownSnapshotSHA256, the reverse scan's scope) and in
// Postgres, exactly the shape D70 describes ("a tombstone row for a
// snapshot that was never purged locally"), rather than a snapshot that
// exists only in Postgres with no local envelope at all (which the
// reverse scan correctly does not consider this ledger's business at
// all -- see PurgeChecker's own doc comment on knownSHA256 in store.go).
// Its local envelope is never marked purged, and no audit entry is ever
// appended for it -- the direct-SQL forgery is layered on afterwards by
// the caller.
func (chain d70Chain) appendExtraKnownButUnpurgedSnapshot(t *testing.T, ctx context.Context) string {
	t.Helper()
	input := testAppendInput()
	input.CorrelationID = uniqueID("corr")
	input.IdempotencyKey = uniqueID("idem")
	input.RequestBytes = []byte(`{"unique":"` + uniqueID("req-orphan") + `"}`)
	input.ResponseBytes = []byte(`{"unique":"` + uniqueID("resp-orphan") + `"}`)
	input.OccurredAt = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	input.Retention.RetentionDays = 1
	result, err := chain.store.Append(input)
	if err != nil {
		t.Fatal(err)
	}
	request, err := chain.store.LoadSnapshot(result.Event.RequestSnapshotSHA256)
	if err != nil {
		t.Fatal(err)
	}
	response, err := chain.store.LoadSnapshot(result.Event.ResponseSnapshotSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.sink.Persist(ctx, result.Event, request, response, ReplicationVerification{}); err != nil {
		t.Fatal(err)
	}
	return result.Event.RequestSnapshotSHA256
}

func assertOrphanTombstoneRefused(t *testing.T, ctx context.Context, chain d70Chain) {
	t.Helper()
	result, err := chain.store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: chain.policy, Purges: chain.sink},
		Anchors:       chain.sink, Provisioning: chain.sink, KAnchor: chain.kAnchor, PolicySHA256: chain.policySHA256,
	})
	if err == nil {
		t.Fatalf("ADR-0007 Addendum 8 D70: verify succeeded (status=%q) despite an orphan tombstone row with no local purge claim and no audit attestation", result.AnchorStatus)
	}
	if !strings.Contains(err.Error(), "D70") {
		t.Fatalf("expected the error to cite ADR-0007 Addendum 8 D70, got: %v", err)
	}
	if !strings.Contains(err.Error(), "no audit entry attests") {
		t.Fatalf("expected the error to name the missing attestation, got: %v", err)
	}
}

// restoreGuardTrigger puts screening_ledger_retention_tombstone_immutable
// back to its declared, legitimate state (no WHEN clause, bound to
// public.screening_ledger_reject_mutation()) so a test can isolate D70's
// own check from D69's, then re-runs the real, shipped
// grant-ddl-ownership against this clone so
// sec7_protected_relation/sec7_protected_object agree with the restored
// trigger's new OID -- D69's own live-behavior check passes on the
// restored trigger, so this run succeeds rather than refusing.
func (chain d70Chain) restoreGuardTrigger(t *testing.T, ctx context.Context, superuser *pgx.Conn) {
	t.Helper()
	// Deliberately does NOT use withD34TriggersDisabled here: that
	// helper re-enables the event triggers (ENABLE ALWAYS) as soon as
	// this function returns, which would fire D40's blanket
	// re-validation (every declared protected relation, on ANY
	// subsequent DDL statement in the database) against the STILL-STALE
	// sec7_protected_relation row for the tombstone -- the restored
	// trigger has a new OID the registry does not know about yet. Left
	// disabled here, on purpose, so that window never opens: the script
	// below re-populates the registry BEFORE it re-creates and
	// re-enables the event triggers itself, at its own end -- the exact
	// ordering D62(a)/D40 rely on for every legitimate re-run.
	if _, err := superuser.Exec(ctx, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop DISABLE`); err != nil {
		t.Fatal(err)
	}
	if _, err := superuser.Exec(ctx, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE`); err != nil {
		t.Fatal(err)
	}
	if _, err := superuser.Exec(ctx, `DROP TRIGGER screening_ledger_retention_tombstone_immutable ON screening_ledger_retention_tombstone`); err != nil {
		t.Fatalf("drop the neutered trigger: %v", err)
	}
	if _, err := superuser.Exec(ctx, `
		CREATE TRIGGER screening_ledger_retention_tombstone_immutable
		  BEFORE DELETE OR UPDATE ON screening_ledger_retention_tombstone
		  FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation()`); err != nil {
		t.Fatalf("restore the legitimate trigger: %v", err)
	}

	host, port, superuserUser, superpassword := pgConnParamsFromDSN(t, chain.superuserDSN)
	cmd := exec.Command(chain.scriptPath, "grant-ddl-ownership")
	cmd.Env = append(cmd.Environ(),
		"PGHOST="+host, "PGPORT="+port, "PGDATABASE="+chain.clone.dbName,
		"PGSUPERUSER="+superuserUser, "PGSUPERPASSWORD="+superpassword,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("re-run grant-ddl-ownership to resync registries after restoring the trigger: %v\n%s", err, output)
	}
}
