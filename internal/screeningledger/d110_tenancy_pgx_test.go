// ADR-0007 Addendum 12 D110 test file (D112 item 7): P-F's two-ledger
// reproduction and R43's premise re-measurement, reproduced
// independently against a real disposable Postgres cluster before this
// addendum's design was written (0007:11778-11860), are not re-derived
// here from the ADR transcript -- these tests build them fresh, through
// the real, unmodified Store.Append/PostgresSink.Persist/VerifyAnchored,
// exactly as that reproduction did.
package screeningledger

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// makeGenuinelySingleTenant deletes every row NOT belonging to ledgerID,
// from clone's own database, as the bootstrap superuser, across all
// THREE relations that carry a ledger_id column (ADR-0007 Addendum 13
// D119: screening_ledger_event, screening_ledger_audit and
// screening_ledger_anchor -- not screening_ledger_event alone, which is
// D110's own original, under-broad text). A d50CloneFixture inherits the
// ENTIRE state of the shared primary database at clone time (CREATE
// DATABASE ... TEMPLATE), which by the time this suite reaches these
// tests genuinely carries many other ledgers' rows in all three
// relations (R43's own measured premise, re-confirmed by
// TestR43PremiseFailsAgainstCurrentDatabase below, and by D119's own
// over-broad-half finding that ForeignLedgerIDs is non-empty against
// this shared database even before screening_ledger_event is
// considered). Destructive, but scoped to this disposable,
// already-cloned, t.Cleanup-dropped database only -- never the shared
// primary.
func makeGenuinelySingleTenant(t *testing.T, ctx context.Context, clone d50CloneFixture, ledgerID string) {
	t.Helper()
	superuser, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())
	tx, err := superuser.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	// Every one of these three tables' row-immutability trigger fires
	// regardless of role, superuser included --
	// session_replication_role=replica disables triggers for this
	// session only, a GUC set rather than a DDL statement, so it does
	// not touch D34's protections at all. Scoped to this one transaction
	// on this disposable clone.
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM screening_ledger_event WHERE ledger_id<>$1`, ledgerID); err != nil {
		t.Fatalf("isolate clone to a single tenant (screening_ledger_event): %v", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM screening_ledger_audit WHERE ledger_id<>$1`, ledgerID); err != nil {
		t.Fatalf("isolate clone to a single tenant (screening_ledger_audit): %v", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM screening_ledger_anchor WHERE ledger_id<>$1`, ledgerID); err != nil {
		t.Fatalf("isolate clone to a single tenant (screening_ledger_anchor): %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// d110SingleTenantFixture builds one ledger, anchored and verified
// clean, on a disposable clone made genuinely single-tenant.
type d110SingleTenantFixture struct {
	store        *Store
	sink         *PostgresSink
	anchorSink   *AnchorSink
	kAnchor      []byte
	policy       VerificationPolicy
	superuserDSN string
}

func newD110SingleTenantFixture(t *testing.T, ctx context.Context, tenancy string) d110SingleTenantFixture {
	t.Helper()
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	anchorDSN := requireAnchorDatabaseURL(t)

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	cloneMigratorDSN := withDatabase(t, migratorDSN, clone.dbName)
	cloneAnchorDSN := withDatabase(t, anchorDSN, clone.dbName)

	store, err := NewStore(t.TempDir(), testKey(), uniqueID("d110"))
	if err != nil {
		t.Fatal(err)
	}
	makeGenuinelySingleTenant(t, ctx, clone, store.ledgerID)

	kAnchor := make([]byte, 32)
	for i := range kAnchor {
		kAnchor[i] = byte(i + 151)
	}
	policy := testExclusivePolicy(store.ledgerID)
	policy.Tenancy = tenancy

	sink, err := NewPostgresSink(ctx, cloneMigratorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	t.Cleanup(func() { sink.Close(context.Background()) })
	anchorSink, err := NewAnchorSink(ctx, cloneAnchorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewAnchorSink: %v", err)
	}
	t.Cleanup(func() { anchorSink.Close(context.Background()) })

	input := testAppendInput()
	input.CorrelationID = uniqueID("corr-d110")
	input.IdempotencyKey = uniqueID("idem-d110")
	input.RequestBytes = []byte(`{"unique":"` + uniqueID("d110-req") + `"}`)
	input.ResponseBytes = []byte(`{"unique":"` + uniqueID("d110-resp") + `"}`)
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

	return d110SingleTenantFixture{store: store, sink: sink, anchorSink: anchorSink, kAnchor: kAnchor, policy: policy, superuserDSN: clone.superuserDSN}
}

// anchorNow writes an anchor covering the store's current head -- kept
// separate from newD110SingleTenantFixture so a caller that needs to
// mutate state (a purge, a forgery) BEFORE the one anchor this test's
// single-event chain can ever hold at event sequence 1 gets the chance
// to do so first.
func (f d110SingleTenantFixture) anchorNow(t *testing.T, ctx context.Context) {
	t.Helper()
	report, err := f.store.VerifyPolicy(ctx, VerifyOptions{Policy: f.policy, Purges: f.sink, allowDeferredPurgeClaims: true})
	if err != nil {
		t.Fatalf("VerifyPolicy: %v", err)
	}
	if err := f.anchorSink.WriteAnchor(ctx, f.kAnchor, f.store.ledgerID, int64(report.Head.Sequence), report.Head.EventSHA256, report.AuditHead.EventSHA256, int64(report.AuditHead.Sequence), testPolicySHA256(t, f.policy)); err != nil {
		t.Fatalf("WriteAnchor: %v", err)
	}
}

func (f d110SingleTenantFixture) verify(t *testing.T, ctx context.Context) (AnchorVerifyResult, error) {
	t.Helper()
	return f.store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: f.policy, Purges: f.sink},
		Anchors:       f.sink, Provisioning: f.sink, KAnchor: f.kAnchor, PolicySHA256: testPolicySHA256(t, f.policy),
	})
}

// TestSingleLedgerExclusiveVerifiesClean is D112 item 7's positive: a
// single-ledger deployment under the default exclusive policy, on a
// genuinely single-tenant database, verifies clean.
func TestSingleLedgerExclusiveVerifiesClean(t *testing.T) {
	ctx := context.Background()
	f := newD110SingleTenantFixture(t, ctx, TenancyExclusive)
	f.anchorNow(t, ctx)
	result, err := f.verify(t, ctx)
	if err != nil || result.AnchorStatus != AnchorStatusVerified {
		t.Fatalf("ADR-0007 Addendum 12 D110: expected a single-ledger deployment under exclusive tenancy to verify clean, got status=%v err=%v", result.AnchorStatus, err)
	}
}

// TestExclusiveTenancyDetectsForeignLedgerID is D112 item 7 / D110's
// own text: in exclusive mode, a screening_ledger_event row carrying a
// foreign ledger_id is itself a named verification failure, naming the
// foreign id.
func TestExclusiveTenancyDetectsForeignLedgerID(t *testing.T) {
	ctx := context.Background()
	f := newD110SingleTenantFixture(t, ctx, TenancyExclusive)
	f.anchorNow(t, ctx)

	foreignLedgerID := uniqueID("foreign-ledger")
	if _, err := f.sink.conn.Exec(ctx,
		`INSERT INTO screening_ledger_event(event_id,ledger_id,sequence,event_sha256,previous_event_sha256,occurred_at,route,http_status,request_sha256,response_sha256,request_snapshot_sha256,response_snapshot_sha256,retention_class,expires_at,event_json)
		 VALUES ($1,$2,1,$3,'',now(),'/screen',200,'req-sha','resp-sha','sha-a','sha-a','screening-standard',now(),'{}'::jsonb)`,
		uniqueID("foreign-event"), foreignLedgerID, uniqueID("foreign-event-sha"),
	); err != nil {
		t.Fatal(err)
	}

	result, err := f.verify(t, ctx)
	if err == nil {
		t.Fatalf("ADR-0007 Addendum 12 D110: expected exclusive-tenancy verification to FAIL over a foreign ledger_id row, got status=%v", result.AnchorStatus)
	}
	if !strings.Contains(err.Error(), "D110") {
		t.Fatalf("expected the error to cite ADR-0007 Addendum 12 D110, got: %v", err)
	}
	if !strings.Contains(err.Error(), foreignLedgerID) {
		t.Fatalf("expected the error to NAME the foreign ledger_id %q, got: %v", foreignLedgerID, err)
	}
}

// TestExclusiveTenancyStillAdjudicatesAttestedTombstoneDivergence is
// D112 item 7's own required plus: D70's adjudication of a tombstone
// this ledger DOES attest still fails on divergence, unchanged by D110
// -- tenancy only changes the UNATTESTED branch.
func TestExclusiveTenancyStillAdjudicatesAttestedTombstoneDivergence(t *testing.T) {
	ctx := context.Background()
	f := newD110SingleTenantFixture(t, ctx, TenancyExclusive)

	events, err := f.store.ListEvents()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("test construction error: expected 1 event, got %d", len(events))
	}
	sha := events[0].RequestSnapshotSHA256

	// Legitimately purge, so an attesting audit entry DOES exist --
	// then forge the tombstone's operator/reason so it diverges from
	// what the audit entry attests (D70's own forward comparison).
	purged, err := f.store.PurgeExpired(ctx, time.Now().AddDate(1000, 0, 0), "legit-operator", "legit-reason", f.policy.Tenancy, f.sink)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if purged == 0 {
		t.Fatal("test construction error: expected the sole event's snapshots to be purgeable")
	}
	superuser := connectSuperuser(t, ctx, f.superuserDSN)
	defer superuser.Close(context.Background())
	forgeTx, err := superuser.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer forgeTx.Rollback(context.Background())
	// screening_ledger_retention_tombstone's own immutability trigger
	// (screening_ledger_reject_mutation) fires regardless of role too --
	// same session-scoped bypass as makeGenuinelySingleTenant, not a DDL
	// statement, so D34's protections are untouched.
	if _, err := forgeTx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := forgeTx.Exec(ctx, `UPDATE screening_ledger_retention_tombstone SET operator='forged-operator' WHERE snapshot_sha256=$1`, sha); err != nil {
		t.Fatal(err)
	}
	if err := forgeTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	f.anchorNow(t, ctx)

	result, err := f.verify(t, ctx)
	if err == nil {
		t.Fatalf("ADR-0007 Addendum 8 D70 unregressed by Addendum 12 D110: expected verification to fail on the forged operator, got status=%v", result.AnchorStatus)
	}
	if !strings.Contains(err.Error(), "D70") {
		t.Fatalf("expected the error to cite ADR-0007 Addendum 8 D70, got: %v", err)
	}
}

// TestV3PolicyRejectedOutright is D112 item 7's negative: a v3 document
// is refused outright by the schema pin, not silently narrowed.
func TestV3PolicyRejectedOutright(t *testing.T) {
	p := testPolicy("some-ledger")
	p.SchemaVersion = VerificationPolicySchemaV3
	if err := p.Validate(); err == nil {
		t.Fatal("ADR-0007 Addendum 12 D110: expected a v3-labelled policy to be refused outright by the v4 schema pin")
	}
}

// TestTenancyHasNoFlagOrEnvironmentEscape is D112 item 7's other
// negative: no flag, environment variable, or mirror-derived probe can
// select shared mode -- Tenancy is read from the signed
// VerificationPolicy field alone, and DecodeUnsignedPolicy requires it
// present with one of exactly two values.
func TestTenancyHasNoFlagOrEnvironmentEscape(t *testing.T) {
	document := `{
		"schema_version":"openwatchlist.screening-ledger-verification-policy.v4",
		"ledger_id":"probe-ledger",
		"min_event_schema":"openwatchlist.screening-ledger-event.v2",
		"min_audit_schema":"openwatchlist.screening-ledger-audit.v2",
		"genesis_event_sequence":1,
		"genesis_audit_sequence":1,
		"allow_unanchored":false,
		"min_anchor_sequence":0,
		"genesis_event_sha256":"",
		"genesis_audit_sha256":""
	}`
	if _, err := DecodeUnsignedPolicy(strings.NewReader(document)); err == nil {
		t.Fatal("ADR-0007 Addendum 12 D110: expected an omitted tenancy field to be refused, not silently defaulted")
	}

	invalid := `{
		"schema_version":"openwatchlist.screening-ledger-verification-policy.v4",
		"ledger_id":"probe-ledger",
		"min_event_schema":"openwatchlist.screening-ledger-event.v2",
		"min_audit_schema":"openwatchlist.screening-ledger-audit.v2",
		"genesis_event_sequence":1,
		"genesis_audit_sequence":1,
		"allow_unanchored":false,
		"min_anchor_sequence":0,
		"genesis_event_sha256":"",
		"genesis_audit_sha256":"",
		"tenancy":"mostly-exclusive"
	}`
	if _, err := DecodeUnsignedPolicy(strings.NewReader(invalid)); err == nil {
		t.Fatal("ADR-0007 Addendum 12 D110: expected a tenancy value other than exclusive/shared to be refused")
	}
}

// TestR43PremiseFailsAgainstCurrentDatabase independently re-confirms
// R43's premise fails against the CURRENT CI database -- the same
// distinct-ledger-ids and shared-sha queries the design pass ran,
// re-run here rather than trusted from the design transcript.
func TestR43PremiseFailsAgainstCurrentDatabase(t *testing.T) {
	ctx := context.Background()
	dsn := requireMigratorDSN(t)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(context.Background())

	var distinctLedgers, eventRows int
	if err := conn.QueryRow(ctx, `SELECT count(DISTINCT ledger_id), count(*) FROM screening_ledger_event`).Scan(&distinctLedgers, &eventRows); err != nil {
		t.Fatal(err)
	}
	t.Logf("A12PROBE distinct_ledger_ids=%d event_rows=%d", distinctLedgers, eventRows)
	if distinctLedgers < 2 {
		t.Fatalf("ADR-0007 Addendum 12 D110: expected the shared primary CI database to carry more than one ledger_id (R43's own premise measurement), got %d -- run the full package suite first", distinctLedgers)
	}

	var sharedShas int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM (SELECT request_snapshot_sha256 FROM screening_ledger_event GROUP BY request_snapshot_sha256 HAVING count(DISTINCT ledger_id) > 1) x`).Scan(&sharedShas); err != nil {
		t.Fatal(err)
	}
	t.Logf("A12PROBE shas_referenced_by_more_than_one_ledger=%d", sharedShas)
}
