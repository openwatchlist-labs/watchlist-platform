// PostgresSink's pgx-backed contract, exercised against a live
// PostgreSQL connection (ADR-0005 §4, §8.2). Gated on
// OWL_MIGRATOR_DATABASE_URL, the same variable
// internal/integrationtest/tenant_isolation_test.go gates on -- skips
// cleanly when unset. It has to be the migrator identity, not
// OWL_TEST_DATABASE_URL/owl_app: owl_app is granted no privileges at all
// on the Class C ledger relations these tests write to (see the doc
// comment on PostgresSink in postgres.go), and Migrate needs DDL rights
// regardless.
//
// These tests replace what a fake CommandRunner used to cover
// (TestPostgresMigrationAndPersistenceContract, removed from
// store_test.go): pgx speaks the wire protocol directly, so there is no
// fork to intercept, and "does this round-trip" can only be answered by
// asking a real server.
package screeningledger

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func requireMigratorDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OWL_MIGRATOR_DATABASE_URL")
	if dsn == "" {
		t.Skip("OWL_MIGRATOR_DATABASE_URL not set; screening-ledger pgx suite requires a live Postgres with DDL rights (see scripts/ci/run-ci.sh)")
	}
	return dsn
}

// verifyConn opens an independent connection to prove a write is truly
// durable and committed -- not just visible on the writer's own
// in-flight transaction -- and is closed by the caller.
func verifyConn(t *testing.T, ctx context.Context, dsn string) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("verify connection: %v", err)
	}
	return conn
}

func newTestSink(t *testing.T) (*PostgresSink, context.Context) {
	t.Helper()
	dsn := requireMigratorDSN(t)
	ctx := context.Background()
	sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	t.Cleanup(func() {
		if err := sink.Close(context.Background()); err != nil {
			t.Errorf("sink.Close: %v", err)
		}
	})
	if err := sink.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return sink, ctx
}

// uniqueID keeps successive test runs against a persistent local/CI
// database from colliding on primary keys.
func uniqueID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func TestPostgresSinkPersistRoundTrip(t *testing.T) {
	sink, ctx := newTestSink(t)
	dsn := requireMigratorDSN(t)

	store, err := NewStore(t.TempDir(), testKey(), uniqueID("pgx-roundtrip"))
	if err != nil {
		t.Fatal(err)
	}
	input := testAppendInput()
	input.IdempotencyKey = uniqueID("idem")
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
		t.Fatalf("Persist: %v", err)
	}

	verify := verifyConn(t, ctx, dsn)
	defer verify.Close(ctx)

	var gotSHA256, gotRoute string
	var gotHTTPStatus int
	var gotEventJSON []byte
	if err := verify.QueryRow(ctx,
		`SELECT event_sha256, route, http_status, event_json FROM screening_ledger_event WHERE event_id=$1`,
		result.Event.EventID,
	).Scan(&gotSHA256, &gotRoute, &gotHTTPStatus, &gotEventJSON); err != nil {
		t.Fatalf("read back screening_ledger_event: %v", err)
	}
	if gotSHA256 != result.Event.EventSHA256 || gotRoute != result.Event.Route || gotHTTPStatus != result.Event.HTTPStatus {
		t.Fatalf("round-tripped event mismatch: sha256=%s route=%s status=%d", gotSHA256, gotRoute, gotHTTPStatus)
	}
	var roundTripped Event
	if err := json.Unmarshal(gotEventJSON, &roundTripped); err != nil {
		t.Fatalf("event_json did not round-trip as valid JSON: %v", err)
	}
	if roundTripped.EventID != result.Event.EventID {
		t.Fatalf("event_json payload mismatch: %#v", roundTripped)
	}

	var replicatedCount int
	if err := verify.QueryRow(ctx,
		`SELECT count(*) FROM screening_ledger_replication WHERE event_id=$1`, result.Event.EventID,
	).Scan(&replicatedCount); err != nil {
		t.Fatal(err)
	}
	if replicatedCount != 1 {
		t.Fatalf("expected one replication row, got %d", replicatedCount)
	}

	var snapshotCount int
	if err := verify.QueryRow(ctx,
		`SELECT count(*) FROM screening_ledger_snapshot WHERE snapshot_sha256 IN ($1,$2)`,
		result.Event.RequestSnapshotSHA256, result.Event.ResponseSnapshotSHA256,
	).Scan(&snapshotCount); err != nil {
		t.Fatal(err)
	}
	if snapshotCount != 2 {
		t.Fatalf("expected both snapshot envelopes persisted, got %d", snapshotCount)
	}

	var receiptCount int
	if err := verify.QueryRow(ctx,
		`SELECT count(*) FROM screening_idempotency_receipt WHERE scope=$1 AND idempotency_key_sha256=$2`,
		result.Event.Route, result.Event.IdempotencyKeyHash,
	).Scan(&receiptCount); err != nil {
		t.Fatal(err)
	}
	if receiptCount != 1 {
		t.Fatalf("expected one idempotency receipt, got %d", receiptCount)
	}

	// ON CONFLICT DO NOTHING (a named, deliberately preserved defect --
	// ADR-0005 §4) must still make a repeat Persist of the identical
	// event a no-op rather than an error.
	if err := sink.Persist(ctx, result.Event, request, response, ReplicationVerification{}); err != nil {
		t.Fatalf("repeat Persist of identical event must be a no-op: %v", err)
	}
}

func TestPostgresSinkPersistIdempotencyConflictGuard(t *testing.T) {
	sink, ctx := newTestSink(t)

	store, err := NewStore(t.TempDir(), testKey(), uniqueID("pgx-idempotency"))
	if err != nil {
		t.Fatal(err)
	}
	sharedKey := uniqueID("idem-conflict")

	first := testAppendInput()
	first.IdempotencyKey = sharedKey
	firstResult, err := store.Append(first)
	if err != nil {
		t.Fatal(err)
	}
	req1, _ := store.LoadSnapshot(firstResult.Event.RequestSnapshotSHA256)
	resp1, _ := store.LoadSnapshot(firstResult.Event.ResponseSnapshotSHA256)
	if err := sink.Persist(ctx, firstResult.Event, req1, resp1, ReplicationVerification{}); err != nil {
		t.Fatalf("first Persist: %v", err)
	}

	// Same idempotency key, different response body -> the guard this
	// test exists to protect (it was a DO $$ ... $$ block before REL-2;
	// now a parameterized SELECT plus an application-side check,
	// ADR-0005 §4) must still reject it rather than silently accepting
	// divergent content under a reused key. Same store/ledger/route as
	// the first append, so only the response content and the resulting
	// event_id differ -- the same shape a real reused-key collision
	// would take.
	second := testAppendInput()
	second.IdempotencyKey = sharedKey
	second.ResponseBytes = []byte(`{"request_id":"req-1","different":true}`)
	secondResult, err := store.Append(second)
	if err != nil {
		t.Fatal(err)
	}
	req2, _ := store.LoadSnapshot(secondResult.Event.RequestSnapshotSHA256)
	resp2, _ := store.LoadSnapshot(secondResult.Event.ResponseSnapshotSHA256)

	if err := sink.Persist(ctx, secondResult.Event, req2, resp2, ReplicationVerification{}); err == nil {
		t.Fatal("expected idempotency receipt conflict, got nil error")
	}
}

func TestPostgresSinkPersistAuditRoundTrip(t *testing.T) {
	sink, ctx := newTestSink(t)
	dsn := requireMigratorDSN(t)

	audit := AuditEvent{
		SchemaVersion: AuditSchemaV1,
		LedgerID:      uniqueID("ledger"),
		Sequence:      1,
		AuditSHA256:   uniqueID("audit-sha"),
		OccurredAt:    time.Now().UTC().Format(time.RFC3339Nano),
		Action:        "postgres_replicated",
	}
	if err := sink.PersistAudit(ctx, audit); err != nil {
		t.Fatalf("PersistAudit: %v", err)
	}

	verify := verifyConn(t, ctx, dsn)
	defer verify.Close(ctx)
	var action string
	if err := verify.QueryRow(ctx,
		`SELECT action FROM screening_ledger_audit WHERE audit_sha256=$1`, audit.AuditSHA256,
	).Scan(&action); err != nil {
		t.Fatalf("read back screening_ledger_audit: %v", err)
	}
	if action != audit.Action {
		t.Fatalf("expected action %q, got %q", audit.Action, action)
	}
}

func TestPostgresSinkPurgeExpiredRoundTrip(t *testing.T) {
	sink, ctx := newTestSink(t)
	dsn := requireMigratorDSN(t)
	verify := verifyConn(t, ctx, dsn)
	defer verify.Close(ctx)

	snapshotSHA := uniqueID("snapshot-sha")
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := verify.Exec(ctx,
		`INSERT INTO screening_ledger_snapshot(snapshot_sha256,kind,created_at,expires_at,retention_class,envelope_json) VALUES ($1,'request',$2::timestamptz,$3::timestamptz,'screening-standard','{}'::jsonb)`,
		snapshotSHA, past, past,
	); err != nil {
		t.Fatalf("seed expired snapshot: %v", err)
	}

	operator := "pgx-test-operator"
	reason := "retention expiration"
	if err := sink.PurgeExpired(ctx, future, operator, reason); err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}

	var purgedAt *time.Time
	var purgeReason string
	if err := verify.QueryRow(ctx,
		`SELECT purged_at, purge_reason FROM screening_ledger_snapshot WHERE snapshot_sha256=$1`, snapshotSHA,
	).Scan(&purgedAt, &purgeReason); err != nil {
		t.Fatal(err)
	}
	if purgedAt == nil || purgeReason != reason {
		t.Fatalf("expected snapshot purged with reason %q, got purged_at=%v reason=%q", reason, purgedAt, purgeReason)
	}

	var tombstoneOperator string
	if err := verify.QueryRow(ctx,
		`SELECT operator FROM screening_ledger_retention_tombstone WHERE snapshot_sha256=$1`, snapshotSHA,
	).Scan(&tombstoneOperator); err != nil {
		t.Fatalf("read back retention tombstone: %v", err)
	}
	if tombstoneOperator != operator {
		t.Fatalf("expected tombstone operator %q, got %q", operator, tombstoneOperator)
	}
}

func TestImportExternalAuditRoundTrip(t *testing.T) {
	sink, ctx := newTestSink(t)
	dsn := requireMigratorDSN(t)

	directory := t.TempDir()
	event := phase8fAuditEvent{
		SchemaVersion: "openwatchlist.activation-promotion-audit-event.v1",
		Sequence:      1,
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		EventType:     "promotion_prepared",
		IntentID:      uniqueID("intent"),
		Revision:      1,
		Actor:         "validator",
	}
	canonical, _ := json.Marshal(event)
	event.EventSHA256 = digestHex(append(canonical, '\n'))
	raw, _ := json.Marshal(event)
	path := filepath.Join(directory, "00000000000000000001-"+event.EventSHA256+".json")
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatal(err)
	}

	source := uniqueID("phase8f-source")
	count, err := ImportExternalAudit(ctx, sink, source, directory)
	if err != nil || count != 1 {
		t.Fatalf("ImportExternalAudit: count=%d err=%v", count, err)
	}

	verify := verifyConn(t, ctx, dsn)
	defer verify.Close(ctx)
	var action string
	if err := verify.QueryRow(ctx,
		`SELECT action FROM watchlist_operational_audit WHERE source=$1 AND event_sha256=$2`,
		source, event.EventSHA256,
	).Scan(&action); err != nil {
		t.Fatalf("read back watchlist_operational_audit: %v", err)
	}
	if action != event.EventType {
		t.Fatalf("expected action %q, got %q", event.EventType, action)
	}
}

// TestPostgresSinkNoProcessSpawn is the reliability property REL-2
// exists to establish for this sink (ADR-0005 §4, §8.2): the whole
// point of the migration is that persistence no longer forks a psql
// process per statement. Running with a PATH containing no binaries at
// all means any surviving fork+exec path fails loudly instead of the
// test silently passing via a shell-out that happened to still work.
func TestPostgresSinkNoProcessSpawn(t *testing.T) {
	dsn := requireMigratorDSN(t)
	empty := t.TempDir()
	t.Setenv("PATH", empty)

	ctx := context.Background()
	sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink with empty PATH: %v", err)
	}
	defer sink.Close(ctx)
	if err := sink.Migrate(ctx); err != nil {
		t.Fatalf("Migrate with empty PATH: %v", err)
	}

	store, err := NewStore(t.TempDir(), testKey(), uniqueID("pgx-no-spawn"))
	if err != nil {
		t.Fatal(err)
	}
	input := testAppendInput()
	input.IdempotencyKey = uniqueID("idem-no-spawn")
	result, err := store.Append(input)
	if err != nil {
		t.Fatal(err)
	}
	result.Event.LedgerID = uniqueID("ledger")
	request, _ := store.LoadSnapshot(result.Event.RequestSnapshotSHA256)
	response, _ := store.LoadSnapshot(result.Event.ResponseSnapshotSHA256)
	if err := sink.Persist(ctx, result.Event, request, response, ReplicationVerification{}); err != nil {
		t.Fatalf("Persist with empty PATH: %v", err)
	}
	if err := sink.PurgeExpired(ctx, time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano), "no-spawn-operator", "expired"); err != nil {
		t.Fatalf("PurgeExpired with empty PATH: %v", err)
	}
}
