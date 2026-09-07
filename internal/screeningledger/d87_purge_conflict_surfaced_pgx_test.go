// ADR-0007 Addendum 10 D87/D95 test 1 (N-A's enabler): ON CONFLICT
// (snapshot_sha256) DO NOTHING no longer swallows a pre-empted tombstone
// -- CLAUDE.md's own named trap ("Do not swallow conflicts... Catch
// 23505 and surface it"), and D86 row 8's own finding that neither
// screening_ledger_purge_snapshots overload had a declared body digest.
package screeningledger

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestPurgePreemptionSurfacesRatherThanBeingSwallowed reproduces CAP #9
// section 7.1's exact sequence: owl_ledger_ddl pre-empts a tombstone for
// a snapshot the mirror still records unpurged, then the real
// Store.PurgeExpired runs. Before D87 this succeeded, leaving the forged
// row in place; after D87 it fails with a named 23505. Plus the three
// positives that make it safe to install: three consecutive legitimate
// purges are idempotent, a purge with no pre-emption still succeeds and
// verifies clean, and both overloads are covered.
func TestPurgePreemptionSurfacesRatherThanBeingSwallowed(t *testing.T) {
	ctx := context.Background()

	t.Run("preemption_via_time_floor_purge_refused", func(t *testing.T) {
		chain := newA10Chain(t, ctx)
		targetSHA := chain.appendExtraKnownButUnpurgedSnapshot(t, ctx, "d87preempt1")

		ledgerDDLConn := chain.ledgerDDLConn(t, ctx)
		defer ledgerDDLConn.Close(context.Background())
		if _, err := ledgerDDLConn.Exec(ctx,
			`INSERT INTO screening_ledger_retention_tombstone (snapshot_sha256, purged_at, operator, reason) VALUES ($1, '1999-01-01', 'attacker-preempt', 'no-audit-trail')`,
			targetSHA,
		); err != nil {
			t.Fatalf("direct pre-emptive INSERT as owl_ledger_ddl: %v", err)
		}

		migratorConn, err := pgx.Connect(ctx, chain.migratorDSN)
		if err != nil {
			t.Fatalf("connect as owl_migrator: %v", err)
		}
		defer migratorConn.Close(context.Background())
		// ADR-0007 Addendum 12 D107: the time-floor overload's leading
		// refusal now needs an honest (count, max) for this ledger's
		// TOTAL mirror population -- computed from the mirror itself, so
		// this specific call is not refused for the WRONG reason (a
		// corroboration mismatch) before it ever reaches the D87
		// pre-emption check this test is actually about.
		var mirrorCount int64
		var mirrorMax time.Time
		if err := migratorConn.QueryRow(ctx, `SELECT count(*), max(expires_at) FROM screening_ledger_event WHERE ledger_id=$1`, chain.store.ledgerID).Scan(&mirrorCount, &mirrorMax); err != nil {
			t.Fatal(err)
		}
		_, err = migratorConn.Exec(ctx, `SELECT screening_ledger_purge_snapshots($1,$2,$3,'legit-op','legit-reason')`, chain.store.ledgerID, mirrorCount, mirrorMax)
		if err == nil {
			t.Fatalf("ADR-0007 Addendum 10 D87: legitimate purge succeeded despite a pre-empted tombstone for %s", targetSHA)
		}
		if !strings.Contains(err.Error(), "D87") || !strings.Contains(err.Error(), targetSHA) {
			t.Fatalf("expected a named D87 error identifying %s, got: %v", targetSHA, err)
		}
	})

	t.Run("preemption_via_array_form_purge_refused", func(t *testing.T) {
		chain := newA10Chain(t, ctx)
		targetSHA := chain.appendExtraKnownButUnpurgedSnapshot(t, ctx, "d87preempt2")

		ledgerDDLConn := chain.ledgerDDLConn(t, ctx)
		defer ledgerDDLConn.Close(context.Background())
		if _, err := ledgerDDLConn.Exec(ctx,
			`INSERT INTO screening_ledger_retention_tombstone (snapshot_sha256, purged_at, operator, reason) VALUES ($1, '1999-01-01', 'attacker-preempt', 'no-audit-trail')`,
			targetSHA,
		); err != nil {
			t.Fatalf("direct pre-emptive INSERT as owl_ledger_ddl: %v", err)
		}

		migratorConn, err := pgx.Connect(ctx, chain.migratorDSN)
		if err != nil {
			t.Fatalf("connect as owl_migrator: %v", err)
		}
		defer migratorConn.Close(context.Background())
		// ADR-0007 Addendum 12 D107: honest, per-sha corroboration for
		// targetSHA, read straight from the mirror -- same reason as
		// the time-floor subtest above.
		var mirrorCount int32
		var mirrorMax time.Time
		if err := migratorConn.QueryRow(ctx, `SELECT count(*), max(expires_at) FROM screening_ledger_event WHERE (request_snapshot_sha256=$1 OR response_snapshot_sha256=$1) AND ledger_id=$2`, targetSHA, chain.store.ledgerID).Scan(&mirrorCount, &mirrorMax); err != nil {
			t.Fatal(err)
		}
		_, err = migratorConn.Exec(ctx, `SELECT screening_ledger_purge_snapshots($1::text[],$2,$3::int[],$4::timestamptz[],'legit-op','legit-reason')`, []string{targetSHA}, chain.store.ledgerID, []int32{mirrorCount}, []time.Time{mirrorMax})
		if err == nil {
			t.Fatalf("ADR-0007 Addendum 10 D87: legitimate array-form purge succeeded despite a pre-empted tombstone for %s", targetSHA)
		}
		if !strings.Contains(err.Error(), "D87") || !strings.Contains(err.Error(), targetSHA) {
			t.Fatalf("expected a named D87 error identifying %s, got: %v", targetSHA, err)
		}
	})

	t.Run("three_legitimate_purges_are_idempotent", func(t *testing.T) {
		chain := newA10Chain(t, ctx)
		migratorConn, err := pgx.Connect(ctx, chain.migratorDSN)
		if err != nil {
			t.Fatalf("connect as owl_migrator: %v", err)
		}
		defer migratorConn.Close(context.Background())

		// Run 1's count is whatever this clone's own template state
		// (owl_ci at clone time, including anything left expired-but-
		// unpurged by other tests sharing the primary database) makes
		// eligible -- not asserted to any particular value, matching
		// CAP #9's own transcript ("run 1 returned: 1"). What idempotency
		// actually requires is runs 2 and 3 finding nothing left. The
		// mirror aggregate is re-read before each run (ADR-0007
		// Addendum 12 D107): a purge changes no screening_ledger_event
		// row, so it is stable across all three, but re-reading rather
		// than caching keeps this honest about what the leading refusal
		// actually compares against.
		var counts []int64
		for i := 0; i < 3; i++ {
			var mirrorCount int64
			var mirrorMax time.Time
			if err := migratorConn.QueryRow(ctx, `SELECT count(*), max(expires_at) FROM screening_ledger_event WHERE ledger_id=$1`, chain.store.ledgerID).Scan(&mirrorCount, &mirrorMax); err != nil {
				t.Fatal(err)
			}
			var n int64
			if err := migratorConn.QueryRow(ctx, `SELECT screening_ledger_purge_snapshots($1,$2,$3,'legit-op','legit-reason')`, chain.store.ledgerID, mirrorCount, mirrorMax).Scan(&n); err != nil {
				t.Fatalf("run %d: %v", i, err)
			}
			counts = append(counts, n)
		}
		if counts[1] != 0 || counts[2] != 0 {
			t.Fatalf("expected runs 2 and 3 to be idempotent no-ops, got %v", counts)
		}
	})

	t.Run("no_preemption_still_succeeds_and_verifies_clean", func(t *testing.T) {
		chain := newA10Chain(t, ctx)
		result, err := chain.verify(t, ctx)
		if err != nil || result.AnchorStatus != AnchorStatusVerified {
			t.Fatalf("expected a clean legitimate purge with no pre-emption to verify, got status=%v err=%v", result.AnchorStatus, err)
		}
	})
}

// appendExtraKnownButUnpurgedSnapshot appends a real, extra local event
// (expired, so it WOULD be eligible for a legitimate purge) through
// Store.Append and mirrors it to Postgres -- its request snapshot
// sha256 is genuinely known both locally and in Postgres, and never
// marked purged locally, matching D70's own appendExtraKnownButUnpurged-
// Snapshot helper's shape for a different addendum's tests.
func (chain a10Chain) appendExtraKnownButUnpurgedSnapshot(t *testing.T, ctx context.Context, tag string) string {
	t.Helper()
	input := testAppendInput()
	input.CorrelationID = uniqueID("corr-" + tag)
	input.IdempotencyKey = uniqueID("idem-" + tag)
	input.RequestBytes = []byte(`{"unique":"` + uniqueID("req-"+tag) + `"}`)
	input.ResponseBytes = []byte(`{"unique":"` + uniqueID("resp-"+tag) + `"}`)
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

// TestPurgeDefinerBodyIsDeclaredNotAddressed is D86 row 8 / D87 part 2:
// both screening_ledger_purge_snapshots overloads now have a declared
// accepted body digest, so a T2 substitution (event triggers disabled,
// the documented recovery window) is refused by CheckProvisioningState
// and by grant-ddl-ownership, naming the function and the live digest.
// Plus the over-tightening positives on both bootstrap paths.
func TestPurgeDefinerBodyIsDeclaredNotAddressed(t *testing.T) {
	ctx := context.Background()
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)

	t.Run("substituted_array_form_body_is_refused", func(t *testing.T) {
		clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
		cloneMigratorDSN := withDatabase(t, migratorDSN, clone.dbName)
		sink, err := NewPostgresSink(ctx, cloneMigratorDSN, 10*time.Second)
		if err != nil {
			t.Fatalf("NewPostgresSink: %v", err)
		}
		defer sink.Close(context.Background())

		superuser := connectSuperuser(t, ctx, clone.superuserDSN)
		defer superuser.Close(context.Background())
		withD34TriggersDisabled(t, ctx, superuser, func() {
			// ADR-0007 Addendum 12 D107: substitutes the CURRENT
			// (text[],text,int4[],timestamptz[],text,text) array-form
			// signature -- the corroboration check stripped out
			// entirely, exactly the shape of substitution D87 exists to
			// catch.
			mustExec(t, ctx, superuser, `
				CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_snapshot_sha256 text[], p_ledger_id text, p_expected_count int[], p_expected_max timestamptz[], p_operator text, p_reason text)
				RETURNS text[] LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
				DECLARE recorded text[];
				BEGIN
					WITH eligible AS (
						SELECT snapshot_sha256 FROM screening_ledger_snapshot WHERE snapshot_sha256 = ANY(p_snapshot_sha256) AND purged_at IS NULL
					), inserted AS (
						INSERT INTO screening_ledger_retention_tombstone(snapshot_sha256, purged_at, operator, reason)
						SELECT snapshot_sha256, '1999-01-01'::timestamptz, p_operator, p_reason FROM eligible
					), updated AS (
						UPDATE screening_ledger_snapshot SET purged_at='1999-01-01'::timestamptz, purge_reason=p_reason
						WHERE snapshot_sha256 IN (SELECT snapshot_sha256 FROM eligible) RETURNING snapshot_sha256
					)
					SELECT array_agg(snapshot_sha256) INTO recorded FROM updated;
					RETURN COALESCE(recorded, ARRAY[]::text[]);
				END; $$;
			`)
		})

		provisioning, err := sink.CheckProvisioningState(ctx)
		if err != nil {
			t.Fatalf("CheckProvisioningState: %v", err)
		}
		if provisioning.Provisioned {
			t.Fatalf("ADR-0007 Addendum 10 D87/D86 row 8: CheckProvisioningState reported Provisioned=true despite a substituted purge-writing definer body")
		}
		if !strings.Contains(provisioning.Reason, "screening_ledger_purge_snapshots") || !strings.Contains(provisioning.Reason, "D87") {
			t.Fatalf("expected the reason to name the function and cite D87, got %q", provisioning.Reason)
		}
		// D87's declared digest set is covered by CheckProvisioningState
		// (this assertion) and by D92's static, DSN-free derivation gate
		// (TestPurgeSnapshotsBodyDigestsMatchCommittedLiterals) -- unlike
		// D69/D77's trigger-bound functions, grant-ddl-ownership's own
		// bash preconditions have no shape for "a declared standalone
		// function's own body digest" to extend (D69/D77's precondition
		// loop is keyed off a TRIGGER binding these two functions do not
		// have), so grant-ddl-ownership is not asserted to refuse here.
	})

	t.Run("clean_migration_bootstrapped_database_accepted", func(t *testing.T) {
		clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
		cloneMigratorDSN := withDatabase(t, migratorDSN, clone.dbName)
		sink, err := NewPostgresSink(ctx, cloneMigratorDSN, 10*time.Second)
		if err != nil {
			t.Fatalf("NewPostgresSink: %v", err)
		}
		defer sink.Close(context.Background())
		provisioning, err := sink.CheckProvisioningState(ctx)
		if err != nil || !provisioning.Provisioned {
			t.Fatalf("expected a clean migration-bootstrapped clone to be Provisioned=true, got %+v err=%v", provisioning, err)
		}
	})

	t.Run("clean_schemasql_only_database_accepted", func(t *testing.T) {
		dsn := requireSchemaSQLOnlyDatabaseURL(t)
		sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
		if err != nil {
			t.Fatalf("NewPostgresSink: %v", err)
		}
		defer sink.Close(context.Background())
		if err := sink.Migrate(ctx); err != nil {
			t.Fatalf("Migrate on SchemaSQL-only database: %v", err)
		}
		var definerOK bool
		if err := sink.conn.QueryRow(ctx, `SELECT encode(sha256(convert_to(prosrc,'UTF8')),'hex') = ANY($2) FROM pg_proc WHERE oid = $1::regprocedure`,
			"screening_ledger_purge_snapshots(text[],text,int4[],timestamptz[],text,text)",
			[]string{purgeSnapshotsArrayFormBodySHA256Migration, purgeSnapshotsArrayFormBodySHA256SchemaSQLBoot},
		).Scan(&definerOK); err != nil {
			t.Fatal(err)
		}
		if !definerOK {
			t.Fatalf("expected the SchemaSQL-bootstrapped array-form body to be in the declared accepted set")
		}
	})
}
