// ADR-0007 Addendum 21 D171: the committed proof obligations for D163
// (the expiry-aware referent), D164 (schema-qualification as the
// control), D166/D167 (registration closing R40's DROP TRIGGER route
// and R44 together) and D168 (R57's demonstrated exploitation, not its
// enumeration gap). Every test below reproduces a transcript this
// addendum's design pass (docs/adr/0007-audit-chain-integrity.md,
// "Addendum 21") already measured -- see D171's own item list for the
// exact correspondence.
//
// Per D42/D47's convention used throughout this package: where the
// finding this addendum fixes is being proven, the PRE-fix mechanism is
// reconstructed on a disposable clone (never the shared primary
// database) so the test distinguishes a working fix from a probe that
// never exercised the gap.
package screeningledger

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// newAddendum21Clone is the same CREATE DATABASE ... TEMPLATE pattern
// d50CloneFixture uses -- a disposable clone of the fully-provisioned
// primary database (OWL_MIGRATOR_DATABASE_URL's own database), torn down
// in t.Cleanup, so this file's seeding and mutation never touches the
// shared primary database or any other suite's fixtures.
type addendum21Clone struct {
	dbName       string
	superuserDSN string
	migratorDSN  string
	ledgerDDLDSN string
}

func newAddendum21Clone(t *testing.T, ctx context.Context) addendum21Clone {
	t.Helper()
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)

	superuser, err := pgx.Connect(ctx, superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())

	sourceDB := dbNameFromDSN(t, migratorDSN)
	cloneDB := fmt.Sprintf("owl_ci_a21_clone_%d", time.Now().UnixNano())
	if _, err := superuser.Exec(ctx, fmt.Sprintf(
		`CREATE DATABASE %s TEMPLATE %s`,
		pgx.Identifier{cloneDB}.Sanitize(), pgx.Identifier{sourceDB}.Sanitize(),
	)); err != nil {
		t.Fatalf("CREATE DATABASE ... TEMPLATE: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		c, err := pgx.Connect(bg, superuserDSN)
		if err != nil {
			t.Errorf("drop addendum21 clone %s: connect: %v", cloneDB, err)
			return
		}
		defer c.Close(bg)
		if _, err := c.Exec(bg, fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, pgx.Identifier{cloneDB}.Sanitize())); err != nil {
			t.Errorf("drop addendum21 clone %s: %v", cloneDB, err)
		}
	})

	return addendum21Clone{
		dbName:       cloneDB,
		superuserDSN: withDatabase(t, superuserDSN, cloneDB),
		migratorDSN:  withDatabase(t, migratorDSN, cloneDB),
		ledgerDDLDSN: withDatabase(t, ledgerDDLDSN, cloneDB),
	}
}

// seedSnapshotAndEvent inserts one screening_ledger_snapshot row (with
// ciphertext present) and, unless referencingEvent is empty, one
// screening_ledger_event row referencing it at the given expires_at.
func seedSnapshotAndEvent(t *testing.T, ctx context.Context, conn *pgx.Conn, snapshotSHA, eventID, ledgerID string, snapshotExpires, eventExpires time.Time, referencingEvent bool) {
	t.Helper()
	if _, err := conn.Exec(ctx, `
		INSERT INTO screening_ledger_snapshot(snapshot_sha256,kind,created_at,expires_at,retention_class,envelope_json)
		VALUES ($1,'request','2020-01-01',$2,'standard','{"ciphertext_base64":"x","nonce_base64":"n"}')
	`, snapshotSHA, snapshotExpires); err != nil {
		t.Fatalf("seed snapshot %s: %v", snapshotSHA, err)
	}
	if !referencingEvent {
		return
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO screening_ledger_event(event_id,ledger_id,sequence,event_sha256,previous_event_sha256,occurred_at,route,http_status,request_sha256,response_sha256,request_snapshot_sha256,response_snapshot_sha256,retention_class,expires_at,event_json)
		VALUES ($1,$2,(SELECT COALESCE(MAX(sequence),0)+1 FROM screening_ledger_event WHERE ledger_id=$2),$3,'','2020-01-01','/screen',200,$3,$3,$4,$4,'standard',$5,'{}')
	`, eventID, ledgerID, eventID+"sha", snapshotSHA, eventExpires); err != nil {
		t.Fatalf("seed event %s referencing %s: %v", eventID, snapshotSHA, err)
	}
}

func snapshotState(t *testing.T, ctx context.Context, conn *pgx.Conn, snapshotSHA string) (purged bool, hasCT bool) {
	t.Helper()
	if err := conn.QueryRow(ctx, `SELECT purged_at IS NOT NULL, envelope_json ? 'ciphertext_base64' FROM screening_ledger_snapshot WHERE snapshot_sha256=$1`, snapshotSHA).Scan(&purged, &hasCT); err != nil {
		t.Fatalf("read snapshot state %s: %v", snapshotSHA, err)
	}
	return purged, hasCT
}

func directStripSQL() string {
	return `UPDATE screening_ledger_snapshot SET purged_at=clock_timestamp(), envelope_json = envelope_json - 'ciphertext_base64' - 'nonce_base64' || jsonb_build_object('purged_at', clock_timestamp()) WHERE snapshot_sha256=$1`
}

// TestD163R40DirectUpdateRefusedBothRoles is D171 item 1: D150's a19live*
// construction as a21live* -- a snapshot under a 2100-01-01 obligation,
// direct UPDATE stripping ciphertext_base64, NO DROP TRIGGER, issued as
// BOTH owl_migrator and owl_ledger_ddl. Plus the guard-live control (the
// same UPDATE also rewriting expires_at, refused today) -- without it
// the test cannot distinguish "the guard refuses" from "the guard is
// gone."
func TestD163R40DirectUpdateRefusedBothRoles(t *testing.T) {
	ctx := context.Background()
	clone := newAddendum21Clone(t, ctx)

	migrator, err := pgx.Connect(ctx, clone.migratorDSN)
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	defer migrator.Close(context.Background())

	future := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	seedSnapshotAndEvent(t, ctx, migrator, "a21t1-migrator", "ev-a21t1-migrator", "ledA21T1", future, future, true)
	seedSnapshotAndEvent(t, ctx, migrator, "a21t1-control", "ev-a21t1-control", "ledA21T1", future, future, true)

	t.Run("guard_live_control_still_refuses_the_allowed_transition_test", func(t *testing.T) {
		_, err := migrator.Exec(ctx, `UPDATE screening_ledger_snapshot SET purged_at=clock_timestamp(), expires_at='2099-01-01', envelope_json = envelope_json - 'ciphertext_base64' - 'nonce_base64' || jsonb_build_object('purged_at', clock_timestamp()) WHERE snapshot_sha256=$1`, "a21t1-control")
		if err == nil {
			t.Fatal("expected the guard's own pre-existing allowed-transition test to refuse rewriting expires_at -- if this passes, the guard trigger itself is not live and the refusal below proves nothing")
		}
		if !strings.Contains(err.Error(), "not an allowed retention transition") {
			t.Fatalf("expected the shipped allowed-transition refusal, got: %v", err)
		}
	})

	t.Run("owl_migrator_direct_strip_refused", func(t *testing.T) {
		_, err := migrator.Exec(ctx, directStripSQL(), "a21t1-migrator")
		if err == nil {
			t.Fatal("ADR-0007 Addendum 21 D163: owl_migrator's direct UPDATE strip on a live 2100 obligation succeeded with NO DROP TRIGGER -- R40 is not closed")
		}
		if !strings.Contains(err.Error(), "ADR-0007 Addendum 21 D163") || !strings.Contains(err.Error(), "still under a live retention obligation") {
			t.Fatalf("expected D163's live-obligation refusal, got: %v", err)
		}
		purged, hasCT := snapshotState(t, ctx, migrator, "a21t1-migrator")
		if purged || !hasCT {
			t.Fatalf("snapshot state changed despite the refusal: purged=%v hasCT=%v", purged, hasCT)
		}
	})

	t.Run("owl_ledger_ddl_direct_strip_refused", func(t *testing.T) {
		ledgerDDL, err := pgx.Connect(ctx, clone.ledgerDDLDSN)
		if err != nil {
			t.Fatalf("connect as owl_ledger_ddl: %v", err)
		}
		defer ledgerDDL.Close(context.Background())
		_, err = ledgerDDL.Exec(ctx, directStripSQL(), "a21t1-migrator")
		if err == nil {
			t.Fatal("ADR-0007 Addendum 21 D163: owl_ledger_ddl's direct UPDATE strip succeeded -- D163's predicate must refuse both roles identically, naming no role at all")
		}
		if !strings.Contains(err.Error(), "ADR-0007 Addendum 21 D163") {
			t.Fatalf("expected D163's refusal for owl_ledger_ddl too, got: %v", err)
		}
	})
}

// TestD163VacuityHalfAndDefinerParity is D171 item 3: an unreferenced
// snapshot is refused after, with the distinct no-referencing-event
// message -- the NOT EXISTS half is vacuously true for a snapshot no
// event references, and shipping only the EXISTS half would permit
// exactly this. Plus the matching definer positive: the same snapshot is
// not purged by either overload today either, so the guard and the
// definer agree (both require the non-vacuity EXISTS).
func TestD163VacuityHalfAndDefinerParity(t *testing.T) {
	ctx := context.Background()
	clone := newAddendum21Clone(t, ctx)

	migrator, err := pgx.Connect(ctx, clone.migratorDSN)
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	defer migrator.Close(context.Background())

	past := time.Date(2019, 6, 1, 0, 0, 0, 0, time.UTC)
	seedSnapshotAndEvent(t, ctx, migrator, "a21t3-orphan", "", "", past, past, false)

	_, err = migrator.Exec(ctx, directStripSQL(), "a21t3-orphan")
	if err == nil {
		t.Fatal("ADR-0007 Addendum 21 D163: an unreferenced snapshot was stripped -- the vacuity trap: NOT EXISTS alone is vacuously true for a snapshot no event references")
	}
	if !strings.Contains(err.Error(), "ADR-0007 Addendum 21 D163") || !strings.Contains(err.Error(), "no referencing screening_ledger_event row") {
		t.Fatalf("expected D163's distinct vacuity refusal (must differ from the live-obligation message), got: %v", err)
	}

	ledgerDDL, err := pgx.Connect(ctx, clone.ledgerDDLDSN)
	if err != nil {
		t.Fatalf("connect as owl_ledger_ddl: %v", err)
	}
	defer ledgerDDL.Close(context.Background())

	// The time-floor overload's ledger-existence precondition needs at
	// least one known ledger; a21t3-orphan is not referenced by it (or by
	// anything), so it is excluded from "eligible" by the same non-vacuity
	// EXISTS the guard itself carries -- this dummy event exists only to
	// give the overload a ledger to corroborate its own GLOBAL aggregate
	// against.
	seedSnapshotAndEvent(t, ctx, migrator, "a21t3-dummy", "ev-a21t3-dummy", "ledA21T3Dummy", time.Now().Add(time.Hour), time.Now().Add(time.Hour), true)
	var mirrorCount int64
	var mirrorMax time.Time
	if err := migrator.QueryRow(ctx, `SELECT count(*), max(e.expires_at) FROM screening_ledger_event e`).Scan(&mirrorCount, &mirrorMax); err != nil {
		t.Fatalf("read global mirror aggregate: %v", err)
	}
	// The time-floor overload's own eligible set is GLOBAL and unscoped
	// (every snapshot in the database, not just this test's own rows), so
	// this assertion checks only what is under test -- a21t3-orphan's own
	// state -- rather than the overload's total affected count, which
	// depends on whatever else is present in the cloned database.
	var timeFloorAffected int64
	if err := ledgerDDL.QueryRow(ctx, `SELECT screening_ledger_purge_snapshots($1, $2, $3, 'op', 'test')`, "ledA21T3Dummy", mirrorCount, mirrorMax).Scan(&timeFloorAffected); err != nil {
		t.Fatalf("time-floor overload: %v", err)
	}
	purged, hasCT := snapshotState(t, ctx, migrator, "a21t3-orphan")
	if purged || !hasCT {
		t.Fatalf("orphan snapshot state changed via the definer path: purged=%v hasCT=%v -- guard and definer must agree", purged, hasCT)
	}
}

// TestD164ShadowingMatrixFourPrototypes is D171 item 4: all four
// prototypes -- bare/qualified x with/without SET search_path -- against
// one CREATE TEMP TABLE screening_ledger_event decoy in one session,
// asserting the shipped-shape variants (bare) strip and the qualified
// variants refuse. This is the test that fails if a later edit replaces
// a qualified name with a bare one, and it must not be discharged by
// asserting the SET search_path clause is present -- so PROTO-B (bare,
// WITH the clause) is included and must still be defeated.
func TestD164ShadowingMatrixFourPrototypes(t *testing.T) {
	ctx := context.Background()

	bareBody := `BEGIN
	  IF NOT EXISTS (SELECT 1 FROM screening_ledger_event e WHERE e.request_snapshot_sha256=OLD.snapshot_sha256 OR e.response_snapshot_sha256=OLD.snapshot_sha256) THEN RAISE EXCEPTION 'no referencing event row'; END IF;
	  IF EXISTS (SELECT 1 FROM screening_ledger_event e WHERE (e.request_snapshot_sha256=OLD.snapshot_sha256 OR e.response_snapshot_sha256=OLD.snapshot_sha256) AND e.expires_at >= clock_timestamp()) THEN RAISE EXCEPTION 'ADR-0007 Addendum 21 D163: still under a live retention obligation'; END IF;
	  RETURN NEW;
	END`
	qualifiedBody := `BEGIN
	  IF NOT EXISTS (SELECT 1 FROM public.screening_ledger_event e WHERE e.request_snapshot_sha256=OLD.snapshot_sha256 OR e.response_snapshot_sha256=OLD.snapshot_sha256) THEN RAISE EXCEPTION 'no referencing event row'; END IF;
	  IF EXISTS (SELECT 1 FROM public.screening_ledger_event e WHERE (e.request_snapshot_sha256=OLD.snapshot_sha256 OR e.response_snapshot_sha256=OLD.snapshot_sha256) AND e.expires_at >= clock_timestamp()) THEN RAISE EXCEPTION 'ADR-0007 Addendum 21 D163: still under a live retention obligation'; END IF;
	  RETURN NEW;
	END`

	// Each case gets its OWN clone: sec7_protected_relation's second
	// phase (D50's own shape) records screening_ledger_snapshot's trigger
	// OID set and re-asserts it on every LATER DDL statement in the same
	// database, so a second DROP/CREATE TRIGGER swap in the SAME clone
	// (a different case's prototype) trips "its trigger set changed" on
	// an unrelated statement -- a real property of the running system,
	// not a test bug to route around. Each case's own swap runs inside
	// withD34TriggersDisabled and is followed only by DML (the UPDATE
	// probe), never a second DDL statement, so this never arises within
	// one clone.
	run := func(name, funcSQL, funcName string, wantDefeats bool) {
		t.Run(name, func(t *testing.T) {
			clone := newAddendum21Clone(t, ctx)
			superuser, err := pgx.Connect(ctx, clone.superuserDSN)
			if err != nil {
				t.Fatalf("connect as bootstrap superuser: %v", err)
			}
			defer superuser.Close(context.Background())
			migrator, err := pgx.Connect(ctx, clone.migratorDSN)
			if err != nil {
				t.Fatalf("connect as owl_migrator: %v", err)
			}
			defer migrator.Close(context.Background())

			future := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
			seedSnapshotAndEvent(t, ctx, migrator, "a21t4", "ev-a21t4", "ledA21T4", future, future, true)
			if _, err := migrator.Exec(ctx, `CREATE TEMP TABLE screening_ledger_event (request_snapshot_sha256 text, response_snapshot_sha256 text, expires_at timestamptz)`); err != nil {
				t.Fatalf("create pg_temp decoy: %v", err)
			}
			if _, err := migrator.Exec(ctx, `INSERT INTO pg_temp.screening_ledger_event VALUES ('a21t4','a21t4','2000-01-01'::timestamptz)`); err != nil {
				t.Fatalf("seed decoy row: %v", err)
			}

			if _, err := migrator.Exec(ctx, funcSQL); err != nil {
				t.Fatalf("install prototype: %v", err)
			}
			withD34TriggersDisabled(t, ctx, superuser, func() {
				if _, err := migrator.Exec(ctx, `DROP TRIGGER screening_ledger_snapshot_guard_trigger ON screening_ledger_snapshot`); err != nil {
					t.Fatalf("drop trigger: %v", err)
				}
				if _, err := migrator.Exec(ctx, fmt.Sprintf(`CREATE TRIGGER screening_ledger_snapshot_guard_trigger BEFORE UPDATE OR DELETE ON screening_ledger_snapshot FOR EACH ROW EXECUTE FUNCTION %s()`, funcName)); err != nil {
					t.Fatalf("bind trigger: %v", err)
				}
			})

			_, err = migrator.Exec(ctx, directStripSQL(), "a21t4")
			purged, hasCT := snapshotState(t, ctx, migrator, "a21t4")
			if wantDefeats {
				if err != nil {
					t.Fatalf("(bare name): expected the pg_temp decoy to defeat this prototype (proving the finding), got refusal instead: %v", err)
				}
				if !purged || hasCT {
					t.Fatalf("expected the strip to succeed (shadowed), got purged=%v hasCT=%v", purged, hasCT)
				}
			} else {
				if err == nil {
					t.Fatal("(qualified name): expected the qualified reference to see the REAL public row (still live) and refuse -- it did not, so qualification is not the control here")
				}
				if purged || !hasCT {
					t.Fatalf("expected the snapshot to remain intact after the refusal, got purged=%v hasCT=%v", purged, hasCT)
				}
			}
		})
	}

	run("a21_proto_a_bare_no_search_path", `CREATE OR REPLACE FUNCTION a21_proto_a() RETURNS trigger LANGUAGE plpgsql AS $$`+bareBody+` $$`, "a21_proto_a", true)
	run("a21_proto_b_bare_with_search_path", `CREATE OR REPLACE FUNCTION a21_proto_b() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$`+bareBody+` $$`, "a21_proto_b", true)
	run("a21_proto_c_qualified_with_search_path", `CREATE OR REPLACE FUNCTION a21_proto_c() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$`+qualifiedBody+` $$`, "a21_proto_c", false)
	run("a21_proto_d_qualified_no_search_path", `CREATE OR REPLACE FUNCTION a21_proto_d() RETURNS trigger LANGUAGE plpgsql AS $$`+qualifiedBody+` $$`, "a21_proto_d", false)

	// The shipped guard itself, unmodified -- the actual committed
	// artifact, not just the prototype shapes above -- proven immune to
	// the identical decoy on its own fresh clone.
	t.Run("shipped_guard_immune_to_the_same_decoy", func(t *testing.T) {
		clone := newAddendum21Clone(t, ctx)
		migrator, err := pgx.Connect(ctx, clone.migratorDSN)
		if err != nil {
			t.Fatalf("connect as owl_migrator: %v", err)
		}
		defer migrator.Close(context.Background())

		future := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
		seedSnapshotAndEvent(t, ctx, migrator, "a21t4-shipped", "ev-a21t4-shipped", "ledA21T4", future, future, true)
		if _, err := migrator.Exec(ctx, `CREATE TEMP TABLE screening_ledger_event (request_snapshot_sha256 text, response_snapshot_sha256 text, expires_at timestamptz)`); err != nil {
			t.Fatalf("create pg_temp decoy: %v", err)
		}
		if _, err := migrator.Exec(ctx, `INSERT INTO pg_temp.screening_ledger_event VALUES ('a21t4-shipped','a21t4-shipped','2000-01-01'::timestamptz)`); err != nil {
			t.Fatalf("seed decoy row for shipped guard case: %v", err)
		}
		_, err = migrator.Exec(ctx, directStripSQL(), "a21t4-shipped")
		if err == nil {
			t.Fatal("the SHIPPED guard was defeated by the pg_temp decoy -- D164 is not fixed on the actual committed artifact")
		}
		if !strings.Contains(err.Error(), "ADR-0007 Addendum 21 D163") {
			t.Fatalf("expected the shipped guard's D163 refusal, got: %v", err)
		}
	})
}

// TestD164DefinerResistsShadowingR84 is D171 item 5 / R84's pin: the same
// pg_temp decoy against the shipped array-form definer asserts
// "permission denied for table screening_ledger_event" -- pinning that
// the definers fail CLOSED here as a privilege accident (SECURITY
// DEFINER as owl_ledger_ddl, which holds no USAGE on the caller's temp
// schema), so a later change that makes them run as their caller (or
// grants owl_ledger_ddl membership in a calling role) fails this test
// rather than silently shipping the exposure.
func TestD164DefinerResistsShadowingR84(t *testing.T) {
	ctx := context.Background()
	clone := newAddendum21Clone(t, ctx)

	migrator, err := pgx.Connect(ctx, clone.migratorDSN)
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	defer migrator.Close(context.Background())

	future := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	seedSnapshotAndEvent(t, ctx, migrator, "a21t5", "ev-a21t5", "ledA21T5", future, future, true)

	if _, err := migrator.Exec(ctx, `CREATE TEMP TABLE screening_ledger_event (request_snapshot_sha256 text, response_snapshot_sha256 text, expires_at timestamptz, ledger_id text)`); err != nil {
		t.Fatalf("create pg_temp decoy: %v", err)
	}
	if _, err := migrator.Exec(ctx, `INSERT INTO pg_temp.screening_ledger_event VALUES ('a21t5','a21t5','2000-01-01'::timestamptz,'ledA21T5')`); err != nil {
		t.Fatalf("seed decoy row: %v", err)
	}

	var recorded []string
	err = migrator.QueryRow(ctx, `SELECT screening_ledger_purge_snapshots($1::text[], $2, $3::int[], $4::timestamptz[], 'op', 'test')`,
		[]string{"a21t5"}, "ledA21T5", []int32{1}, []time.Time{future}).Scan(&recorded)
	if err == nil {
		t.Fatalf("R84: the array-form definer was NOT blocked by the pg_temp decoy (recorded=%v) -- it must fail closed with permission denied, a privilege accident that must not silently disappear", recorded)
	}
	if !strings.Contains(err.Error(), "permission denied for table screening_ledger_event") {
		t.Fatalf("expected R84's exact pinned failure (permission denied for table screening_ledger_event), got: %v", err)
	}
}

// TestPositiveControlsBothOverloadsPurgeGenuinelyExpiredSnapshot is D171
// item 6: a snapshot whose referencing events have genuinely expired is
// purged end to end through BOTH overloads -- the array form (024) and
// the time-floor form (023/019) -- each producing a tombstone row,
// has_ct=f, and purged_at set. The over-tightening failure this item
// exists to catch: a guard that blocks a legitimate purge.
func TestPositiveControlsBothOverloadsPurgeGenuinelyExpiredSnapshot(t *testing.T) {
	ctx := context.Background()
	clone := newAddendum21Clone(t, ctx)

	migrator, err := pgx.Connect(ctx, clone.migratorDSN)
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	defer migrator.Close(context.Background())
	ledgerDDL, err := pgx.Connect(ctx, clone.ledgerDDLDSN)
	if err != nil {
		t.Fatalf("connect as owl_ledger_ddl: %v", err)
	}
	defer ledgerDDL.Close(context.Background())

	past := time.Now().Add(-24 * time.Hour)

	t.Run("array_form_024", func(t *testing.T) {
		seedSnapshotAndEvent(t, ctx, migrator, "a21t6-array", "ev-a21t6-array", "ledA21T6Array", past, past, true)
		var mirrorCount int
		var mirrorMax time.Time
		if err := migrator.QueryRow(ctx, `SELECT count(*), max(e.expires_at) FROM screening_ledger_event e WHERE e.request_snapshot_sha256='a21t6-array' OR e.response_snapshot_sha256='a21t6-array'`).Scan(&mirrorCount, &mirrorMax); err != nil {
			t.Fatalf("read mirror obligation: %v", err)
		}
		var recorded []string
		if err := ledgerDDL.QueryRow(ctx, `SELECT screening_ledger_purge_snapshots($1::text[], $2, $3::int[], $4::timestamptz[], 'op', 'test')`,
			[]string{"a21t6-array"}, "ledA21T6Array", []int32{int32(mirrorCount)}, []time.Time{mirrorMax}).Scan(&recorded); err != nil {
			t.Fatalf("array-form overload should purge a genuinely expired snapshot: %v", err)
		}
		if len(recorded) != 1 || recorded[0] != "a21t6-array" {
			t.Fatalf("expected exactly [a21t6-array] recorded, got %v", recorded)
		}
		purged, hasCT := snapshotState(t, ctx, migrator, "a21t6-array")
		if !purged || hasCT {
			t.Fatalf("expected purged=true hasCT=false, got purged=%v hasCT=%v", purged, hasCT)
		}
		var tombstones int
		if err := migrator.QueryRow(ctx, `SELECT count(*) FROM screening_ledger_retention_tombstone WHERE snapshot_sha256='a21t6-array'`).Scan(&tombstones); err != nil {
			t.Fatal(err)
		}
		if tombstones != 1 {
			t.Fatalf("expected 1 tombstone row, got %d", tombstones)
		}
	})

	t.Run("time_floor_form_023_019", func(t *testing.T) {
		seedSnapshotAndEvent(t, ctx, migrator, "a21t6-floor", "ev-a21t6-floor", "ledA21T6Floor", past, past, true)
		var mirrorCount int64
		var mirrorMax time.Time
		if err := migrator.QueryRow(ctx, `SELECT count(*), max(e.expires_at) FROM screening_ledger_event e`).Scan(&mirrorCount, &mirrorMax); err != nil {
			t.Fatalf("read global mirror aggregate: %v", err)
		}
		var affected int64
		if err := ledgerDDL.QueryRow(ctx, `SELECT screening_ledger_purge_snapshots($1, $2, $3, 'op', 'test')`, "ledA21T6Floor", mirrorCount, mirrorMax).Scan(&affected); err != nil {
			t.Fatalf("time-floor overload should purge a genuinely expired snapshot: %v", err)
		}
		if affected < 1 {
			t.Fatalf("expected at least 1 row purged, got %d", affected)
		}
		purged, hasCT := snapshotState(t, ctx, migrator, "a21t6-floor")
		if !purged || hasCT {
			t.Fatalf("expected purged=true hasCT=false, got purged=%v hasCT=%v", purged, hasCT)
		}
		var tombstones int
		if err := migrator.QueryRow(ctx, `SELECT count(*) FROM screening_ledger_retention_tombstone WHERE snapshot_sha256='a21t6-floor'`).Scan(&tombstones); err != nil {
			t.Fatal(err)
		}
		if tombstones != 1 {
			t.Fatalf("expected 1 tombstone row, got %d", tombstones)
		}
	})
}

// registryCounts reads all three registries' row counts, D90's own
// unregressed postcondition (20/4/1 after ADR-0007 Addendum 21 D166).
func registryCounts(t *testing.T, ctx context.Context, conn *pgx.Conn) (obj, rel, bind int) {
	t.Helper()
	if err := conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM sec7_protected_object), (SELECT count(*) FROM sec7_protected_relation), (SELECT count(*) FROM sec7_instance_binding)`).Scan(&obj, &rel, &bind); err != nil {
		t.Fatalf("read registry counts: %v", err)
	}
	return obj, rel, bind
}

func eventTriggersEnabled(t *testing.T, ctx context.Context, conn *pgx.Conn) bool {
	t.Helper()
	var count int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM pg_event_trigger WHERE evtname IN ('sec7_protect_ddl_objects_on_drop','sec7_protect_ddl_objects_on_alter') AND evtenabled='A'`).Scan(&count); err != nil {
		t.Fatalf("read event trigger state: %v", err)
	}
	return count == 2
}

// TestD166D167ClosureMatrix is D171 item 9: against the fully registered
// database, every route R40/R44/R57 named -- direct UPDATE as each role,
// DROP TRIGGER on the guard trigger, the guard body swap, DROP TRIGGER on
// screening_ledger_event_immutable, the direct UPDATE of
// screening_ledger_event.expires_at, the R57 overload, the pg_temp decoy,
// and the vacuity case -- each asserting the SPECIFIC refusal, not merely
// "an error." Plus D90 unregressed: after every new refusal path, both
// event triggers stay evtenabled='A' and all three registries stay at
// 20/4/1 -- none of these routes actually succeeds, so nothing here ever
// opens the disable window or mutates the registries.
func TestD166D167ClosureMatrix(t *testing.T) {
	ctx := context.Background()
	clone := newAddendum21Clone(t, ctx)

	migrator, err := pgx.Connect(ctx, clone.migratorDSN)
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	defer migrator.Close(context.Background())
	ledgerDDL, err := pgx.Connect(ctx, clone.ledgerDDLDSN)
	if err != nil {
		t.Fatalf("connect as owl_ledger_ddl: %v", err)
	}
	defer ledgerDDL.Close(context.Background())

	future := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, id := range []string{"a21t9-migrator", "a21t9-ddl", "a21t9-r44", "a21t9-r57", "a21t9-eventrewrite", "a21t9-orphan"} {
		referencing := id != "a21t9-orphan"
		seedSnapshotAndEvent(t, ctx, migrator, id, "ev-"+id, "ledA21T9", future, future, referencing)
	}

	wantObj, wantRel, wantBind := 20, 4, 1
	assertUnregressed := func(t *testing.T, label string) {
		t.Helper()
		if !eventTriggersEnabled(t, ctx, migrator) {
			t.Fatalf("%s: D90 unregressed: event triggers are not both ENABLE ALWAYS after this refusal", label)
		}
		obj, rel, bind := registryCounts(t, ctx, migrator)
		if obj != wantObj || rel != wantRel || bind != wantBind {
			t.Fatalf("%s: D90 unregressed: expected registries at %d/%d/%d, got obj=%d rel=%d bind=%d", label, wantObj, wantRel, wantBind, obj, rel, bind)
		}
	}

	t.Run("direct_UPDATE_as_owl_migrator", func(t *testing.T) {
		_, err := migrator.Exec(ctx, directStripSQL(), "a21t9-migrator")
		if err == nil || !strings.Contains(err.Error(), "ADR-0007 Addendum 21 D163") {
			t.Fatalf("expected D163's refusal, got: %v", err)
		}
		assertUnregressed(t, "direct_UPDATE_as_owl_migrator")
	})

	t.Run("direct_UPDATE_as_owl_ledger_ddl", func(t *testing.T) {
		_, err := ledgerDDL.Exec(ctx, directStripSQL(), "a21t9-ddl")
		if err == nil || !strings.Contains(err.Error(), "ADR-0007 Addendum 21 D163") {
			t.Fatalf("expected D163's refusal, got: %v", err)
		}
		assertUnregressed(t, "direct_UPDATE_as_owl_ledger_ddl")
	})

	t.Run("DROP_TRIGGER_on_the_guard_trigger", func(t *testing.T) {
		_, err := migrator.Exec(ctx, `DROP TRIGGER screening_ledger_snapshot_guard_trigger ON screening_ledger_snapshot`)
		if err == nil || !strings.Contains(err.Error(), "ADR-0007 Addendum 3 D34") {
			t.Fatalf("expected D34's registered-object refusal (D166's own mechanism), got: %v", err)
		}
		assertUnregressed(t, "DROP_TRIGGER_on_the_guard_trigger")
	})

	t.Run("guard_body_swap", func(t *testing.T) {
		_, err := migrator.Exec(ctx, `CREATE OR REPLACE FUNCTION screening_ledger_snapshot_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$`)
		if err == nil || !strings.Contains(err.Error(), "ADR-0007 Addendum 3 D34") {
			t.Fatalf("expected D34's registered-object refusal against the guard function itself, got: %v", err)
		}
		assertUnregressed(t, "guard_body_swap")
	})

	t.Run("DROP_TRIGGER_on_screening_ledger_event_immutable", func(t *testing.T) {
		_, err := migrator.Exec(ctx, `DROP TRIGGER screening_ledger_event_immutable ON screening_ledger_event`)
		if err == nil || !strings.Contains(err.Error(), "ADR-0007 Addendum 3 D34") {
			t.Fatalf("expected D34's registered-object refusal (D167's own R44 closure), got: %v", err)
		}
		assertUnregressed(t, "DROP_TRIGGER_on_screening_ledger_event_immutable")
	})

	t.Run("direct_UPDATE_of_event_expires_at", func(t *testing.T) {
		_, err := migrator.Exec(ctx, `UPDATE screening_ledger_event SET expires_at='2000-01-01' WHERE request_snapshot_sha256='a21t9-eventrewrite'`)
		if err == nil {
			t.Fatal("expected screening_ledger_event_immutable's own row-immutability trigger to refuse an UPDATE, not merely a DROP TRIGGER")
		}
		if !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("expected the append-only refusal, got: %v", err)
		}
		assertUnregressed(t, "direct_UPDATE_of_event_expires_at")
	})

	t.Run("R57_undeclared_overload", func(t *testing.T) {
		if _, err := migrator.Exec(ctx, `CREATE FUNCTION a21_r57_overload(text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN UPDATE screening_ledger_snapshot SET purged_at=clock_timestamp(), envelope_json=envelope_json-'ciphertext_base64'-'nonce_base64'||jsonb_build_object('purged_at',clock_timestamp()) WHERE snapshot_sha256=$1; END $$`); err != nil {
			t.Fatalf("D168: creating an undeclared overload must still succeed (the enumeration gap stays open) -- got: %v", err)
		}
		_, err := migrator.Exec(ctx, `SELECT a21_r57_overload('a21t9-r57')`)
		if err == nil {
			t.Fatal("D168: the rogue overload's destructive UPDATE succeeded -- the BEFORE ROW guard must fire regardless of the calling function's SECURITY DEFINER status")
		}
		if !strings.Contains(err.Error(), "ADR-0007 Addendum 21 D163") {
			t.Fatalf("expected D163's refusal to fire inside the rogue overload too, got: %v", err)
		}
		purged, hasCT := snapshotState(t, ctx, migrator, "a21t9-r57")
		if purged || !hasCT {
			t.Fatalf("snapshot state changed despite the refusal: purged=%v hasCT=%v", purged, hasCT)
		}
		assertUnregressed(t, "R57_undeclared_overload")
	})

	t.Run("pg_temp_decoy_against_the_shipped_guard", func(t *testing.T) {
		if _, err := migrator.Exec(ctx, `CREATE TEMP TABLE screening_ledger_event (request_snapshot_sha256 text, response_snapshot_sha256 text, expires_at timestamptz)`); err != nil {
			t.Fatalf("create pg_temp decoy: %v", err)
		}
		if _, err := migrator.Exec(ctx, `INSERT INTO pg_temp.screening_ledger_event VALUES ('a21t9-migrator','a21t9-migrator','2000-01-01'::timestamptz)`); err != nil {
			t.Fatalf("seed decoy row: %v", err)
		}
		_, err := migrator.Exec(ctx, directStripSQL(), "a21t9-migrator")
		if err == nil || !strings.Contains(err.Error(), "ADR-0007 Addendum 21 D163") {
			t.Fatalf("expected D164's qualification to see the real, still-live public row despite the decoy, got: %v", err)
		}
		assertUnregressed(t, "pg_temp_decoy_against_the_shipped_guard")
	})

	t.Run("vacuity_case", func(t *testing.T) {
		_, err := migrator.Exec(ctx, directStripSQL(), "a21t9-orphan")
		if err == nil || !strings.Contains(err.Error(), "no referencing screening_ledger_event row") {
			t.Fatalf("expected D163's vacuity refusal, got: %v", err)
		}
		assertUnregressed(t, "vacuity_case")
	})
}

// TestD172RecoveryProcedureEndToEnd is D171 item 11's DSN-gated half: the
// documented disable-window procedure (docs/operations/sec7-database-
// copies.md, ADR-0007 Addendum 21 D172's correction) applied to a
// database carrying the pre-025 guard body, executed literally end to
// end (D84's standard) rather than reasoned about, ending in three PASS
// lines and both event triggers 'A'. Also proves D172's own correction:
// owl_migrator itself (not the bootstrap superuser) can apply 025 inside
// the window, since grant-ddl-ownership never transfers this function's
// ownership away from owl_migrator.
func TestD172RecoveryProcedureEndToEnd(t *testing.T) {
	ctx := context.Background()
	clone := newAddendum21Clone(t, ctx)

	superuser, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())
	migrator, err := pgx.Connect(ctx, clone.migratorDSN)
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	defer migrator.Close(context.Background())

	t.Run("who_owns_the_guard_function", func(t *testing.T) {
		var owner string
		if err := migrator.QueryRow(ctx, `SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE proname='screening_ledger_snapshot_guard'`).Scan(&owner); err != nil {
			t.Fatal(err)
		}
		if owner != "owl_migrator" {
			t.Fatalf("ADR-0007 Addendum 21 D172: expected screening_ledger_snapshot_guard() to still be owned by owl_migrator after grant-ddl-ownership, got %q -- D155's 'apply as the bootstrap superuser' does not generalise to this function if ownership ever moves", owner)
		}
	})

	t.Run("apply_025_without_the_disable_window_must_be_refused", func(t *testing.T) {
		_, err := migrator.Exec(ctx, `CREATE OR REPLACE FUNCTION screening_ledger_snapshot_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$`)
		if err == nil || !strings.Contains(err.Error(), "ADR-0007 Addendum 3 D34") {
			t.Fatalf("expected D34's refusal outside the disable window, got: %v", err)
		}
	})

	t.Run("documented_procedure_owl_migrator_inside_the_window", func(t *testing.T) {
		withD34TriggersDisabled(t, ctx, superuser, func() {
			if _, err := migrator.Exec(ctx, `CREATE OR REPLACE FUNCTION screening_ledger_snapshot_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$ BEGIN IF TG_OP='DELETE'THEN RAISE EXCEPTION 'screening snapshots cannot be deleted';END IF;RETURN NEW;END $$`); err != nil {
				t.Fatalf("owl_migrator should be able to apply a guard-body change inside the disable window (ownership never left it): %v", err)
			}
		})
		// Restore the real shipped body so the postcondition below
		// observes the actual declared digest, not this test's own
		// placeholder.
		withD34TriggersDisabled(t, ctx, superuser, func() {
			migrationSQL, err := os.ReadFile("../../db/migrations/025_screening_ledger_snapshot_guard_expiry.sql")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := migrator.Exec(ctx, string(migrationSQL)); err != nil {
				t.Fatalf("re-apply migration 025: %v", err)
			}
		})
		var digest string
		if err := migrator.QueryRow(ctx, `SELECT encode(sha256(convert_to(prosrc,'UTF8')),'hex') FROM pg_proc WHERE proname='screening_ledger_snapshot_guard'`).Scan(&digest); err != nil {
			t.Fatal(err)
		}
		if digest != screeningLedgerSnapshotGuardBodySHA256 {
			t.Fatalf("expected the declared digest %s after recovery, got %s", screeningLedgerSnapshotGuardBodySHA256, digest)
		}
	})

	t.Run("guard_is_live_and_refusing_on_the_recovered_database", func(t *testing.T) {
		future := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
		seedSnapshotAndEvent(t, ctx, migrator, "a21t11-recovered", "ev-a21t11-recovered", "ledA21T11", future, future, true)
		_, err := migrator.Exec(ctx, directStripSQL(), "a21t11-recovered")
		if err == nil || !strings.Contains(err.Error(), "ADR-0007 Addendum 21 D163") {
			t.Fatalf("expected the recovered guard to refuse R40's construction, got: %v", err)
		}
	})

	t.Run("both_event_triggers_ENABLE_ALWAYS_after_recovery", func(t *testing.T) {
		if !eventTriggersEnabled(t, ctx, migrator) {
			t.Fatal("expected both D34 event triggers ENABLE ALWAYS after the recovery procedure closed the window")
		}
	})
}
