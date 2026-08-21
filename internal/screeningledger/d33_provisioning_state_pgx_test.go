// ADR-0007 Addendum 3 D33/D37 (G-A, HIGH): CAP #2 built a database with
// all sixteen migrations applied and provisioning skipped -- migrate
// printed {"status":"ok"} at exit 0, owl_migrator owned both protected
// tables, no event trigger existed, the tombstone forgery succeeded, and
// ALTER TABLE ... DISABLE TRIGGER on the anchor's own guard succeeded
// with Migrate() never re-enabling it. D33 names the second completion
// condition (provisioning, not just schema) and asserts it where it is
// load-bearing: reported by Migrate(), required by VerifyAnchored.
//
// Reproducing this needs a database in exactly that state -- every
// migration applied, scripts/ci/provision_test_roles.sh grant-ddl-
// ownership never run. It cannot be built against owl_ci: that step
// already ran there. See provision_test_roles.sh's create-unprovisioned-
// database subcommand and OWL_MIGRATOR_UNPROVISIONED_DATABASE_URL.
package screeningledger

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func requireUnprovisionedDatabaseURL(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OWL_MIGRATOR_UNPROVISIONED_DATABASE_URL")
	if dsn == "" {
		t.Skip("OWL_MIGRATOR_UNPROVISIONED_DATABASE_URL not set; ADR-0007 Addendum 3 D33/G-A regression requires a live Postgres database migrated in full but never provisioned via grant-ddl-ownership (see scripts/ci/provision_test_roles.sh create-unprovisioned-database and scripts/ci/run-ci.sh)")
	}
	return dsn
}

// TestVerifyAnchoredRefusesUnprovisionedDatabase is D33's required
// reproduction: CAP #2 §7.5's owl_p4 state, reached with no migration
// missing at all -- only provisioning. Before this fix, nothing anywhere
// observed the difference; VerifyAnchored must now refuse.
func TestVerifyAnchoredRefusesUnprovisionedDatabase(t *testing.T) {
	dsn := requireUnprovisionedDatabaseURL(t)
	ctx := context.Background()

	sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())

	// Confirmed part of the CAP's own finding: Migrate() still reports
	// success on this database (schema is complete -- every migration
	// ran; only provisioning is missing, and D21's schema check is
	// deliberately silent about that).
	if err := sink.Migrate(ctx); err != nil {
		t.Fatalf("Migrate() should still report success on a database with a complete schema (D21 point 3: ownership/provisioning is reported, not enforced, by the schema check): %v", err)
	}

	store, err := NewStore(t.TempDir(), testKey(), uniqueID("sec7-unprovisioned"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(testAppendInput()); err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(store.ledgerID)
	kAnchor := make([]byte, 32)
	for i := range kAnchor {
		kAnchor[i] = byte(i + 7)
	}

	_, err = store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: policy, Purges: sink},
		Anchors:       sink, Provisioning: sink, KAnchor: kAnchor, AllowGenesis: true,
	})
	if err == nil {
		t.Fatal("CAP #2 §7.5's owl_p4 state: VerifyAnchored succeeded against a fully migrated but never-provisioned database (ADR-0007 Addendum 3 D33)")
	}
	if !strings.Contains(err.Error(), "not fully provisioned") {
		t.Fatalf("expected the error to name provisioning incompleteness (ADR-0007 Addendum 3 D33), got: %v", err)
	}
}

// TestCheckProvisioningStateDetectsStaleRegistryRow is ADR-0007
// Addendum 3 R15: "a stale registry fails open... accepted only because
// D33 closes it: requiredProvisioningState asserts that every registry
// row's OID resolves to the object it claims." A fabricated OID that
// resolves to nothing in pg_class/pg_proc/pg_trigger must be reported as
// unprovisioned.
//
// owl_migrator only has SELECT on sec7_protected_object (by design --
// nobody but the bootstrap superuser writes to the registry), so the
// fabricated row is inserted and removed via
// OWL_BOOTSTRAP_SUPERUSER_DATABASE_URL, committed rather than left in an
// open transaction: the check itself runs over a separate connection
// (as owl_migrator, mirroring the real runtime path), which would not
// see an uncommitted insert from a different session.
func TestCheckProvisioningStateDetectsStaleRegistryRow(t *testing.T) {
	migratorDSN := requireMigratorDSN(t)
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	ctx := context.Background()

	sink, err := NewPostgresSink(ctx, migratorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())

	baseline, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("baseline CheckProvisioningState: %v", err)
	}
	if !baseline.Provisioned {
		t.Fatalf("expected the primary test database to be fully provisioned already, got Reason=%q", baseline.Reason)
	}

	superuser, err := pgx.Connect(ctx, superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())

	// 4294967295 (max uint32) is not a real OID any live catalog entry
	// will ever have in this fresh test cluster. Repointed via UPDATE,
	// not INSERTed as a 13th row: ADR-0007 Addendum 4 D41 checks
	// population (exact row count) before identity, so an extra row
	// would be reported as "padded" rather than exercising the
	// stale-OID identity path this test is specifically about.
	const fakeOID = 4294967295
	var originalOID uint32
	if err := superuser.QueryRow(ctx, `SELECT objid FROM sec7_protected_object WHERE note LIKE 'table: screening_ledger_anchor%'`).Scan(&originalOID); err != nil {
		t.Fatalf("read the anchor table's registry row: %v", err)
	}
	if _, err := superuser.Exec(ctx, `UPDATE sec7_protected_object SET objid = $1 WHERE note LIKE 'table: screening_ledger_anchor%'`, fakeOID); err != nil {
		t.Fatalf("repoint registry row to a stale OID: %v", err)
	}
	t.Cleanup(func() {
		cleanup, err := pgx.Connect(context.Background(), superuserDSN)
		if err != nil {
			t.Errorf("restoring repointed registry row: connect: %v", err)
			return
		}
		defer cleanup.Close(context.Background())
		if _, err := cleanup.Exec(context.Background(), `UPDATE sec7_protected_object SET objid = $1 WHERE objid = $2`, originalOID, fakeOID); err != nil {
			t.Errorf("restoring repointed registry row: %v", err)
		}
	})

	state, err := sink.checkProvisioningState(ctx)
	if err != nil {
		t.Fatalf("checkProvisioningState: %v", err)
	}
	if state.Provisioned {
		t.Fatal("expected a stale registry row (objid resolving to nothing) to be reported as unprovisioned (ADR-0007 Addendum 3 R15)")
	}
	if !strings.Contains(state.Reason, "stale") {
		t.Fatalf("expected the reason to name the registry as stale, got: %q", state.Reason)
	}
}

// TestMigrateFailsOnDisabledGuardTrigger is D33's second required
// reproduction: CAP §7.5's owl_p4 finding continued -- as owl_migrator
// (which still owns screening_ledger_anchor on an unprovisioned
// database), ALTER TABLE ... DISABLE TRIGGER succeeds, and Migrate()
// used to return nil and leave the trigger disabled (triggerExists
// matched tgname/tgrelid but never read tgenabled). triggerEnabled now
// asserts tgenabled='O' unconditionally, so Migrate() must refuse.
func TestMigrateFailsOnDisabledGuardTrigger(t *testing.T) {
	dsn := requireUnprovisionedDatabaseURL(t)
	ctx := context.Background()

	sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())
	if err := sink.Migrate(ctx); err != nil {
		t.Fatalf("baseline Migrate(): %v", err)
	}

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	defer conn.Close(context.Background())

	if _, err := conn.Exec(ctx, `ALTER TABLE screening_ledger_anchor DISABLE TRIGGER screening_ledger_anchor_immutable`); err != nil {
		t.Fatalf("CAP #2 §7.5: disabling the guard trigger (owl_migrator owns this table on an unprovisioned database) should succeed -- got an error instead, which would mean the fixture no longer reproduces the finding: %v", err)
	}
	// A fresh connection, not conn: this test's own `defer conn.Close(...)`
	// runs (in LIFO order with other defers) when this function returns,
	// which is BEFORE t.Cleanup callbacks run -- reusing conn here would
	// silently no-op against an already-closed connection, leaving the
	// shared database's trigger disabled for every later test.
	t.Cleanup(func() {
		restore, err := pgx.Connect(context.Background(), dsn)
		if err != nil {
			t.Errorf("re-enabling the guard trigger: connect: %v", err)
			return
		}
		defer restore.Close(context.Background())
		if _, err := restore.Exec(context.Background(), `ALTER TABLE screening_ledger_anchor ENABLE TRIGGER screening_ledger_anchor_immutable`); err != nil {
			t.Errorf("re-enabling the guard trigger: %v", err)
		}
	})

	if err := sink.Migrate(ctx); err == nil {
		t.Fatal("CAP #2 §7.5: Migrate() succeeded with screening_ledger_anchor_immutable disabled; expected a named schema-incomplete error (ADR-0007 Addendum 3 D33) -- a disabled trigger is not a present one")
	} else if !strings.Contains(err.Error(), "screening_ledger_anchor_immutable") {
		t.Fatalf("expected Migrate()'s error to name the disabled trigger, got: %v", err)
	}
}
