// ADR-0007 Addendum 10 D90/D95 test 4 (N-B, HIGH): a refusal must restore
// what it took down, including what the restored objects READ. D79's own
// five refusal cases (d79_refusal_no_disarm_pgx_test.go) all fail during
// the D62(a)/D69/D77/D80 precondition loops, which run entirely as SELECT
// queries BEFORE grant-ddl-ownership's failure trap is even armed -- none
// of them ever exercises the trap at all. The gap this test closes is a
// failure AFTER the trap is armed: a psql error, the row-count assertion,
// or (as reproduced here) a forced error landing between the registry
// DELETEs and their re-population -- D79's own comment names exactly this
// class ("a psql error, the row-count assertion below, a later refusal").
//
// Reproduced with a one-shot trigger on sec7_protected_object, backed by
// a SEQUENCE (non-transactional, so its state survives the aborting
// transaction) rather than a table flag (a table UPDATE inside the same
// aborting transaction as the RAISE would itself roll back, making the
// "fires exactly once" property untestable) -- confirmed by execution
// during this addendum's implementation pass that a table-flag version
// fires on every retry, not once.
package screeningledger

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// installA10OneShotRegistryFailure disables both event triggers, installs
// a trigger on sec7_protected_object that raises exactly once (on the
// first INSERT it sees) via a SEQUENCE-backed counter, then re-enables
// both event triggers ENABLE ALWAYS -- reproducing "an operator has
// already re-enabled enforcement and is re-running grant-ddl-ownership
// when a transient failure strikes its own registry re-population."
func installA10OneShotRegistryFailure(t *testing.T, ctx context.Context, superuser *pgx.Conn) {
	t.Helper()
	mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop DISABLE`)
	mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE`)
	mustExec(t, ctx, superuser, `CREATE SEQUENCE a10_oneshot_seq`)
	mustExec(t, ctx, superuser, `
		CREATE OR REPLACE FUNCTION a10_oneshot_trigger() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF nextval('a10_oneshot_seq') = 1 THEN
				RAISE EXCEPTION 'ADR-0007 Addendum 10 D90 test: simulated one-shot failure between the registry DELETEs and their re-population';
			END IF;
			RETURN NEW;
		END $$`)
	mustExec(t, ctx, superuser, `CREATE TRIGGER a10_oneshot_before_insert BEFORE INSERT ON sec7_protected_object FOR EACH ROW EXECUTE FUNCTION a10_oneshot_trigger()`)
	mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop ENABLE ALWAYS`)
	mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter ENABLE ALWAYS`)
}

func registryRowCounts(t *testing.T, ctx context.Context, conn *pgx.Conn) (obj, rel, bind int) {
	t.Helper()
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM sec7_protected_object`).Scan(&obj); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM sec7_protected_relation`).Scan(&rel); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM sec7_instance_binding`).Scan(&bind); err != nil {
		t.Fatal(err)
	}
	return
}

// mAForgery is M-A's own one-statement reproduction (Addendum 9's
// CRITICAL): CREATE OR REPLACE the shared row-immutability guard function
// as owl_migrator, with NO event-trigger disable of its own. Succeeding
// means DDL enforcement is not actually live.
func mAForgery(ctx context.Context, migratorConn *pgx.Conn) error {
	_, err := migratorConn.Exec(ctx, `CREATE OR REPLACE FUNCTION public.screening_ledger_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$`)
	return err
}

// TestRefusalRestoresTheDeclaredState is D90/D95 test 4: a failure after
// the trap is armed restores both event triggers to ENABLE ALWAYS AND all
// three registries to their declared row counts (13/2/1) -- not merely
// "unchanged from before," since the whole point is recovering FROM a
// state where they were already taken down. Before this fix: evtenabled
// 'O'/'O' and an EMPTY sec7_protected_object (0 rows), and M-A's forgery
// succeeds against that trap-restored database.
func TestRefusalRestoresTheDeclaredState(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()
	scriptPath := d62ScriptPath(t)

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	superuser, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())

	installA10OneShotRegistryFailure(t, ctx, superuser)

	output, runErr := runGrantDDLOwnership(t, scriptPath, clone.superuserDSN, clone.dbName)
	if runErr == nil {
		t.Fatalf("expected grant-ddl-ownership to fail on the injected one-shot error, got exit 0:\n%s", output)
	}

	after := eventTriggerStates(t, ctx, superuser)
	if len(after) != 2 || after["sec7_protect_ddl_objects_on_drop"] != "A" || after["sec7_protect_ddl_objects_on_alter"] != "A" {
		t.Fatalf("ADR-0007 Addendum 10 D90: expected both event triggers ENABLE ALWAYS after the trap's own restoration, got %v\noutput:\n%s", after, output)
	}
	obj, rel, bind := registryRowCounts(t, ctx, superuser)
	if obj != 13 || rel != 2 || bind != 1 {
		t.Fatalf("ADR-0007 Addendum 10 D90: expected registries restored to 13/2/1, got obj=%d rel=%d bind=%d\noutput:\n%s", obj, rel, bind, output)
	}

	// The named consequence regression: M-A's one-statement forgery, as
	// owl_migrator with no event-trigger disable of its own, must now be
	// refused against this trap-restored database.
	migratorConn, err := pgx.Connect(ctx, withDatabase(t, migratorDSN, clone.dbName))
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	defer migratorConn.Close(context.Background())
	if err := mAForgery(ctx, migratorConn); err == nil {
		t.Fatalf("ADR-0007 Addendum 10 D90: M-A's forgery succeeded against a trap-restored database -- enforcement was not actually restored")
	}

	// The pristine control: the same statement against a database that
	// was never disrupted is refused too, so this test cannot pass by
	// the consequence check being vacuous.
	pristineClone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	pristineMigratorConn, err := pgx.Connect(ctx, withDatabase(t, migratorDSN, pristineClone.dbName))
	if err != nil {
		t.Fatalf("connect as owl_migrator (pristine): %v", err)
	}
	defer pristineMigratorConn.Close(context.Background())
	if err := mAForgery(ctx, pristineMigratorConn); err == nil {
		t.Fatalf("test bug: M-A's forgery succeeded against a never-disrupted pristine clone")
	}
}

// TestRefusalRestoresTheDeclaredState_RegistryAloneIsLoadBearing is
// D95 test 4's isolation requirement: ENABLE ALWAYS restored with the
// registry still empty must still let M-A's forgery through -- proving
// part 2 (the registries) is independently load-bearing, not redundant
// with part 1 (ENABLE ALWAYS).
func TestRefusalRestoresTheDeclaredState_RegistryAloneIsLoadBearing(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	superuser, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())

	mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop DISABLE`)
	mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE`)
	mustExec(t, ctx, superuser, `DELETE FROM sec7_protected_object`)
	mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop ENABLE ALWAYS`)
	mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter ENABLE ALWAYS`)

	obj, _, _ := registryRowCounts(t, ctx, superuser)
	if obj != 0 {
		t.Fatalf("test precondition failed: expected sec7_protected_object empty, got %d rows", obj)
	}
	states := eventTriggerStates(t, ctx, superuser)
	if states["sec7_protect_ddl_objects_on_drop"] != "A" || states["sec7_protect_ddl_objects_on_alter"] != "A" {
		t.Fatalf("test precondition failed: expected both event triggers ENABLE ALWAYS, got %v", states)
	}

	migratorConn, err := pgx.Connect(ctx, withDatabase(t, migratorDSN, clone.dbName))
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	defer migratorConn.Close(context.Background())
	if err := mAForgery(ctx, migratorConn); err != nil {
		t.Fatalf("ADR-0007 Addendum 10 D90 isolation: expected M-A's forgery to SUCCEED with ENABLE ALWAYS but an empty registry (proving the registry alone is load-bearing), got refused: %v", err)
	}
}
