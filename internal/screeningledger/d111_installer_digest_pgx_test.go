// ADR-0007 Addendum 12 D111 test file (D112 item 8): the operator
// procedure's own reproduction (0007:11945-12038), reproduced
// independently against a real disposable Postgres cluster before this
// addendum's design was written, is not re-derived here from the ADR
// transcript -- these tests build it fresh, through the real,
// unmodified scripts/ci/provision_test_roles.sh grant-ddl-ownership and
// PostgresSink.CheckProvisioningState, exactly as that reproduction
// did.
package screeningledger

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestGrantDdlOwnershipDetectsASubstitutedDefinerBody is D111(a) / D112
// item 8: grant-ddl-ownership exits 0 TODAY (before this decision) with
// three PASS lines and no body-digest check on the two purge_snapshots
// overloads; after D111(a) it exits non-zero, naming the function and
// the live digest -- while CheckProvisioningState (the pre-existing
// verifier) refuses in both, unregressed. Plus D90's own over-
// tightening negative: the refusal must leave both event triggers
// evtenabled='A' and all three registries at 13/2/1 -- a refusal that
// disarms the protections it is checking is the shape D90 exists to
// forbid.
func TestGrantDdlOwnershipDetectsASubstitutedDefinerBody(t *testing.T) {
	ctx := context.Background()
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	scriptPath := d62ScriptPath(t)

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	superuser := connectSuperuser(t, ctx, clone.superuserDSN)
	defer superuser.Close(context.Background())

	// Substitute the array-form overload's body inside the documented
	// event-trigger disable window -- the same T2 re-provisioning
	// window D87/D111's own text describes.
	withD34TriggersDisabled(t, ctx, superuser, func() {
		mustExec(t, ctx, superuser, `
			CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_snapshot_sha256 text[], p_ledger_id text, p_expected_count int[], p_expected_max timestamptz[], p_operator text, p_reason text)
			RETURNS text[] LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
			BEGIN
				RETURN p_snapshot_sha256; -- purges nothing it re-validates; tombstones nothing; a substitution nonetheless
			END; $$;
		`)
	})

	// The pre-existing verifier (D87/D86 row 8) still refuses -- unregressed.
	sink, err := NewPostgresSink(ctx, withDatabase(t, migratorDSN, clone.dbName), 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())
	provisioning, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState: %v", err)
	}
	if provisioning.Provisioned {
		t.Fatal("ADR-0007 Addendum 10 D87/D86 row 8: CheckProvisioningState reported Provisioned=true despite a substituted purge-writing definer body")
	}

	// D111(a): the installer now proves the property it installs too.
	host, port, superuserRole, superpassword := pgConnParamsFromDSN(t, clone.superuserDSN)
	cmd := exec.Command(scriptPath, "grant-ddl-ownership")
	cmd.Env = append(cmd.Environ(),
		"PGHOST="+host, "PGPORT="+port, "PGDATABASE="+clone.dbName,
		"PGSUPERUSER="+superuserRole, "PGSUPERPASSWORD="+superpassword,
	)
	output, runErr := cmd.CombinedOutput()
	t.Logf("grant-ddl-ownership output:\n%s", output)
	if runErr == nil {
		t.Fatal("ADR-0007 Addendum 12 D111: grant-ddl-ownership succeeded against a database with a substituted purge-snapshots definer body -- expected refusal")
	}
	if !strings.Contains(string(output), "screening_ledger_purge_snapshots") {
		t.Fatalf("expected the refusal to name screening_ledger_purge_snapshots, got:\n%s", output)
	}
	if !strings.Contains(string(output), "D111") {
		t.Fatalf("expected the refusal to cite ADR-0007 Addendum 12 D111, got:\n%s", output)
	}

	// D90 unregressed: the refusal must not disarm what is already
	// installed -- both event triggers stay ENABLE ALWAYS, and all
	// three registries stay at their declared 13/2/1 population.
	var alterEnabled, dropEnabled string
	if err := superuser.QueryRow(ctx, `SELECT evtenabled FROM pg_event_trigger WHERE evtname='sec7_protect_ddl_objects_on_alter'`).Scan(&alterEnabled); err != nil {
		t.Fatal(err)
	}
	if err := superuser.QueryRow(ctx, `SELECT evtenabled FROM pg_event_trigger WHERE evtname='sec7_protect_ddl_objects_on_drop'`).Scan(&dropEnabled); err != nil {
		t.Fatal(err)
	}
	if alterEnabled != "A" || dropEnabled != "A" {
		t.Fatalf("ADR-0007 Addendum 9 D90: expected both event triggers to remain ENABLE ALWAYS after the refusal, got alter=%q drop=%q", alterEnabled, dropEnabled)
	}
	var objectCount, relationCount, instanceCount int
	if err := superuser.QueryRow(ctx, `SELECT count(*) FROM sec7_protected_object`).Scan(&objectCount); err != nil {
		t.Fatal(err)
	}
	if err := superuser.QueryRow(ctx, `SELECT count(*) FROM sec7_protected_relation`).Scan(&relationCount); err != nil {
		t.Fatal(err)
	}
	if err := superuser.QueryRow(ctx, `SELECT count(*) FROM sec7_instance_binding`).Scan(&instanceCount); err != nil {
		t.Fatal(err)
	}
	if objectCount != 13 || relationCount != 2 || instanceCount != 1 {
		t.Fatalf("ADR-0007 Addendum 9 D90: expected registries at 13/2/1 after the refusal, got object=%d relation=%d instance=%d", objectCount, relationCount, instanceCount)
	}
}
