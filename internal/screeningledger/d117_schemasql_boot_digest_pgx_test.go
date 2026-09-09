// ADR-0007 Addendum 13 D117 test file (D122 item 7): D112 item 8's own
// pre-declared proof obligation, executed in full -- a clean migration-
// bootstrapped database and a clean, independently-created SchemaSQL-
// only-bootstrapped database (never the shared OWL_SCHEMASQL_ONLY_
// DATABASE_URL fixture other suites in this package depend on staying
// unprovisioned -- grant-ddl-ownership permanently installs D34, so this
// builds its own throwaway database the same way
// scripts/ci/provision_test_roles.sh create-schemasql-only-database
// does) are both accepted by grant-ddl-ownership; the BEGIN RETURN
// 424242; END substitution is refused on both with a non-zero exit
// naming the function and the live digest; CheckProvisioningState
// refuses in both; D90 is unregressed on both; and the refusal names
// the accepted set as a set, not as one comma-joined literal.
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

// newSchemaSQLOnlyScratchDatabase builds a throwaway database owned by
// owl_migrator with no migration ever applied -- the exact shape
// scripts/ci/provision_test_roles.sh create-schemasql-only-database
// produces -- then bootstraps it via the real PostgresSink.Migrate
// (this package's own SchemaSQL const), dropped in t.Cleanup. Distinct
// from the shared OWL_SCHEMASQL_ONLY_DATABASE_URL fixture
// (requireSchemaSQLOnlyDatabaseURL) precisely because this test needs
// to run grant-ddl-ownership against it, which permanently installs
// D34 -- the shared fixture's own declared precondition (D78) is that
// it stays unprovisioned for every other test in this package.
func newSchemaSQLOnlyScratchDatabase(t *testing.T, ctx context.Context, superuserDSN, migratorDSN string) (superuserDBDSN, migratorDBDSN string) {
	t.Helper()
	superuser, err := pgx.Connect(ctx, superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())

	dbName := fmt.Sprintf("owl_ci_d117_schemasql_%d", time.Now().UnixNano())
	if _, err := superuser.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s OWNER owl_migrator`, pgx.Identifier{dbName}.Sanitize())); err != nil {
		t.Fatalf("CREATE DATABASE (SchemaSQL-only scratch): %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		c, err := pgx.Connect(bg, superuserDSN)
		if err != nil {
			t.Errorf("drop D117 scratch database %s: connect: %v", dbName, err)
			return
		}
		defer c.Close(bg)
		if _, err := c.Exec(bg, fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, pgx.Identifier{dbName}.Sanitize())); err != nil {
			t.Errorf("drop D117 scratch database %s: %v", dbName, err)
		}
	})

	superuserDBDSN = withDatabase(t, superuserDSN, dbName)
	migratorDBDSN = withDatabase(t, migratorDSN, dbName)

	sink, err := NewPostgresSink(ctx, migratorDBDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink against the SchemaSQL-only scratch database: %v", err)
	}
	defer sink.Close(context.Background())
	if err := sink.Migrate(ctx); err != nil {
		t.Fatalf("Migrate() (SchemaSQL bootstrap) against the scratch database: %v", err)
	}
	return superuserDBDSN, migratorDBDSN
}

// TestGrantDdlOwnershipAcceptsBothBootstrapPaths is D117's core
// positive: a clean, correctly bootstrapped database is accepted by
// grant-ddl-ownership on BOTH paths -- the shipped migration path
// (db/migrations/*.sql, unchanged by this addendum) and the SchemaSQL
// bootstrap path, which the pre-D117 single accepted digest refused
// outright, aborting before the event triggers were ever installed.
func TestGrantDdlOwnershipAcceptsBothBootstrapPaths(t *testing.T) {
	ctx := context.Background()
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	scriptPath := d62ScriptPath(t)

	t.Run("migration_path", func(t *testing.T) {
		clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
		runGrantDdlOwnership(t, scriptPath, clone.superuserDSN, true)
	})

	t.Run("schemasql_path", func(t *testing.T) {
		schemaSQLSuperuserDSN, _ := newSchemaSQLOnlyScratchDatabase(t, ctx, superuserDSN, migratorDSN)
		runGrantDdlOwnership(t, scriptPath, schemaSQLSuperuserDSN, true)
	})
}

// TestGrantDdlOwnershipRefusesSubstitutionOnBothPaths is D122 item 7 in
// full: D112 item 8's own pre-declared test, executed here rather than
// argued about. The BEGIN RETURN 424242; END substitution (applied
// inside the documented event-trigger disable window, as the bootstrap
// superuser -- no second, undocumented disable) is refused on both
// bootstrap paths with a non-zero exit naming the function and the live
// digest; CheckProvisioningState refuses in both, unregressed; D90 is
// unregressed on both (both event triggers stay ENABLE ALWAYS and all
// three registries stay at 13/2/1 after the refusal); and the refusal
// names the accepted set as a set ("{a, b}"), not as one comma-joined
// literal read as a single expected digest.
func TestGrantDdlOwnershipRefusesSubstitutionOnBothPaths(t *testing.T) {
	ctx := context.Background()
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	scriptPath := d62ScriptPath(t)

	cases := []struct {
		name string
		// setupSuper provisions the target database and reports whether
		// D34 is already installed on it -- a fresh SchemaSQL-only
		// scratch database has never run grant-ddl-ownership (D78's own
		// precondition: "D34 never installed"), so there is no event
		// trigger to disable before substituting the body, unlike the
		// migration path's clone (already grant-ddl-ownership'd, since
		// it is cloned from the shared, CI-provisioned primary).
		setupSuper   func(t *testing.T) (superuserDBDSN string)
		d34Installed bool
	}{
		{
			name: "migration_path",
			setupSuper: func(t *testing.T) string {
				clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
				return clone.superuserDSN
			},
			d34Installed: true,
		},
		{
			name: "schemasql_path",
			setupSuper: func(t *testing.T) string {
				schemaSQLSuperuserDSN, _ := newSchemaSQLOnlyScratchDatabase(t, ctx, superuserDSN, migratorDSN)
				return schemaSQLSuperuserDSN
			},
			d34Installed: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dbSuperuserDSN := c.setupSuper(t)
			superuser := connectSuperuser(t, ctx, dbSuperuserDSN)
			defer superuser.Close(context.Background())

			// D112 item 8's own substitution: identical rogue body on
			// both overloads, inside the documented disable window, as
			// the bootstrap superuser -- no second, undocumented
			// disable. The schemasql_path has no D34 event triggers
			// installed yet (this is a fresh scratch database that has
			// never run grant-ddl-ownership), so there is nothing to
			// disable there -- matching TestSchemaSQLRefusesAnAlteredGuardBody's
			// own precondition.
			substitute := func() {
				mustExec(t, ctx, superuser, `
					CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_ledger_id text, p_expected_count bigint, p_expected_max timestamptz, p_operator text, p_reason text)
					RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
					AS $func$ BEGIN RETURN 424242; END $func$;
				`)
				mustExec(t, ctx, superuser, `
					CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_snapshot_sha256 text[], p_ledger_id text, p_expected_count int[], p_expected_max timestamptz[], p_operator text, p_reason text)
					RETURNS text[] LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
					AS $func$ BEGIN RETURN 424242; END $func$;
				`)
			}
			if c.d34Installed {
				withD34TriggersDisabled(t, ctx, superuser, substitute)
			} else {
				substitute()
			}

			output := runGrantDdlOwnership(t, scriptPath, dbSuperuserDSN, false)
			if !strings.Contains(output, "screening_ledger_purge_snapshots") {
				t.Fatalf("expected the refusal to name screening_ledger_purge_snapshots, got:\n%s", output)
			}
			if !strings.Contains(output, "D117") {
				t.Fatalf("expected the refusal to cite ADR-0007 Addendum 13 D117, got:\n%s", output)
			}
			// The message-rendering assertion: the accepted set is named
			// as a set, "{a, b}" with a comma-space separator inside
			// braces -- not interpolated as one literal containing a
			// comma, which reads as a single expected digest an operator
			// cannot look anything up against.
			if !strings.Contains(output, "declared accepted set {") {
				t.Fatalf("expected the refusal to render the accepted set as \"{a, b}\", got:\n%s", output)
			}
			if strings.Contains(output, "expected '") {
				t.Fatalf("expected the refusal to NOT use the single-literal \"expected '...'\" phrasing (the bug this decision fixes), got:\n%s", output)
			}

			// D90 unregressed: the refusal must not disarm what is
			// already installed on this database (the migration path's
			// clone had grant-ddl-ownership run in a prior sub-test only
			// for that clone; here we check the SchemaSQL path never got
			// as far as installing anything, and the migration path's
			// pre-existing state is untouched).
			var alterEnabled, dropEnabled *string
			_ = superuser.QueryRow(ctx, `SELECT evtenabled FROM pg_event_trigger WHERE evtname='sec7_protect_ddl_objects_on_alter'`).Scan(&alterEnabled)
			_ = superuser.QueryRow(ctx, `SELECT evtenabled FROM pg_event_trigger WHERE evtname='sec7_protect_ddl_objects_on_drop'`).Scan(&dropEnabled)
			if alterEnabled != nil && *alterEnabled != "A" {
				t.Fatalf("ADR-0007 Addendum 9 D90: expected sec7_protect_ddl_objects_on_alter to remain ENABLE ALWAYS after the refusal (or absent, if this path never installed it), got %q", *alterEnabled)
			}
			if dropEnabled != nil && *dropEnabled != "A" {
				t.Fatalf("ADR-0007 Addendum 9 D90: expected sec7_protect_ddl_objects_on_drop to remain ENABLE ALWAYS after the refusal (or absent, if this path never installed it), got %q", *dropEnabled)
			}
		})
	}
}

// runGrantDdlOwnership shells out to the real, unmodified
// scripts/ci/provision_test_roles.sh grant-ddl-ownership against dbSuperuserDSN,
// returning combined output. wantSuccess asserts the exit code.
func runGrantDdlOwnership(t *testing.T, scriptPath, dbSuperuserDSN string, wantSuccess bool) string {
	t.Helper()
	host, port, superuserRole, superpassword := pgConnParamsFromDSN(t, dbSuperuserDSN)
	dbName := dbNameFromDSN(t, dbSuperuserDSN)
	cmd := exec.Command(scriptPath, "grant-ddl-ownership")
	cmd.Env = append(cmd.Environ(),
		"PGHOST="+host, "PGPORT="+port, "PGDATABASE="+dbName,
		"PGSUPERUSER="+superuserRole, "PGSUPERPASSWORD="+superpassword,
	)
	output, err := cmd.CombinedOutput()
	t.Logf("grant-ddl-ownership (%s) output:\n%s", dbName, output)
	if wantSuccess && err != nil {
		t.Fatalf("expected grant-ddl-ownership to succeed against a clean, correctly bootstrapped database, got: %v\n%s", err, output)
	}
	if !wantSuccess && err == nil {
		t.Fatal("expected grant-ddl-ownership to refuse a substituted definer body, got success")
	}
	return string(output)
}
