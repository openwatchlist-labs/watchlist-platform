// ADR-0007 Addendum 6 D54/D58 test 6 (J-C, J-D, LOW, LOW): D46's
// diagnostic is ordered by evidence -- the instance-binding comparison
// runs before name resolution, so a database whose binding mismatches
// reports "this is a copy" whether or not the recorded relation
// resolves by name -- made deterministic (ORDER BY identity), and given
// a fourth message for the case where the evidence itself is absent or
// unreadable, which the read must not turn into a raised exception.
//
// The three existing messages (a: copy, b: dropped-and-recreated,
// c: genuinely-gone) are exercised by
// TestD40DiagnosticNamesTheRelationAndTheInstance in
// d46_copy_diagnostics_pgx_test.go, already running in this package;
// this file adds CAP #5's exact pg_dump --exclude-table scenario (which
// must now report the copy, not (c)), the two states that produce the
// new fourth message, and the ordering-determinism assertion. D46's
// existing negative (a corrupted identity on a healthy database leaves
// every DDL statement succeeding) is retained unchanged in that file,
// per D58's explicit instruction, and is not duplicated here.
package screeningledger

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// pgDumpPipe runs `pg_dump <dumpArgs...> | psql -d destDSN`, exactly the
// shape scripts/ci/provision_test_roles.sh create-restored-database
// uses, via sh -c so the pipe is a real pipe rather than buffered
// through Go -- CAP #5 §7.5 built its reproduction with plain shell
// commands, and this reproduces the same shape rather than a
// Go-mediated approximation of it.
func pgDumpPipe(t *testing.T, sourceDSN, destDSN string, extraDumpArgs ...string) {
	t.Helper()
	host, port, user, password := pgConnParamsFromDSN(t, sourceDSN)
	sourceDB := dbNameFromDSN(t, sourceDSN)
	destHost, destPort, destUser, destPassword := pgConnParamsFromDSN(t, destDSN)
	destDB := dbNameFromDSN(t, destDSN)

	args := append([]string{"-h", host, "-p", port, "-U", user, "-d", sourceDB}, extraDumpArgs...)
	dumpCmd := exec.Command("pg_dump", args...)
	dumpCmd.Env = append(dumpCmd.Environ(), "PGPASSWORD="+password)

	restoreCmd := exec.Command("psql", "-h", destHost, "-p", destPort, "-U", destUser, "-d", destDB, "-X", "-q", "-v", "ON_ERROR_STOP=1")
	restoreCmd.Env = append(restoreCmd.Environ(), "PGPASSWORD="+destPassword)

	pipe, err := dumpCmd.StdoutPipe()
	if err != nil {
		t.Fatalf("pg_dump stdout pipe: %v", err)
	}
	restoreCmd.Stdin = pipe

	var restoreOut strings.Builder
	restoreCmd.Stdout = &restoreOut
	restoreCmd.Stderr = &restoreOut

	if err := dumpCmd.Start(); err != nil {
		t.Fatalf("start pg_dump: %v", err)
	}
	if err := restoreCmd.Start(); err != nil {
		t.Fatalf("start psql restore: %v", err)
	}
	dumpErr := dumpCmd.Wait()
	restoreErr := restoreCmd.Wait()
	if dumpErr != nil {
		t.Fatalf("pg_dump: %v", dumpErr)
	}
	if restoreErr != nil {
		t.Fatalf("psql restore: %v\noutput:\n%s", restoreErr, restoreOut.String())
	}
}

// TestD54PgDumpExcludeTableReportsCopyNotAbsent is CAP #5 §7.5's exact
// reproduction: pg_dump --exclude-table on the (non-schema-only) primary
// carries the registries' DATA -- including sec7_instance_binding's
// row, recorded under the SOURCE instance -- but not the excluded
// table itself. Before D54, the excluded relation's absence was
// detected first and its message never looked at the binding at all,
// so this reported message (c) ("genuinely gone... do not
// re-provision"), which is the OPPOSITE of the correct action for a
// copy. After D54, the binding mismatch is checked first and this
// reports message (a).
func TestD54PgDumpExcludeTableReportsCopyNotAbsent(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ctx := context.Background()

	superuser, err := pgx.Connect(ctx, superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())

	destDB := fmt.Sprintf("owl_ci_d54_exclude_%d", time.Now().UnixNano())
	if _, err := superuser.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s`, pgx.Identifier{destDB}.Sanitize())); err != nil {
		t.Fatalf("CREATE DATABASE %s: %v", destDB, err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		c, err := pgx.Connect(bg, superuserDSN)
		if err != nil {
			t.Errorf("drop %s: connect: %v", destDB, err)
			return
		}
		defer c.Close(bg)
		if _, err := c.Exec(bg, fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, pgx.Identifier{destDB}.Sanitize())); err != nil {
			t.Errorf("drop %s: %v", destDB, err)
		}
	})

	destSuperuserDSN := withDatabase(t, superuserDSN, destDB)
	// A plain, full pg_dump | psql (neither --no-owner nor
	// --no-privileges, matching D43's Variant 1 -- "the shape an
	// operator actually types") with one table excluded: CAP #5 §7.5's
	// own reproduction. Ownership and grants are preserved, so
	// owl_migrator can still act on the destination the way D46's own
	// "copy" subtest (d46_copy_diagnostics_pgx_test.go) does.
	pgDumpPipe(t, superuserDSN, destSuperuserDSN,
		"--exclude-table=public.screening_ledger_retention_tombstone")

	destMigratorDSN := withDatabase(t, migratorDSN, destDB)
	conn, err := pgx.Connect(ctx, destMigratorDSN)
	if err != nil {
		t.Fatalf("connect to the excluded-table copy as owl_migrator: %v", err)
	}
	defer conn.Close(context.Background())

	// D46/D54's messages fire from the live DDL event trigger, not from
	// CheckProvisioningState's read-only probes -- any DDL statement
	// trips sec7_protect_ddl_objects()'s second phase, which loops over
	// every row in sec7_protected_relation regardless of what the
	// statement itself touched.
	_, execErr := conn.Exec(ctx, `GRANT SELECT ON screening_ledger_event TO owl_app`)
	if execErr == nil {
		t.Fatal("ADR-0007 Addendum 6 D54: unrelated DDL succeeded against a pg_dump --exclude-table copy with a dangling registry row")
	}
	var pgErr *pgconn.PgError
	if !errors.As(execErr, &pgErr) || pgErr.Code != "P0001" {
		t.Fatalf("expected SQLSTATE P0001, got %q: %v", pgErrorCode(execErr), execErr)
	}
	if !strings.Contains(execErr.Error(), "This database is a copy or restore of another") {
		t.Fatalf("ADR-0007 Addendum 6 D54: expected message (a) (\"this is a copy\") for the excluded-table case, got: %v", execErr)
	}
	if strings.Contains(execErr.Error(), "no relation of that name is present") {
		t.Fatalf("ADR-0007 Addendum 6 D54: CAP #5 §7.5's exact regression -- got message (c) (\"genuinely gone, do not re-provision\") for a copy, got: %v", execErr)
	}
	t.Logf("D54 message (a) correctly reported for the excluded-table copy: %v", execErr)
}

// TestD54AbsentOrEmptyBindingReportsFourthMessage covers both states
// D54(c) introduces the fourth message for: the instance binding table
// present but empty, and the instance binding table absent entirely.
// Both are built and torn down on a disposable TEMPLATE clone, never on
// the shared primary database.
func TestD54AbsentOrEmptyBindingReportsFourthMessage(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	const fourthMessage = "the instance binding is absent or empty, so whether this database is a copy cannot be determined"

	t.Run("zero_binding_rows", func(t *testing.T) {
		clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
		superuser, err := pgx.Connect(ctx, clone.superuserDSN)
		if err != nil {
			t.Fatalf("connect as bootstrap superuser: %v", err)
		}
		defer superuser.Close(context.Background())

		if _, err := superuser.Exec(ctx, `DELETE FROM sec7_instance_binding`); err != nil {
			t.Fatalf("empty sec7_instance_binding: %v", err)
		}
		withD34TriggersDisabled(t, ctx, superuser, func() {
			if _, err := superuser.Exec(ctx, `DROP TABLE screening_ledger_retention_tombstone`); err != nil {
				t.Fatalf("drop tombstone table: %v", err)
			}
		})

		_, probeErr := superuser.Exec(ctx, `CREATE TABLE zz_d54_probe (id int)`)
		if probeErr == nil {
			t.Fatal("ADR-0007 Addendum 6 D54: unrelated DDL succeeded with a registered relation gone and the instance binding empty")
		}
		var pgErr *pgconn.PgError
		if !errors.As(probeErr, &pgErr) || pgErr.Code != "P0001" {
			t.Fatalf("expected SQLSTATE P0001, got %q: %v", pgErrorCode(probeErr), probeErr)
		}
		if !strings.Contains(probeErr.Error(), fourthMessage) {
			t.Fatalf("expected the fourth message (absent/empty evidence), got: %v", probeErr)
		}
	})

	t.Run("binding_table_absent", func(t *testing.T) {
		clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
		superuser, err := pgx.Connect(ctx, clone.superuserDSN)
		if err != nil {
			t.Fatalf("connect as bootstrap superuser: %v", err)
		}
		defer superuser.Close(context.Background())

		withD34TriggersDisabled(t, ctx, superuser, func() {
			if _, err := superuser.Exec(ctx, `DROP TABLE sec7_instance_binding`); err != nil {
				t.Fatalf("drop sec7_instance_binding: %v", err)
			}
			if _, err := superuser.Exec(ctx, `DELETE FROM sec7_protected_object WHERE note LIKE 'table: sec7_instance_binding%'`); err != nil {
				t.Fatalf("deregister sec7_instance_binding: %v", err)
			}
			if _, err := superuser.Exec(ctx, `DROP TABLE screening_ledger_retention_tombstone`); err != nil {
				t.Fatalf("drop tombstone table: %v", err)
			}
		})

		// The critical assertion: to_regclass on a literal never raises,
		// so this DDL statement's own error is D54's fourth message --
		// never a bare "relation sec7_instance_binding does not exist"
		// escaping from inside the event trigger function (R17's
		// accepted risk, which D46 rejected to_regclass(rel.identity)
		// specifically to avoid for the DATA column; D54(c) proves the
		// LITERAL guard does not reintroduce it).
		_, probeErr := superuser.Exec(ctx, `CREATE TABLE zz_d54_probe2 (id int)`)
		if probeErr == nil {
			t.Fatal("ADR-0007 Addendum 6 D54: unrelated DDL succeeded with a registered relation gone and the instance binding table absent")
		}
		var pgErr *pgconn.PgError
		if !errors.As(probeErr, &pgErr) || pgErr.Code != "P0001" {
			t.Fatalf("expected SQLSTATE P0001 (the fourth message, not a bare catalog error), got %q: %v", pgErrorCode(probeErr), probeErr)
		}
		if strings.Contains(probeErr.Error(), "does not exist") && !strings.Contains(probeErr.Error(), fourthMessage) {
			t.Fatalf("ADR-0007 Addendum 6 D54(c): a bare catalog error escaped instead of the fourth message: %v", probeErr)
		}
		if !strings.Contains(probeErr.Error(), fourthMessage) {
			t.Fatalf("expected the fourth message (absent/empty evidence), got: %v", probeErr)
		}
	})
}

// TestD54DiagnosticOrderingIsDeterministic is D54(b): two runs against
// one database state produce one message, not one decided by heap
// order -- built by registering two scratch relations as "gone" at
// once (one whose name resolves, so it would produce message (b); one
// that does not, message (c)) and confirming the SAME message names
// the SAME relation across repeated probes.
func TestD54DiagnosticOrderingIsDeterministic(t *testing.T) {
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

	registerScratch := func(name string) {
		if _, err := superuser.Exec(ctx, `
			INSERT INTO sec7_protected_relation (objid, relowner, relkind, relrowsecurity, relforcerowsecurity, trigger_oids, index_defs, policy_oids, identity)
			SELECT c.oid, c.relowner, c.relkind, c.relrowsecurity, c.relforcerowsecurity, ARRAY[]::oid[], ARRAY[]::text[], ARRAY[]::oid[], $1
			FROM pg_class c WHERE c.relname = $2
		`, "public."+name, name); err != nil {
			t.Fatalf("register scratch relation %s: %v", name, err)
		}
	}

	withD34TriggersDisabled(t, ctx, superuser, func() {
		if _, err := superuser.Exec(ctx, `CREATE TABLE zz_d54_ord_a (id int)`); err != nil {
			t.Fatalf("create zz_d54_ord_a: %v", err)
		}
		registerScratch("zz_d54_ord_a")
		if _, err := superuser.Exec(ctx, `CREATE TABLE zz_d54_ord_b (id int)`); err != nil {
			t.Fatalf("create zz_d54_ord_b: %v", err)
		}
		registerScratch("zz_d54_ord_b")
		// Both dropped without recreation: both resolve to message (c),
		// and both sort by identity ('public.zz_d54_ord_a' before
		// 'public.zz_d54_ord_b'), so the deterministic first failure is
		// always zz_d54_ord_a's.
		if _, err := superuser.Exec(ctx, `DROP TABLE zz_d54_ord_a, zz_d54_ord_b`); err != nil {
			t.Fatalf("drop both scratch tables: %v", err)
		}
	})

	var firstMessage string
	for i := 0; i < 5; i++ {
		_, err := superuser.Exec(ctx, `CREATE TABLE zz_d54_ord_probe (id int)`)
		if err == nil {
			t.Fatal("ADR-0007 Addendum 6 D54: unrelated DDL succeeded with two registered relations gone")
		}
		if !strings.Contains(err.Error(), "public.zz_d54_ord_a") {
			t.Fatalf("run %d: expected the deterministic first failure (by identity ORDER BY) to name zz_d54_ord_a, got: %v", i, err)
		}
		if i == 0 {
			firstMessage = err.Error()
		} else if err.Error() != firstMessage {
			t.Fatalf("ADR-0007 Addendum 6 D54(b): message varied across repeated runs against one unchanged database state:\nrun 0: %s\nrun %d: %s", firstMessage, i, err.Error())
		}
	}
}
