// ADR-0007 Addendum 5 D45/D49 test 4: sec7_instance_binding is a
// copy-diagnosis marker, never a security control. This test proves both
// halves of that sentence against a real Postgres database: the row is
// recorded and protected the same way the two registries are, and
// deliberately mismatching it changes nothing CheckProvisioningState
// reports -- the test that would fail if anyone later made the binding a
// gate (D49's own stated purpose for this test).
package screeningledger

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestInstanceBindingIsRecordedAndNeverGates(t *testing.T) {
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
		t.Fatalf("test precondition failed: database is not provisioned before any binding tampering (Reason=%q)", baseline.Reason)
	}

	superuser, err := pgx.Connect(ctx, superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())

	t.Run("row_exists_and_matches_the_live_instance", func(t *testing.T) {
		var rows int
		var sysid int64
		var dboid uint32
		var dbname string
		if err := superuser.QueryRow(ctx, `SELECT count(*) FROM sec7_instance_binding`).Scan(&rows); err != nil {
			t.Fatalf("count sec7_instance_binding: %v", err)
		}
		if rows != 1 {
			t.Fatalf("ADR-0007 Addendum 5 D45: expected exactly 1 row in sec7_instance_binding, found %d", rows)
		}
		if err := superuser.QueryRow(ctx, `SELECT system_identifier, database_oid, database_name FROM sec7_instance_binding`).Scan(&sysid, &dboid, &dbname); err != nil {
			t.Fatalf("read sec7_instance_binding: %v", err)
		}
		var liveSysid int64
		var liveDBOid uint32
		var liveDBName string
		if err := superuser.QueryRow(ctx, `SELECT system_identifier FROM pg_control_system()`).Scan(&liveSysid); err != nil {
			t.Fatalf("read pg_control_system: %v", err)
		}
		if err := superuser.QueryRow(ctx, `SELECT oid, datname FROM pg_database WHERE datname = current_database()`).Scan(&liveDBOid, &liveDBName); err != nil {
			t.Fatalf("read pg_database: %v", err)
		}
		if sysid != liveSysid || dboid != liveDBOid || dbname != liveDBName {
			t.Fatalf("ADR-0007 Addendum 5 D45: sec7_instance_binding (%d/%d %q) does not match the live instance (%d/%d %q) on a freshly provisioned database", sysid, dboid, dbname, liveSysid, liveDBOid, liveDBName)
		}
	})

	t.Run("owl_ledger_ddl_and_owl_migrator_both_refused_UPDATE", func(t *testing.T) {
		ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
		ledgerDDL, err := pgx.Connect(ctx, ledgerDDLDSN)
		if err != nil {
			t.Fatalf("connect as owl_ledger_ddl: %v", err)
		}
		defer ledgerDDL.Close(context.Background())
		if _, err := ledgerDDL.Exec(ctx, `UPDATE sec7_instance_binding SET database_name = 'forged'`); err == nil {
			t.Fatal("ADR-0007 Addendum 5 D45: owl_ledger_ddl (the protected tables' OWNER) was able to UPDATE sec7_instance_binding -- it must be as unwritable to every non-superuser role as the two registries")
		}

		migrator, err := pgx.Connect(ctx, migratorDSN)
		if err != nil {
			t.Fatalf("connect as owl_migrator: %v", err)
		}
		defer migrator.Close(context.Background())
		if _, err := migrator.Exec(ctx, `UPDATE sec7_instance_binding SET database_name = 'forged'`); err == nil {
			t.Fatal("ADR-0007 Addendum 5 D45: owl_migrator was able to UPDATE sec7_instance_binding")
		}
	})

	t.Run("mismatched_binding_with_valid_registries_still_reports_Provisioned_true", func(t *testing.T) {
		// The test D49 names explicitly: a control that becomes a gate
		// here is a different and worse decision than D45, and this
		// test exists to make that change fail loudly.
		var originalOID uint32
		if err := superuser.QueryRow(ctx, `SELECT database_oid FROM sec7_instance_binding`).Scan(&originalOID); err != nil {
			t.Fatalf("read original database_oid: %v", err)
		}
		if _, err := superuser.Exec(ctx, `UPDATE sec7_instance_binding SET system_identifier = 1, database_oid = 999999, database_name = 'not-this-database'`); err != nil {
			t.Fatalf("mismatch the binding: %v", err)
		}
		t.Cleanup(func() {
			bg := context.Background()
			c, err := pgx.Connect(bg, superuserDSN)
			if err != nil {
				t.Errorf("restore binding: connect: %v", err)
				return
			}
			defer c.Close(bg)
			if _, err := c.Exec(bg, `
				UPDATE sec7_instance_binding SET
					system_identifier = (SELECT system_identifier FROM pg_control_system()),
					database_oid = $1,
					database_name = current_database()
			`, originalOID); err != nil {
				t.Errorf("restore binding: %v", err)
			}
		})

		state, err := sink.CheckProvisioningState(ctx)
		if err != nil {
			t.Fatalf("CheckProvisioningState with a mismatched binding: %v", err)
		}
		if !state.Provisioned {
			t.Fatalf("ADR-0007 Addendum 5 D45: CheckProvisioningState reported Provisioned=false with sec7_instance_binding mismatched but both registries otherwise valid (Reason=%q) -- the binding must never be consulted by provisioning state at all", state.Reason)
		}
	})
}
