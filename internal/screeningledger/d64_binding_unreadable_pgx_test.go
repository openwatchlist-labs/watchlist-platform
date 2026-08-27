// ADR-0007 Addendum 7 D64/D67 test 5 (K-E, LOW): D54(c)'s to_regclass
// guard proves sec7_instance_binding EXISTS; it says nothing about its
// SHAPE. A renamed column or a well-shaped raising view both leave a
// bare catalog error escaping sec7_protect_ddl_objects() -- naming
// neither the protected relation nor the cause -- when the relation the
// event trigger is examining is itself absent. J-D's own resolution
// (the read cannot raise) is applied: the binding read is wrapped in an
// exception handler, and an unreadable binding is classified as D54's
// fourth message. This file reproduces both K-E states, proves the raw
// mechanism (reconstructed as an isolated DO block, mirroring exactly
// what sec7_protect_ddl_objects()'s pre-D64 binding read did) raises an
// unclassified error, and proves the shipped, real event trigger now
// reports the new named diagnostic for both -- plus the passing-path
// negative that keeps the exception handler off the hot path: a raising
// binding on an otherwise healthy database leaves every DDL statement
// succeeding, because the guarded read sits strictly inside the
// already-failing NOT EXISTS branch.
package screeningledger

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

const d64FourthMessage = "the instance binding is present but could not be read, so whether this database is a copy cannot be determined"

// preD64BindingRead reconstructs sec7_protect_ddl_objects()'s binding
// read exactly as it existed before ADR-0007 Addendum 7 D64 -- guarded
// only by to_regclass on a literal, with no exception handler around
// the SELECT itself -- as an isolated DO block, so a raised error is
// unclassified and unguarded, the same as it was inside the event
// trigger function prior to this addendum.
func preD64BindingRead(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, `
		DO $$
		DECLARE
		  binding_readable boolean;
		  binding_row_count integer;
		  rec_sysid bigint;
		  rec_dboid oid;
		  rec_dbname text;
		BEGIN
		  binding_readable := to_regclass('sec7_instance_binding') IS NOT NULL;
		  IF binding_readable THEN
		    SELECT count(*) INTO binding_row_count FROM sec7_instance_binding;
		  ELSE
		    binding_row_count := 0;
		  END IF;
		  IF binding_row_count > 0 THEN
		    SELECT b.system_identifier, b.database_oid, b.database_name
		      INTO rec_sysid, rec_dboid, rec_dbname
		      FROM sec7_instance_binding b LIMIT 1;
		  END IF;
		END $$;
	`)
	return err
}

func TestD64UnreadableBindingReportsFourthMessage(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	cases := []struct {
		name  string
		build func(t *testing.T, ctx context.Context, superuser *pgx.Conn)
	}{
		{
			name: "renamed_column",
			build: func(t *testing.T, ctx context.Context, superuser *pgx.Conn) {
				if _, err := superuser.Exec(ctx, `ALTER TABLE sec7_instance_binding RENAME COLUMN system_identifier TO sysid_renamed`); err != nil {
					t.Fatalf("rename system_identifier: %v", err)
				}
			},
		},
		{
			name: "raising_view",
			build: func(t *testing.T, ctx context.Context, superuser *pgx.Conn) {
				if _, err := superuser.Exec(ctx, `DROP TABLE sec7_instance_binding`); err != nil {
					t.Fatalf("drop sec7_instance_binding: %v", err)
				}
				if _, err := superuser.Exec(ctx, `
					CREATE VIEW sec7_instance_binding AS
					SELECT (1/0)::bigint AS system_identifier, 0::oid AS database_oid, 'x'::text AS database_name, now() AS provisioned_at
				`); err != nil {
					t.Fatalf("create raising view: %v", err)
				}
				if _, err := superuser.Exec(ctx, `DELETE FROM sec7_protected_object WHERE note LIKE 'table: sec7_instance_binding%'`); err != nil {
					t.Fatalf("deregister sec7_instance_binding: %v", err)
				}
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Run("pre-D64 mechanism raises an unclassified error", func(t *testing.T) {
				clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
				superuser, err := pgx.Connect(ctx, clone.superuserDSN)
				if err != nil {
					t.Fatalf("connect as bootstrap superuser: %v", err)
				}
				defer superuser.Close(context.Background())

				withD34TriggersDisabled(t, ctx, superuser, func() {
					c.build(t, ctx, superuser)
				})

				readErr := preD64BindingRead(ctx, superuser)
				if readErr == nil {
					t.Fatalf("ADR-0007 Addendum 7 D64: expected the pre-fix binding read to raise for case %s", c.name)
				}
				if strings.Contains(readErr.Error(), "ADR-0007") {
					t.Fatalf("ADR-0007 Addendum 7 D64: expected an UNCLASSIFIED catalog error (no SEC-7 diagnostic text) from the pre-fix mechanism, got: %v", readErr)
				}
				t.Logf("pre-D64 raw error confirmed: %v", readErr)
			})

			t.Run("shipped event trigger reports the fourth message", func(t *testing.T) {
				clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
				superuser, err := pgx.Connect(ctx, clone.superuserDSN)
				if err != nil {
					t.Fatalf("connect as bootstrap superuser: %v", err)
				}
				defer superuser.Close(context.Background())

				withD34TriggersDisabled(t, ctx, superuser, func() {
					c.build(t, ctx, superuser)
					// The binding read is reached only inside the
					// already-failing NOT EXISTS branch -- put the anchor
					// relation itself into that state too.
					if _, err := superuser.Exec(ctx, `DROP TABLE screening_ledger_retention_tombstone`); err != nil {
						t.Fatalf("drop tombstone table: %v", err)
					}
				})

				_, probeErr := superuser.Exec(ctx, `CREATE TABLE zz_d64_probe (id int)`)
				if probeErr == nil {
					t.Fatalf("ADR-0007 Addendum 7 D64: unrelated DDL succeeded with the tombstone gone and the instance binding unreadable (%s)", c.name)
				}
				if !strings.Contains(probeErr.Error(), d64FourthMessage) {
					t.Fatalf("ADR-0007 Addendum 7 D64: expected the fourth message (present but unreadable) for case %s, got: %v", c.name, probeErr)
				}
				if !strings.Contains(probeErr.Error(), "screening_ledger_retention_tombstone") {
					t.Fatalf("expected the diagnostic to name the protected relation, got: %v", probeErr)
				}
			})
		})
	}
}

// TestD64UnreadableBindingOnHealthyDatabaseLeavesDDLSucceeding is D67
// test 5's required passing-path negative: the binding read sits
// strictly inside the NOT EXISTS branch, so a raising binding on an
// otherwise healthy database (both protected relations present and
// unchanged) never reaches it -- confirmed by an unrelated CREATE TABLE
// succeeding, not merely by reading the code.
func TestD64UnreadableBindingOnHealthyDatabaseLeavesDDLSucceeding(t *testing.T) {
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

	withD34TriggersDisabled(t, ctx, superuser, func() {
		if _, err := superuser.Exec(ctx, `DROP TABLE sec7_instance_binding`); err != nil {
			t.Fatalf("drop sec7_instance_binding: %v", err)
		}
		if _, err := superuser.Exec(ctx, `
			CREATE VIEW sec7_instance_binding AS
			SELECT (1/0)::bigint AS system_identifier, 0::oid AS database_oid, 'x'::text AS database_name, now() AS provisioned_at
		`); err != nil {
			t.Fatalf("create raising view: %v", err)
		}
		if _, err := superuser.Exec(ctx, `DELETE FROM sec7_protected_object WHERE note LIKE 'table: sec7_instance_binding%'`); err != nil {
			t.Fatalf("deregister sec7_instance_binding: %v", err)
		}
	})

	assertHealthy(t, ctx, clone.superuserDSN, "zz_d64_healthy_probe")
}
