// ADR-0007 Addendum 4 D41 (H-E, MEDIUM): the registry's identity and its
// population both become assertions. CAP #3 §7.2's exact two states --
// a row repointed to a different, existing relation, and the registry
// emptied outright -- reproduced against the real sec7_protected_object
// table, plus the cross-catalog-reuse case D41's own text names as a
// gap the shipped three-way NOT EXISTS could not see, plus the two
// owl_ledger_ddl CREATE-privilege facts D41 part three adds.
package screeningledger

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestCheckProvisioningStateDetectsRepointedAndEmptiedRegistry is D41 /
// D42 point 5.
func TestCheckProvisioningStateDetectsRepointedAndEmptiedRegistry(t *testing.T) {
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
		t.Fatalf("test precondition failed: database is not provisioned before any registry tampering (Reason=%q)", baseline.Reason)
	}

	superuser, err := pgx.Connect(ctx, superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())

	t.Run("repointed_to_a_different_existing_relation", func(t *testing.T) {
		// CAP #3 §7.2's exact repoint: the registry's claim
		// ("screening_ledger_anchor") no longer matches what its objid
		// actually resolves to.
		var originalOID uint32
		var otherOID uint32
		if err := superuser.QueryRow(ctx, `SELECT objid FROM sec7_protected_object WHERE note LIKE 'table: screening_ledger_anchor%'`).Scan(&originalOID); err != nil {
			t.Fatalf("read anchor registry row: %v", err)
		}
		if err := superuser.QueryRow(ctx, `SELECT 'screening_ledger_event'::regclass::oid`).Scan(&otherOID); err != nil {
			t.Fatalf("resolve screening_ledger_event oid: %v", err)
		}
		if _, err := superuser.Exec(ctx, `UPDATE sec7_protected_object SET objid = $1 WHERE note LIKE 'table: screening_ledger_anchor%'`, otherOID); err != nil {
			t.Fatalf("repoint registry row: %v", err)
		}
		t.Cleanup(func() {
			bg := context.Background()
			c, err := pgx.Connect(bg, superuserDSN)
			if err != nil {
				t.Errorf("restore repointed row: connect: %v", err)
				return
			}
			defer c.Close(bg)
			if _, err := c.Exec(bg, `UPDATE sec7_protected_object SET objid = $1 WHERE objid = $2`, originalOID, otherOID); err != nil {
				t.Errorf("restore repointed row: %v", err)
			}
		})

		state, err := sink.CheckProvisioningState(ctx)
		if err != nil {
			t.Fatalf("CheckProvisioningState: %v", err)
		}
		if state.Provisioned {
			t.Fatal("ADR-0007 Addendum 4 D41: CheckProvisioningState reported Provisioned=true with a registry row repointed to a different existing relation (CAP #3 §7.2)")
		}
		if !strings.Contains(state.Reason, "stale, repointed, or was never populated") {
			t.Fatalf("expected the repoint-specific reason, got: %q", state.Reason)
		}
	})

	t.Run("emptied_outright", func(t *testing.T) {
		// CAP #3 §7.2's exact DELETE: with zero rows, D34's trigger is
		// inert for every object, and the shipped three-way NOT EXISTS
		// vacuously certified this state as provisioned.
		var backup []struct {
			objid   uint32
			classid uint32
			note    string
		}
		rows, err := superuser.Query(ctx, `SELECT objid, classid, note FROM sec7_protected_object`)
		if err != nil {
			t.Fatalf("backup registry: %v", err)
		}
		for rows.Next() {
			var r struct {
				objid   uint32
				classid uint32
				note    string
			}
			if err := rows.Scan(&r.objid, &r.classid, &r.note); err != nil {
				rows.Close()
				t.Fatalf("scan backup row: %v", err)
			}
			backup = append(backup, r)
		}
		rows.Close()

		if _, err := superuser.Exec(ctx, `DELETE FROM sec7_protected_object`); err != nil {
			t.Fatalf("empty the registry: %v", err)
		}
		t.Cleanup(func() {
			bg := context.Background()
			c, err := pgx.Connect(bg, superuserDSN)
			if err != nil {
				t.Errorf("restore emptied registry: connect: %v", err)
				return
			}
			defer c.Close(bg)
			for _, r := range backup {
				if _, err := c.Exec(bg, `INSERT INTO sec7_protected_object (objid, classid, note) VALUES ($1, $2, $3)`, r.objid, r.classid, r.note); err != nil {
					t.Errorf("restore emptied registry row %v: %v", r, err)
				}
			}
		})

		state, err := sink.CheckProvisioningState(ctx)
		if err != nil {
			t.Fatalf("CheckProvisioningState: %v", err)
		}
		if state.Provisioned {
			t.Fatal("ADR-0007 Addendum 4 D41: CheckProvisioningState reported Provisioned=true with sec7_protected_object emptied outright (CAP #3 §7.2)")
		}
		if !strings.Contains(state.Reason, "expected exactly") {
			t.Fatalf("expected the population-count reason, got: %q", state.Reason)
		}
	})

	t.Run("cross_catalog_OID_reuse", func(t *testing.T) {
		// D41's own stated gap: the shipped three-way NOT EXISTS accepts
		// a pg_class OID sitting in a row that claims a function, because
		// OIDs are drawn from one global counter and unique only within
		// a catalog, not across catalogs. This is what
		// pg_identify_object(classid, objid, 0) closes: a wrong-catalog
		// OID resolves to NULL identity rather than raising, so the
		// comparison fails closed.
		var funcOID uint32
		if err := superuser.QueryRow(ctx, `SELECT 'screening_ledger_reject_mutation()'::regprocedure::oid`).Scan(&funcOID); err != nil {
			t.Fatalf("resolve screening_ledger_reject_mutation oid: %v", err)
		}
		if _, err := superuser.Exec(ctx, `UPDATE sec7_protected_object SET classid = 'pg_class'::regclass::oid WHERE note LIKE 'function: screening_ledger_reject_mutation%'`); err != nil {
			t.Fatalf("relabel classid to pg_class for a pg_proc OID: %v", err)
		}
		t.Cleanup(func() {
			bg := context.Background()
			c, err := pgx.Connect(bg, superuserDSN)
			if err != nil {
				t.Errorf("restore classid: connect: %v", err)
				return
			}
			defer c.Close(bg)
			if _, err := c.Exec(bg, `UPDATE sec7_protected_object SET classid = 'pg_proc'::regclass::oid WHERE objid = $1`, funcOID); err != nil {
				t.Errorf("restore classid: %v", err)
			}
		})

		// The shipped (pre-D41) three-way NOT EXISTS query, run directly:
		// a pg_proc OID resolves under ANY of the three EXISTS clauses
		// (it is a real pg_proc row), so the shipped check reads zero
		// stale rows even though the row's classid now claims the wrong
		// catalog.
		var shippedStaleCount int
		if err := superuser.QueryRow(ctx, `
			SELECT count(*) FROM sec7_protected_object r
			WHERE NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = r.objid)
			  AND NOT EXISTS (SELECT 1 FROM pg_proc p WHERE p.oid = r.objid)
			  AND NOT EXISTS (SELECT 1 FROM pg_trigger t WHERE t.oid = r.objid)
		`).Scan(&shippedStaleCount); err != nil {
			t.Fatalf("shipped three-way NOT EXISTS query: %v", err)
		}
		if shippedStaleCount != 0 {
			t.Fatalf("test construction bug: expected the shipped query to see 0 stale rows for a cross-catalog OID reuse (that is the gap), got %d", shippedStaleCount)
		}

		state, err := sink.CheckProvisioningState(ctx)
		if err != nil {
			t.Fatalf("CheckProvisioningState: %v", err)
		}
		if state.Provisioned {
			t.Fatal("ADR-0007 Addendum 4 D41: CheckProvisioningState reported Provisioned=true with a row's classid claiming the wrong catalog for its OID (cross-catalog reuse)")
		}
		if !strings.Contains(state.Reason, "stale, repointed, or was never populated") {
			t.Fatalf("expected the identity-mismatch reason, got: %q", state.Reason)
		}
	})

	t.Run("owl_ledger_ddl_CREATE_privilege_facts", func(t *testing.T) {
		if _, err := superuser.Exec(ctx, `GRANT CREATE ON SCHEMA public TO owl_ledger_ddl`); err != nil {
			t.Fatalf("grant schema CREATE to owl_ledger_ddl: %v", err)
		}
		t.Cleanup(func() {
			bg := context.Background()
			c, err := pgx.Connect(bg, superuserDSN)
			if err != nil {
				t.Errorf("revoke schema CREATE: connect: %v", err)
				return
			}
			defer c.Close(bg)
			if _, err := c.Exec(bg, `REVOKE CREATE ON SCHEMA public FROM owl_ledger_ddl`); err != nil {
				t.Errorf("revoke schema CREATE: %v", err)
			}
		})

		state, err := sink.CheckProvisioningState(ctx)
		if err != nil {
			t.Fatalf("CheckProvisioningState: %v", err)
		}
		if state.Provisioned {
			t.Fatal("ADR-0007 Addendum 4 D41 part three: CheckProvisioningState reported Provisioned=true while owl_ledger_ddl holds CREATE on schema public")
		}
		if !strings.Contains(state.Reason, "CREATE on schema public") {
			t.Fatalf("expected the schema-CREATE-privilege reason, got: %q", state.Reason)
		}
	})
}
