// ADR-0007 Addendum 5 D47/D49 test 6: sec7_protected_relation's seven
// recorded STATE columns (everything besides objid) get a referent of
// their own. CAP #4 §7.5 case G's exact reproduction: rewriting
// trigger_oids alone, with identity and population left intact, passed
// every check that shipped before this addendum. Per D42's convention
// (referenced by D49), this test proves the CURRENT (pre-fix, in the
// sense of the check that shipped before D47) behaviour is acceptance --
// not just that the post-fix behaviour is refusal -- table-driven over
// all seven columns, plus a clean-state positive so the comparison is not
// merely tightened into a false refusal on a healthy database.
package screeningledger

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestCheckProvisioningStateDetectsRewrittenRecordedState(t *testing.T) {
	migratorDSN := requireMigratorDSN(t)
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	ctx := context.Background()

	sink, err := NewPostgresSink(ctx, migratorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())

	superuser, err := pgx.Connect(ctx, superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())

	baseline, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("baseline CheckProvisioningState: %v", err)
	}
	if !baseline.Provisioned {
		t.Fatalf("test precondition failed: database is not provisioned before any recorded-state tampering (Reason=%q)", baseline.Reason)
	}

	// preShippedThreeWayCheck is exactly what protectedRelationIdentityReason
	// (D41, unchanged by this addendum) asserts on its own: population
	// count and objid-resolves-via-pg_identify_object. It says nothing
	// about the seven recorded state columns D47 adds -- run directly, it
	// proves the state this test rewrites was, on its own, invisible to
	// every check that shipped before D47.
	preShippedThreeWayCheck := func(t *testing.T) bool {
		t.Helper()
		var totalRows int
		if err := superuser.QueryRow(ctx, `SELECT count(*) FROM sec7_protected_relation`).Scan(&totalRows); err != nil {
			t.Fatalf("count sec7_protected_relation: %v", err)
		}
		if totalRows != len(requiredProtectedRelations) {
			return false
		}
		for _, identity := range requiredProtectedRelations {
			var matches int
			if err := superuser.QueryRow(ctx, `
				SELECT count(*) FROM sec7_protected_relation r
				WHERE (pg_identify_object('pg_class'::regclass, r.objid, 0)).identity = $1
			`, identity).Scan(&matches); err != nil {
				t.Fatalf("pre-D47 identity check for %s: %v", identity, err)
			}
			if matches != 1 {
				return false
			}
		}
		return true
	}

	cases := []struct {
		name    string
		mutate  string
		restore string
		reason  string
	}{
		{
			name:    "relowner",
			mutate:  `UPDATE sec7_protected_relation SET relowner = 'owl_migrator'::regrole::oid WHERE identity = 'public.screening_ledger_anchor'`,
			restore: `UPDATE sec7_protected_relation SET relowner = 'owl_ledger_ddl'::regrole::oid WHERE identity = 'public.screening_ledger_anchor'`,
			reason:  "recorded relowner",
		},
		{
			name:    "relkind",
			mutate:  `UPDATE sec7_protected_relation SET relkind = 'v' WHERE identity = 'public.screening_ledger_anchor'`,
			restore: `UPDATE sec7_protected_relation SET relkind = 'r' WHERE identity = 'public.screening_ledger_anchor'`,
			reason:  "recorded relkind",
		},
		{
			name:    "relrowsecurity",
			mutate:  `UPDATE sec7_protected_relation SET relrowsecurity = true WHERE identity = 'public.screening_ledger_anchor'`,
			restore: `UPDATE sec7_protected_relation SET relrowsecurity = false WHERE identity = 'public.screening_ledger_anchor'`,
			reason:  "row-level-security flags",
		},
		{
			name:    "relforcerowsecurity",
			mutate:  `UPDATE sec7_protected_relation SET relforcerowsecurity = true WHERE identity = 'public.screening_ledger_anchor'`,
			restore: `UPDATE sec7_protected_relation SET relforcerowsecurity = false WHERE identity = 'public.screening_ledger_anchor'`,
			reason:  "row-level-security flags",
		},
		{
			name:    "trigger_oids",
			mutate:  `UPDATE sec7_protected_relation SET trigger_oids = trigger_oids || ARRAY[999999]::oid[] WHERE identity = 'public.screening_ledger_anchor'`,
			restore: `UPDATE sec7_protected_relation SET trigger_oids = array_remove(trigger_oids, 999999) WHERE identity = 'public.screening_ledger_anchor'`,
			reason:  "recorded trigger_oids",
		},
		{
			// ADR-0007 Addendum 6 D50: index_oids was replaced by
			// index_defs (a sorted text[] of pg_get_indexdef()
			// renderings, not OIDs) -- the mutation targets the new
			// column, tampering with a definition string rather than an
			// OID, since that is what a corrupted recording now looks
			// like.
			name:    "index_defs",
			mutate:  `UPDATE sec7_protected_relation SET index_defs = index_defs || ARRAY['-- tampered']::text[] WHERE identity = 'public.screening_ledger_anchor'`,
			restore: `UPDATE sec7_protected_relation SET index_defs = array_remove(index_defs, '-- tampered') WHERE identity = 'public.screening_ledger_anchor'`,
			reason:  "recorded index_defs",
		},
		{
			name:    "policy_oids",
			mutate:  `UPDATE sec7_protected_relation SET policy_oids = ARRAY[999999]::oid[] WHERE identity = 'public.screening_ledger_anchor'`,
			restore: `UPDATE sec7_protected_relation SET policy_oids = ARRAY[]::oid[] WHERE identity = 'public.screening_ledger_anchor'`,
			reason:  "recorded policy_oids",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// CAP #4 §7.5 case G's own point, re-verified per-column: the
			// check that shipped before this addendum reads this exact
			// state as fully populated and correctly identified.
			if !preShippedThreeWayCheck(t) {
				t.Fatal("test precondition failed: the pre-D47 identity/population check already reads this database as not populated, before any mutation")
			}

			if _, err := superuser.Exec(ctx, tc.mutate); err != nil {
				t.Fatalf("mutate %s: %v", tc.name, err)
			}
			t.Cleanup(func() {
				bg := context.Background()
				c, err := pgx.Connect(bg, superuserDSN)
				if err != nil {
					t.Errorf("restore %s: connect: %v", tc.name, err)
					return
				}
				defer c.Close(bg)
				if _, err := c.Exec(bg, tc.restore); err != nil {
					t.Errorf("restore %s: %v", tc.name, err)
				}
			})

			// The pre-D47 check still reads this exact state as
			// populated and correctly identified -- CAP #4 §7.5 case G's
			// finding, reproduced live rather than asserted.
			if !preShippedThreeWayCheck(t) {
				t.Fatalf("test construction bug: the pre-D47 identity/population check should still pass after mutating only %s (that is the gap D47 closes)", tc.name)
			}

			state, err := sink.CheckProvisioningState(ctx)
			if err != nil {
				t.Fatalf("CheckProvisioningState after mutating %s: %v", tc.name, err)
			}
			if state.Provisioned {
				t.Fatalf("ADR-0007 Addendum 5 D47: CheckProvisioningState reported Provisioned=true with %s rewritten (CAP #4 §7.5 case G)", tc.name)
			}
			if !strings.Contains(state.Reason, tc.reason) {
				t.Fatalf("expected a reason naming %q, got: %q", tc.reason, state.Reason)
			}
		})
	}

	t.Run("clean_state_positive", func(t *testing.T) {
		// D37's/D42's collateral-damage discipline, applied to D47: a
		// suite that proves only the refusals has not proven the
		// comparison is safe to install. Confirms the seven-column
		// reconciliation does not false-positive on the database every
		// other test in this package depends on being provisioned.
		state, err := sink.CheckProvisioningState(ctx)
		if err != nil {
			t.Fatalf("CheckProvisioningState on a clean database: %v", err)
		}
		if !state.Provisioned {
			t.Fatalf("ADR-0007 Addendum 5 D47: CheckProvisioningState reported Provisioned=false on an untampered, freshly provisioned database (Reason=%q) -- D47's comparison must not be tighter than the state grant-ddl-ownership actually produces", state.Reason)
		}
	})
}
