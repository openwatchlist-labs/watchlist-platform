// ADR-0007 Addendum 4 D39 (H-C, HIGH): the privilege probes reach
// column granularity. CAP #3 §7.1's exact demonstration -- a
// column-level GRANT on screening_ledger_retention_tombstone leaves
// has_table_privilege reading false while the granted INSERT genuinely
// succeeds -- reproduced here, table-driven over the direct-grant,
// PUBLIC, and role-membership routes CAP #3's own comparison table
// names, plus the anchor writer's SELECT probe.
package screeningledger

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestProvisioningStateDetectsColumnLevelGrant is D39 / D42 point 3.
func TestProvisioningStateDetectsColumnLevelGrant(t *testing.T) {
	superDSN := requireBootstrapSuperuserDatabaseURL(t)
	ctx := context.Background()

	superConn, err := pgx.Connect(ctx, superDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superConn.Close(context.Background())

	sink, sinkCtx := newTestSink(t)

	// Baseline: with no forgery grant in place, the real provisioning
	// state (already provisioned by newTestSink's Migrate + this
	// package's CI-equivalent role setup) must read Provisioned=true, or
	// every case below proves nothing about what changed.
	baseline, err := sink.CheckProvisioningState(sinkCtx)
	if err != nil {
		t.Fatalf("CheckProvisioningState baseline: %v", err)
	}
	if !baseline.Provisioned {
		t.Fatalf("test precondition failed: database is not provisioned before any forgery grant (Reason=%q) -- this test cannot isolate D39's effect", baseline.Reason)
	}

	cases := []struct {
		name    string
		table   string
		column  string
		priv    string
		grantee string // the role has_table_privilege/has_column_privilege is asked about
		grant   string
		revoke  string
	}{
		{
			name:    "direct_grant_to_migrator",
			table:   "screening_ledger_retention_tombstone",
			column:  "snapshot_sha256",
			priv:    "INSERT",
			grantee: "owl_migrator",
			grant:   "GRANT INSERT (snapshot_sha256,purged_at,operator,reason) ON screening_ledger_retention_tombstone TO owl_migrator",
			revoke:  "REVOKE INSERT (snapshot_sha256,purged_at,operator,reason) ON screening_ledger_retention_tombstone FROM owl_migrator",
		},
		{
			name:    "grant_to_public",
			table:   "screening_ledger_retention_tombstone",
			column:  "snapshot_sha256",
			priv:    "INSERT",
			grantee: "owl_migrator",
			grant:   "GRANT INSERT (snapshot_sha256,purged_at,operator,reason) ON screening_ledger_retention_tombstone TO PUBLIC",
			revoke:  "REVOKE INSERT (snapshot_sha256,purged_at,operator,reason) ON screening_ledger_retention_tombstone FROM PUBLIC",
		},
		{
			name:    "grant_via_role_membership",
			table:   "screening_ledger_retention_tombstone",
			column:  "snapshot_sha256",
			priv:    "INSERT",
			grantee: "owl_migrator",
			grant:   "GRANT INSERT (snapshot_sha256,purged_at,operator,reason) ON screening_ledger_retention_tombstone TO sec7_d39_grantee_role",
			revoke:  "REVOKE INSERT (snapshot_sha256,purged_at,operator,reason) ON screening_ledger_retention_tombstone FROM sec7_d39_grantee_role",
		},
		{
			name:    "anchor_writer_select_probe",
			table:   "screening_ledger_anchor",
			column:  "sequence",
			priv:    "SELECT",
			grantee: "owl_ledger_anchor",
			grant:   "GRANT SELECT (ledger_id,sequence,event_sha256,audit_sha256,audit_sequence,policy_sha256,anchored_at,anchor_mac) ON screening_ledger_anchor TO owl_ledger_anchor",
			revoke:  "REVOKE SELECT (ledger_id,sequence,event_sha256,audit_sha256,audit_sequence,policy_sha256,anchored_at,anchor_mac) ON screening_ledger_anchor FROM owl_ledger_anchor",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.name == "grant_via_role_membership" {
				// A role owl_migrator is a MEMBER of, granted the column
				// privilege directly -- CAP #3's own third comparison
				// column ("column GRANT to a role the target is a MEMBER
				// of"), the case the raw pg_attribute.attacl + aclexplode
				// alternative D39's design phase rejected cannot see at
				// all (an ACL entry names its grantee literally and does
				// not expand membership).
				if _, err := superConn.Exec(ctx, `CREATE ROLE sec7_d39_grantee_role`); err != nil {
					t.Fatalf("CREATE ROLE sec7_d39_grantee_role: %v", err)
				}
				if _, err := superConn.Exec(ctx, `GRANT sec7_d39_grantee_role TO owl_migrator`); err != nil {
					t.Fatalf("GRANT sec7_d39_grantee_role TO owl_migrator: %v", err)
				}
				t.Cleanup(func() {
					bg := context.Background()
					if _, err := superConn.Exec(bg, `REVOKE sec7_d39_grantee_role FROM owl_migrator`); err != nil {
						t.Errorf("cleanup: REVOKE sec7_d39_grantee_role FROM owl_migrator: %v", err)
					}
					if _, err := superConn.Exec(bg, `DROP ROLE sec7_d39_grantee_role`); err != nil {
						t.Errorf("cleanup: DROP ROLE sec7_d39_grantee_role: %v", err)
					}
				})
			}
			if _, err := superConn.Exec(ctx, c.grant); err != nil {
				t.Fatalf("%s: GRANT failed: %v", c.name, err)
			}
			t.Cleanup(func() {
				if _, err := superConn.Exec(context.Background(), c.revoke); err != nil {
					t.Errorf("%s: REVOKE cleanup failed (database left with a forgery grant -- fix manually): %v", c.name, err)
				}
			})

			// The old (pre-D39) probe, run directly: table-level
			// has_table_privilege must read false even though the
			// privilege is genuinely usable via the column grant --
			// CAP #3's exact finding.
			var tableProbe bool
			if err := superConn.QueryRow(ctx, `SELECT has_table_privilege($1, $2, $3)`, c.grantee, c.table, c.priv).Scan(&tableProbe); err != nil {
				t.Fatalf("%s: has_table_privilege probe: %v", c.name, err)
			}
			if tableProbe {
				t.Fatalf("%s: test construction bug: expected the table-level probe to already read false for a column-only grant, got true", c.name)
			}

			// The new probe: has_column_privilege over the live column
			// set must read true.
			columnProbe, err := sink.anyColumnPrivilege(sinkCtx, c.grantee, c.table, c.priv)
			if err != nil {
				t.Fatalf("%s: anyColumnPrivilege: %v", c.name, err)
			}
			if !columnProbe {
				t.Fatalf("%s: ADR-0007 Addendum 4 D39: anyColumnPrivilege did not detect the column-level grant that has_table_privilege missed", c.name)
			}

			// The real CheckProvisioningState must now report
			// Provisioned=false, naming this specific gap.
			state, err := sink.CheckProvisioningState(sinkCtx)
			if err != nil {
				t.Fatalf("%s: CheckProvisioningState: %v", c.name, err)
			}
			if state.Provisioned {
				t.Fatalf("%s: ADR-0007 Addendum 4 D39: CheckProvisioningState reported Provisioned=true with a live column-level forgery grant in place -- D33's table-level probe regression", c.name)
			}
			t.Logf("%s: CheckProvisioningState correctly reports Provisioned=false: %q", c.name, state.Reason)
		})
	}
}

// TestProvisioningStateColumnGrantEnablesRealForgery is CAP #3 §7.1's
// second half: the tombstone-forgery INSERT the column grant enables
// must actually succeed against the live database -- otherwise D39
// would only be proven to change a probe's reading, not to have closed
// a real hole (this file's sibling test proves the probe; this proves
// the hole it is reading is real). Run inside a transaction that is
// always rolled back, never committed -- screening_ledger_retention_
// tombstone's row-immutability trigger makes a committed forged row
// permanent and undeletable even by a superuser (append-only, by
// design), so committing it here would leave a live piece of forged
// evidence in a database other tests in this package depend on.
// Whether the INSERT itself is permitted is fully decided at Exec time,
// independent of whether the surrounding transaction later commits.
func TestProvisioningStateColumnGrantEnablesRealForgery(t *testing.T) {
	superDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ctx := context.Background()

	superConn, err := pgx.Connect(ctx, superDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	// t.Cleanup, not defer: registered before the REVOKE cleanup below so
	// LIFO ordering closes this connection LAST, after the REVOKE has
	// run on it -- a plain defer would close it first, since deferred
	// statements run before the enclosing function returns to the
	// testing framework's own Cleanup invocation.
	t.Cleanup(func() { superConn.Close(context.Background()) })

	grant := "GRANT INSERT (snapshot_sha256,purged_at,operator,reason) ON screening_ledger_retention_tombstone TO owl_migrator"
	revoke := "REVOKE INSERT (snapshot_sha256,purged_at,operator,reason) ON screening_ledger_retention_tombstone FROM owl_migrator"
	if _, err := superConn.Exec(ctx, grant); err != nil {
		t.Fatalf("GRANT failed: %v", err)
	}
	t.Cleanup(func() {
		if _, err := superConn.Exec(context.Background(), revoke); err != nil {
			t.Errorf("REVOKE cleanup failed (database left with a forgery grant -- fix manually): %v", err)
		}
	})

	migratorConn, err := pgx.Connect(ctx, migratorDSN)
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	defer migratorConn.Close(context.Background())

	tx, err := migratorConn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(context.Background())

	forgedSHA := "d39-column-grant-forgery-" + uniqueID("sha")
	if _, err := tx.Exec(ctx,
		`INSERT INTO screening_ledger_retention_tombstone (snapshot_sha256,purged_at,operator,reason) VALUES ($1, now(), 'attacker', 'forged without the definer function')`,
		forgedSHA,
	); err != nil {
		t.Fatalf("test construction bug: CAP #3's forgery INSERT must succeed via the column grant, got: %v", err)
	}
	t.Log("CAP #3 §7.1's forgery: owl_migrator INSERT into screening_ledger_retention_tombstone succeeded via the column-level grant (transaction rolled back, not committed)")
}
