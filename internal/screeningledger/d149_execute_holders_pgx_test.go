// ADR-0007 Addendum 19 D149/D151 test 7 (F2, MEDIUM): the two
// screening_ledger_purge_snapshots overloads' EXECUTE holder set is
// enumerated through D60/D61/D73's own two-limb machinery
// (privilegeHolders, now object-kind-parameterised), matching D60/D61's
// exact pattern -- both limbs, set equality in both directions, the
// measured (empty) predefined-role allowlist, and an installer
// postcondition that proves the property it installs.
//
// scripts/ci/provision_test_roles.sh grant-ddl-ownership revokes EXECUTE
// from PUBLIC and grants it to owl_migrator (373-376), and until this
// addendum nothing enumerated who could call either overload afterward
// -- checkPurgeSnapshotsDefiner is deliberately prosecdef-only (D27),
// and grant-ddl-ownership's own postcondition checked ownership and
// digests but not the EXECUTE ACL. Every route below reads
// Provisioned=true against the shipped, pre-D149 check.
package screeningledger

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestProvisioningStateAcceptsFunctionExecuteHoldersOnPrimary is D151
// item 7's positive: the shipped, declared {owl_ledger_ddl,
// owl_migrator} EXECUTE holder set reads Provisioned=true on the primary
// database.
func TestProvisioningStateAcceptsFunctionExecuteHoldersOnPrimary(t *testing.T) {
	sink, ctx := newTestSink(t)
	state, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState: %v", err)
	}
	if !state.Provisioned {
		t.Fatalf("ADR-0007 Addendum 19 D149: the shipped, declared EXECUTE holder set should read Provisioned=true on the primary database, got Reason=%q", state.Reason)
	}
}

// TestProvisioningStateAcceptsFunctionExecuteHoldersOnTemplateClone is
// D151 item 7's "and so does a TEMPLATE clone" (Addendum 5's population
// positive) -- a byte-identical CREATE DATABASE ... TEMPLATE copy must
// read the same clean state, not merely the primary itself.
func TestProvisioningStateAcceptsFunctionExecuteHoldersOnTemplateClone(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	sink, err := NewPostgresSink(ctx, withDatabase(t, migratorDSN, clone.dbName), 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())

	state, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState: %v", err)
	}
	if !state.Provisioned {
		t.Fatalf("ADR-0007 Addendum 19 D149: a TEMPLATE clone of a clean database should read Provisioned=true, got Reason=%q", state.Reason)
	}
}

const purgeSnapshotsTimeFloorSignature = `screening_ledger_purge_snapshots(text,int8,timestamptz,text,text)`
const purgeSnapshotsArrayFormSignature = `screening_ledger_purge_snapshots(text[],text,int4[],timestamptz[],text,text)`

// dropCloneRoleAfterTest drops role, first releasing any privileges it
// holds within the clone database (DROP OWNED BY) -- unlike a pure
// membership grant (GRANT some_role TO role, which DROP ROLE unwinds on
// its own), a role directly GRANTed a privilege on an object blocks
// plain DROP ROLE until that ACL entry is gone. Connects to
// cloneSuperuserDSN (the clone this role's privilege was granted in),
// and must run BEFORE the clone database itself is dropped -- since
// t.Cleanup runs LIFO, callers register this AFTER newD50Clone's own
// cleanup is already registered, so this one fires first.
func dropCloneRoleAfterTest(t *testing.T, cloneSuperuserDSN, role string) {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), cloneSuperuserDSN)
	if err != nil {
		t.Errorf("drop clone role %s: connect: %v", role, err)
		return
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(context.Background(), fmt.Sprintf(`DROP OWNED BY %s`, pgx.Identifier{role}.Sanitize())); err != nil {
		t.Errorf("drop clone role %s: DROP OWNED BY: %v", role, err)
	}
	if _, err := conn.Exec(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, pgx.Identifier{role}.Sanitize())); err != nil {
		t.Errorf("drop clone role %s: %v", role, err)
	}
}

// TestProvisioningStateDetectsUndeclaredFunctionExecuteHolder is D151
// item 7's route table: every route ADR-0007 Addendum 19's design pass
// measured (direct grant, grant to PUBLIC, NOINHERIT membership, WITH
// INHERIT FALSE membership, a transitive chain, and a role with no
// members) is a named failure -- against a check that read
// Provisioned=true on every one of them before D149.
func TestProvisioningStateDetectsUndeclaredFunctionExecuteHolder(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	grantExecuteBothOverloads := func(ctx context.Context, owner *pgx.Conn, grantee string) error {
		for _, sig := range []string{purgeSnapshotsTimeFloorSignature, purgeSnapshotsArrayFormSignature} {
			if _, err := owner.Exec(ctx, fmt.Sprintf(`GRANT EXECUTE ON FUNCTION %s TO %s`, sig, pgx.Identifier{grantee}.Sanitize())); err != nil {
				return fmt.Errorf("GRANT EXECUTE ON %s TO %s: %w", sig, grantee, err)
			}
		}
		return nil
	}

	cases := []struct {
		name  string
		setup func(t *testing.T, ctx context.Context, superuser, owner *pgx.Conn, cloneSuperuserDSN string) (wantNamed string)
	}{
		{
			// Route r1: direct grant to an undeclared, unprivileged role.
			name: "direct_grant_to_owl_app",
			setup: func(t *testing.T, ctx context.Context, superuser, owner *pgx.Conn, cloneSuperuserDSN string) string {
				if err := grantExecuteBothOverloads(ctx, owner, "owl_app"); err != nil {
					t.Fatal(err)
				}
				return "owl_app"
			},
		},
		{
			// Route r2: grant to PUBLIC -- every non-superuser role,
			// including every predefined role, genuinely holds EXECUTE
			// under this grant (correctly not allowlisted: D72's own
			// point is that a PUBLIC grant makes the capability real for
			// them), so the reason names the live holder-side population
			// rather than the literal word "PUBLIC" (which only the
			// grantee-side aclexplode limb, not reached here since the
			// holder-side limb fails first, would print).
			name: "grant_to_public",
			setup: func(t *testing.T, ctx context.Context, superuser, owner *pgx.Conn, cloneSuperuserDSN string) string {
				for _, sig := range []string{purgeSnapshotsTimeFloorSignature, purgeSnapshotsArrayFormSignature} {
					if _, err := owner.Exec(ctx, `GRANT EXECUTE ON FUNCTION `+sig+` TO PUBLIC`); err != nil {
						t.Fatal(err)
					}
				}
				return "pg_read_all_data"
			},
		},
		{
			// Route r3: NOINHERIT membership in a role that itself holds
			// EXECUTE -- has_function_privilege(member, ...) reports
			// false for this role directly, so only the holder-side
			// pg_has_role(...,'MEMBER') traversal catches it.
			name: "noinherit_membership",
			setup: func(t *testing.T, ctx context.Context, superuser, owner *pgx.Conn, cloneSuperuserDSN string) string {
				grp := uniqueID("zz_d149_grp")
				member := uniqueID("zz_d149_noinh")
				if _, err := superuser.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s NOSUPERUSER NOLOGIN`, pgx.Identifier{grp}.Sanitize())); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { dropCloneRoleAfterTest(t, cloneSuperuserDSN, grp) })
				if err := grantExecuteBothOverloads(ctx, owner, grp); err != nil {
					t.Fatal(err)
				}
				if _, err := superuser.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN NOSUPERUSER NOINHERIT PASSWORD 'x'`, pgx.Identifier{member}.Sanitize())); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { dropRoleAfterTest(t, superuserDSN, member) })
				if _, err := superuser.Exec(ctx, fmt.Sprintf(`GRANT %s TO %s`, pgx.Identifier{grp}.Sanitize(), pgx.Identifier{member}.Sanitize())); err != nil {
					t.Fatal(err)
				}
				return member
			},
		},
		{
			// Route r4: an ordinary member granted WITH INHERIT FALSE on
			// the per-grant, not the role default.
			name: "with_inherit_false_membership",
			setup: func(t *testing.T, ctx context.Context, superuser, owner *pgx.Conn, cloneSuperuserDSN string) string {
				grp := uniqueID("zz_d149_grp2")
				member := uniqueID("zz_d149_wif")
				if _, err := superuser.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s NOSUPERUSER NOLOGIN`, pgx.Identifier{grp}.Sanitize())); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { dropCloneRoleAfterTest(t, cloneSuperuserDSN, grp) })
				if err := grantExecuteBothOverloads(ctx, owner, grp); err != nil {
					t.Fatal(err)
				}
				if _, err := superuser.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s NOSUPERUSER NOLOGIN`, pgx.Identifier{member}.Sanitize())); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { dropRoleAfterTest(t, superuserDSN, member) })
				if _, err := superuser.Exec(ctx, fmt.Sprintf(`GRANT %s TO %s WITH INHERIT FALSE`, pgx.Identifier{grp}.Sanitize(), pgx.Identifier{member}.Sanitize())); err != nil {
					t.Fatal(err)
				}
				return member
			},
		},
		{
			// Route r5: a transitive NOINHERIT chain, two hops.
			name: "transitive_chain",
			setup: func(t *testing.T, ctx context.Context, superuser, owner *pgx.Conn, cloneSuperuserDSN string) string {
				grp := uniqueID("zz_d149_grp3")
				mid := uniqueID("zz_d149_mid")
				chain := uniqueID("zz_d149_chain")
				if _, err := superuser.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s NOSUPERUSER NOLOGIN`, pgx.Identifier{grp}.Sanitize())); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { dropCloneRoleAfterTest(t, cloneSuperuserDSN, grp) })
				if err := grantExecuteBothOverloads(ctx, owner, grp); err != nil {
					t.Fatal(err)
				}
				if _, err := superuser.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s NOSUPERUSER NOINHERIT NOLOGIN`, pgx.Identifier{mid}.Sanitize())); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { dropRoleAfterTest(t, superuserDSN, mid) })
				if _, err := superuser.Exec(ctx, fmt.Sprintf(`GRANT %s TO %s`, pgx.Identifier{grp}.Sanitize(), pgx.Identifier{mid}.Sanitize())); err != nil {
					t.Fatal(err)
				}
				if _, err := superuser.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s NOSUPERUSER NOINHERIT NOLOGIN`, pgx.Identifier{chain}.Sanitize())); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { dropRoleAfterTest(t, superuserDSN, chain) })
				if _, err := superuser.Exec(ctx, fmt.Sprintf(`GRANT %s TO %s`, pgx.Identifier{mid}.Sanitize(), pgx.Identifier{chain}.Sanitize())); err != nil {
					t.Fatal(err)
				}
				return chain
			},
		},
		{
			// Route r6: a role with no members at all, granted directly
			// -- both limbs see it (a role is always a MEMBER of
			// itself), still a named failure since it is undeclared.
			name: "memberless_role_direct_grant",
			setup: func(t *testing.T, ctx context.Context, superuser, owner *pgx.Conn, cloneSuperuserDSN string) string {
				empty := uniqueID("zz_d149_empty")
				if _, err := superuser.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s NOSUPERUSER NOLOGIN`, pgx.Identifier{empty}.Sanitize())); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { dropCloneRoleAfterTest(t, cloneSuperuserDSN, empty) })
				if err := grantExecuteBothOverloads(ctx, owner, empty); err != nil {
					t.Fatal(err)
				}
				return empty
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
			cloneMigratorDSN := withDatabase(t, migratorDSN, clone.dbName)

			sink, err := NewPostgresSink(ctx, cloneMigratorDSN, 10*time.Second)
			if err != nil {
				t.Fatalf("NewPostgresSink: %v", err)
			}
			defer sink.Close(context.Background())

			baseline, err := sink.CheckProvisioningState(ctx)
			if err != nil {
				t.Fatalf("baseline: %v", err)
			}
			if !baseline.Provisioned {
				t.Fatalf("test precondition failed: clone must start provisioned (Reason=%q)", baseline.Reason)
			}

			superuser, err := pgx.Connect(ctx, clone.superuserDSN)
			if err != nil {
				t.Fatalf("connect as bootstrap superuser: %v", err)
			}
			defer superuser.Close(context.Background())
			owner, err := pgx.Connect(ctx, clone.ledgerDDLDSN)
			if err != nil {
				t.Fatalf("connect as owl_ledger_ddl: %v", err)
			}
			defer owner.Close(context.Background())

			wantNamed := c.setup(t, ctx, superuser, owner, clone.superuserDSN)

			after, err := sink.CheckProvisioningState(ctx)
			if err != nil {
				t.Fatalf("CheckProvisioningState after %s: %v", c.name, err)
			}
			if after.Provisioned {
				t.Fatalf("ADR-0007 Addendum 19 D149: CheckProvisioningState reported Provisioned=true after %s -- the shipped, pre-D149 check reads Provisioned=true on every route in this table", c.name)
			}
			if !strings.Contains(after.Reason, "EXECUTE") {
				t.Fatalf("expected a reason naming EXECUTE, got: %q", after.Reason)
			}
			if !strings.Contains(after.Reason, wantNamed) {
				t.Fatalf("expected the reason to name %s, got: %q", wantNamed, after.Reason)
			}
		})
	}
}

// TestProvisioningStateDetectsMissingFunctionExecuteHolder is D151 item
// 7's missing-holder direction: revoking a DECLARED holder's EXECUTE is
// equally a named failure -- D39's own probes never checked this at
// all, and D61's own text makes it part of the same set-equality
// assertion rather than a one-directional negative.
func TestProvisioningStateDetectsMissingFunctionExecuteHolder(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	cloneMigratorDSN := withDatabase(t, migratorDSN, clone.dbName)

	sink, err := NewPostgresSink(ctx, cloneMigratorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())

	baseline, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if !baseline.Provisioned {
		t.Fatalf("test precondition failed: clone must start provisioned (Reason=%q)", baseline.Reason)
	}

	owner, err := pgx.Connect(ctx, clone.ledgerDDLDSN)
	if err != nil {
		t.Fatalf("connect as owl_ledger_ddl: %v", err)
	}
	defer owner.Close(context.Background())
	if _, err := owner.Exec(ctx, `REVOKE EXECUTE ON FUNCTION `+purgeSnapshotsTimeFloorSignature+` FROM owl_migrator`); err != nil {
		t.Fatalf("REVOKE EXECUTE ... FROM owl_migrator: %v", err)
	}

	after, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState after revoke: %v", err)
	}
	if after.Provisioned {
		t.Fatal("ADR-0007 Addendum 19 D149: CheckProvisioningState reported Provisioned=true after revoking a declared holder's EXECUTE")
	}
	if !strings.Contains(after.Reason, "EXECUTE") || !strings.Contains(after.Reason, "owl_migrator") {
		t.Fatalf("expected a reason naming EXECUTE and owl_migrator, got: %q", after.Reason)
	}
}

// TestGrantDdlOwnershipRefusesUndeclaredFunctionExecuteHolder is D151
// item 7's installer check: grant-ddl-ownership on route r1's granted
// state exits non-zero naming owl_app, where it printed three PASS
// lines before D149 -- and D90's non-disarm property (Addendum 10)
// holds on this new refusal path too: both event triggers stay
// ENABLE ALWAYS and all three registries stay at 20/4/1 (ADR-0007 Addendum 21 D166).
func TestGrantDdlOwnershipRefusesUndeclaredFunctionExecuteHolder(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()
	scriptPath := d62ScriptPath(t)

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	owner, err := pgx.Connect(ctx, clone.ledgerDDLDSN)
	if err != nil {
		t.Fatalf("connect as owl_ledger_ddl: %v", err)
	}
	defer owner.Close(context.Background())
	for _, sig := range []string{purgeSnapshotsTimeFloorSignature, purgeSnapshotsArrayFormSignature} {
		if _, err := owner.Exec(ctx, `GRANT EXECUTE ON FUNCTION `+sig+` TO owl_app`); err != nil {
			t.Fatalf("GRANT EXECUTE ON %s TO owl_app: %v", sig, err)
		}
	}

	output, runErr := runGrantDDLOwnership(t, scriptPath, clone.superuserDSN, clone.dbName)
	if runErr == nil {
		t.Fatalf("ADR-0007 Addendum 19 D149: grant-ddl-ownership succeeded against a database where owl_app holds EXECUTE on both purge_snapshots overloads -- expected refusal\n%s", output)
	}
	if !strings.Contains(output, "owl_app") || !strings.Contains(output, "EXECUTE") {
		t.Fatalf("expected the installer's refusal to name owl_app and EXECUTE, got:\n%s", output)
	}

	superuser, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())

	triggers := eventTriggerStates(t, ctx, superuser)
	if len(triggers) != 2 || triggers["sec7_protect_ddl_objects_on_drop"] != "A" || triggers["sec7_protect_ddl_objects_on_alter"] != "A" {
		t.Fatalf("ADR-0007 Addendum 10 D90 (unregressed): expected both event triggers ENABLE ALWAYS after this refusal, got %v\noutput:\n%s", triggers, output)
	}
	obj, rel, bind := registryRowCounts(t, ctx, superuser)
	if obj != 20 || rel != 4 || bind != 1 {
		t.Fatalf("ADR-0007 Addendum 10 D90 (unregressed): expected registries at 20/4/1 after this refusal (ADR-0007 Addendum 21 D166), got obj=%d rel=%d bind=%d\noutput:\n%s", obj, rel, bind, output)
	}
}
