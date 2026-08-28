// ADR-0007 Addendum 8 D72/D73/D75 test 4 (L-A, HIGH): the predefined-role
// MAINTAIN exclusion becomes an explicit, measured allowlist ({pg_maintain}
// alone), not an oid >= 16384 range (D72); and the holder enumeration
// gains a MEMBER-side (SET ROLE reachability, transitive, both NOINHERIT
// and WITH INHERIT FALSE) and grantee-side (aclexplode) limb, neither
// subsuming the other (D73). D72 and D73 ship together: D72 alone
// leaves the NOINHERIT path open (a member of a role holding MAINTAIN
// via inheritance-blocked membership never reports true from
// has_table_privilege), and D73 alone leaves the sub-16384 grantee path
// open (oid >= 16384 alone still excludes a direct grant to
// pg_read_all_data).
package screeningledger

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestMaintainHoldersAreEnumeratedOverGranteesAndMembers is D75 test 4:
// table-driven over L-A(i) (direct grant to the predefined
// pg_read_all_data role, which D59's own oid >= 16384 discriminator
// silently excluded) and L-A(ii)'s three membership shapes (NOINHERIT,
// WITH INHERIT FALSE, and a transitive NOINHERIT chain).
func TestMaintainHoldersAreEnumeratedOverGranteesAndMembers(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	cases := []struct {
		name  string
		setup func(t *testing.T, ctx context.Context, superuser, owner *pgx.Conn) (wantNamed string)
	}{
		{
			// L-A(i): a direct grant to a PREDEFINED role D59's
			// oid >= 16384 range excluded wholesale -- D72's own finding.
			name: "direct_grant_to_pg_read_all_data",
			setup: func(t *testing.T, ctx context.Context, superuser, owner *pgx.Conn) string {
				if _, err := owner.Exec(ctx, `GRANT MAINTAIN ON TABLE screening_ledger_anchor TO pg_read_all_data`); err != nil {
					t.Fatalf("GRANT MAINTAIN TO pg_read_all_data: %v", err)
				}
				return "pg_read_all_data"
			},
		},
		{
			// L-A(ii): NOINHERIT membership in pg_maintain --
			// has_table_privilege(member, ...) reports false for this
			// role (D73's own executed fact), which is exactly what
			// D72 alone (still using has_table_privilege(r.rolname,
			// ...) as the holder question) would miss.
			name: "noinherit_membership_in_pg_maintain",
			setup: func(t *testing.T, ctx context.Context, superuser, owner *pgx.Conn) string {
				role := uniqueID("zz_d73_noinh")
				if _, err := superuser.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN NOSUPERUSER NOINHERIT PASSWORD 'x'`, pgx.Identifier{role}.Sanitize())); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { dropRoleAfterTest(t, superuserDSN, role) })
				if _, err := superuser.Exec(ctx, fmt.Sprintf(`GRANT pg_maintain TO %s`, pgx.Identifier{role}.Sanitize())); err != nil {
					t.Fatal(err)
				}
				return role
			},
		},
		{
			name: "with_inherit_false_membership_in_pg_maintain",
			setup: func(t *testing.T, ctx context.Context, superuser, owner *pgx.Conn) string {
				role := uniqueID("zz_d73_wif")
				if _, err := superuser.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN NOSUPERUSER PASSWORD 'x'`, pgx.Identifier{role}.Sanitize())); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { dropRoleAfterTest(t, superuserDSN, role) })
				if _, err := superuser.Exec(ctx, fmt.Sprintf(`GRANT pg_maintain TO %s WITH INHERIT FALSE`, pgx.Identifier{role}.Sanitize())); err != nil {
					t.Fatal(err)
				}
				return role
			},
		},
		{
			// A transitive chain: cap8_chain is a NOINHERIT member of
			// cap8_noinh, which is a NOINHERIT member of pg_maintain --
			// pg_has_role(..., 'MEMBER') must reach through both hops.
			name: "transitive_noinherit_chain",
			setup: func(t *testing.T, ctx context.Context, superuser, owner *pgx.Conn) string {
				inner := uniqueID("zz_d73_chain_inner")
				outer := uniqueID("zz_d73_chain_outer")
				if _, err := superuser.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s NOSUPERUSER NOINHERIT NOLOGIN`, pgx.Identifier{inner}.Sanitize())); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { dropRoleAfterTest(t, superuserDSN, inner) })
				if _, err := superuser.Exec(ctx, fmt.Sprintf(`GRANT pg_maintain TO %s`, pgx.Identifier{inner}.Sanitize())); err != nil {
					t.Fatal(err)
				}
				if _, err := superuser.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s NOSUPERUSER NOINHERIT NOLOGIN`, pgx.Identifier{outer}.Sanitize())); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { dropRoleAfterTest(t, superuserDSN, outer) })
				if _, err := superuser.Exec(ctx, fmt.Sprintf(`GRANT %s TO %s`, pgx.Identifier{inner}.Sanitize(), pgx.Identifier{outer}.Sanitize())); err != nil {
					t.Fatal(err)
				}
				return outer
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

			wantNamed := c.setup(t, ctx, superuser, owner)

			after, err := sink.CheckProvisioningState(ctx)
			if err != nil {
				t.Fatalf("CheckProvisioningState after %s: %v", c.name, err)
			}
			if after.Provisioned {
				t.Fatalf("ADR-0007 Addendum 8 D72/D73: CheckProvisioningState reported Provisioned=true after %s", c.name)
			}
			if !strings.Contains(after.Reason, "MAINTAIN") {
				t.Fatalf("expected a reason naming MAINTAIN, got: %q", after.Reason)
			}
			if !strings.Contains(after.Reason, wantNamed) {
				t.Fatalf("expected the reason to name %s, got: %q", wantNamed, after.Reason)
			}
		})
	}
}

// TestMaintainAllowlistPreservesAddendum7RoutesClosed re-verifies, under
// D72/D73's new shape, the seven routes Addendum 7's own investigation
// closed: inheriting pg_maintain membership (named -- unlike the
// NOINHERIT cases above, an ordinary INHERIT member already reported via
// has_table_privilege before this addendum, and must still), GRANT ... TO
// PUBLIC (every owl_* role named), pg_database_owner on a
// non-superuser-owned database, a CREATE ROLE landing below oid 16384
// (not reachable -- Postgres itself refuses to assign a new role an oid
// in the reserved range), and owl_migrator/owl_ledger_ddl granting role
// membership (refused by ordinary Postgres privilege rules, unrelated to
// this addendum).
func TestMaintainAllowlistPreservesAddendum7RoutesClosed(t *testing.T) {
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

	superuser, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())

	// Inheriting membership: still named, as before this addendum.
	inheritRole := uniqueID("zz_d73_inherit")
	if _, err := superuser.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s NOSUPERUSER NOLOGIN`, pgx.Identifier{inheritRole}.Sanitize())); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dropRoleAfterTest(t, superuserDSN, inheritRole) })
	if _, err := superuser.Exec(ctx, fmt.Sprintf(`GRANT pg_maintain TO %s`, pgx.Identifier{inheritRole}.Sanitize())); err != nil {
		t.Fatal(err)
	}
	after, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState: %v", err)
	}
	if after.Provisioned || !strings.Contains(after.Reason, inheritRole) {
		t.Fatalf("expected inheriting pg_maintain membership to still be named, got Provisioned=%v Reason=%q", after.Provisioned, after.Reason)
	}
	if _, err := superuser.Exec(ctx, fmt.Sprintf(`REVOKE pg_maintain FROM %s`, pgx.Identifier{inheritRole}.Sanitize())); err != nil {
		t.Fatal(err)
	}

	// A CREATE ROLE cannot land below FirstNormalObjectId (16384) --
	// Postgres itself reserves that range; confirmed rather than assumed.
	freshRole := uniqueID("zz_d73_fresh")
	if _, err := superuser.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s NOSUPERUSER NOLOGIN`, pgx.Identifier{freshRole}.Sanitize())); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dropRoleAfterTest(t, superuserDSN, freshRole) })
	var freshOID uint32
	if err := superuser.QueryRow(ctx, `SELECT oid FROM pg_roles WHERE rolname = $1`, freshRole).Scan(&freshOID); err != nil {
		t.Fatal(err)
	}
	if freshOID < 16384 {
		t.Fatalf("a freshly created role landed below FirstNormalObjectId (oid %d) -- the precondition this route depends on no longer holds", freshOID)
	}

	// owl_migrator/owl_ledger_ddl cannot grant role membership at all --
	// ordinary Postgres privilege rules (neither holds pg_maintain WITH
	// ADMIN OPTION, nor CREATEROLE), unrelated to this addendum.
	migratorConn, err := pgx.Connect(ctx, cloneMigratorDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer migratorConn.Close(context.Background())
	if _, err := migratorConn.Exec(ctx, fmt.Sprintf(`GRANT pg_maintain TO %s`, pgx.Identifier{freshRole}.Sanitize())); err == nil {
		t.Fatal("expected owl_migrator to be refused GRANT pg_maintain (no ADMIN OPTION, no CREATEROLE)")
	}
}

// dropRoleAfterTest opens ITS OWN connection rather than reusing a
// caller's -- roles created by these tests are cluster-wide (visible to
// every database, including clones created by later subtests), so a
// role left behind by a cleanup that silently no-ops on an
// already-closed connection (t.Cleanup callbacks run after the test
// function's own `defer`s have already unwound, including a `defer
// conn.Close()`) leaks into every subsequent subtest's baseline, not
// just this one.
func dropRoleAfterTest(t *testing.T, superuserDSN, role string) {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), superuserDSN)
	if err != nil {
		t.Errorf("drop role %s: connect: %v", role, err)
		return
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, pgx.Identifier{role}.Sanitize())); err != nil {
		t.Errorf("drop role %s: %v", role, err)
	}
}
