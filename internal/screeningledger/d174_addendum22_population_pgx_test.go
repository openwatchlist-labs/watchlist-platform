// ADR-0007 Addendum 22 D174/D175/D176 (CAP #22 C22-A/C22-B): three
// controls that range over "every protected relation" -- D60's MAINTAIN
// empty-set assertion, D61's privilege-holder matrix, D33's owner check
// -- had silently stopped covering screening_ledger_event and
// screening_ledger_snapshot once Addendum 21 D166 grew
// sec7_protected_relation from two members to four. This file is
// D179's proof obligation for the Go/pgx half of the fix (test 1
// C22-A itself, test 2 C22-A's consequence, test 3 the re-grant route
// matrix, test 4 D175, test 5 D176, test 6 the DSN-free derivation
// guard). Every test reproduces the specific gap named above rather
// than merely asserting the post-fix shape, per D179's own standard.
package screeningledger

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// seedD174EventRows inserts n ordinary, well-formed screening_ledger_event
// rows as owl_migrator -- enough that a REINDEX ... CONCURRENTLY rebuild
// outlives a short statement_timeout (ADR-0007 Addendum 22's own
// reproduction used 300,000 for the same reason).
func seedD174EventRows(t *testing.T, ctx context.Context, migratorDSN string, n int, prefix string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, migratorDSN)
	if err != nil {
		t.Fatalf("connect as owl_migrator to seed rows: %v", err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(ctx, `
		INSERT INTO screening_ledger_event
		  (event_id, ledger_id, sequence, event_sha256, previous_event_sha256, occurred_at, route, http_status,
		   request_sha256, response_sha256, request_snapshot_sha256, response_snapshot_sha256, retention_class, expires_at, event_json)
		SELECT
		  $1 || '-' || g, $1 || '-ledger', g,
		  encode(sha256(($1 || '-sha-' || g)::bytea), 'hex'),
		  encode(sha256(($1 || '-prev-' || g)::bytea), 'hex'),
		  now(), '/screen', 200,
		  encode(sha256(($1 || '-req-' || g)::bytea), 'hex'),
		  encode(sha256(($1 || '-resp-' || g)::bytea), 'hex'),
		  encode(sha256(($1 || '-reqsnap-' || g)::bytea), 'hex'),
		  encode(sha256(($1 || '-respsnap-' || g)::bytea), 'hex'),
		  'standard', now() + interval '80 years', '{}'::jsonb
		FROM generate_series(1, $2) g
	`, prefix, n); err != nil {
		t.Fatalf("seed %d event rows: %v", n, err)
	}
}

// TestD174MaintainAssertionRangesOverAllFourRelations is ADR-0007
// Addendum 22 D179 test 1: before this addendum, MAINTAIN re-granted to
// the owner of screening_ledger_event/screening_ledger_snapshot was
// invisible to CheckProvisioningState -- only requiredDDLOwnedTables
// (the anchor and tombstone) was enumerated. Reproduced on a TEMPLATE
// clone of the shipped (already-fixed) baseline by re-granting MAINTAIN
// to simulate the pre-D174 gap on the two new relations, then confirming
// the positive control D179 requires: the same assertion on the two
// original relations is unregressed.
func TestD174MaintainAssertionRangesOverAllFourRelations(t *testing.T) {
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
		t.Fatalf("baseline CheckProvisioningState: %v", err)
	}
	if !baseline.Provisioned {
		t.Fatalf("test precondition failed: the clone is not provisioned before any MAINTAIN tampering (Reason=%q)", baseline.Reason)
	}

	superuserConn, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuserConn.Close(context.Background())

	// Simulate the pre-D174 gap: grant MAINTAIN back to the owner
	// (owl_migrator) on the two D166-added relations -- the same
	// self-re-grant shape D51's own test (TestProvisioningStateDetects
	// MaintainRegrant) uses for the original two, applied one round
	// later to the two relations D174 fixes.
	for _, table := range []string{"screening_ledger_event", "screening_ledger_snapshot"} {
		if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`GRANT MAINTAIN ON TABLE %s TO owl_migrator`, table)); err != nil {
			t.Fatalf("re-grant MAINTAIN on %s: %v", table, err)
		}
	}

	afterRegrant, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState after re-grant: %v", err)
	}
	if afterRegrant.Provisioned {
		t.Fatal("ADR-0007 Addendum 22 D174: CheckProvisioningState reported Provisioned=true with MAINTAIN re-granted to owl_migrator on screening_ledger_event/screening_ledger_snapshot -- the population must range over all four protected relations, not requiredDDLOwnedTables")
	}
	if !strings.Contains(afterRegrant.Reason, "MAINTAIN") {
		t.Fatalf("expected a reason naming MAINTAIN, got: %q", afterRegrant.Reason)
	}
	if !strings.Contains(afterRegrant.Reason, "screening_ledger_event") && !strings.Contains(afterRegrant.Reason, "screening_ledger_snapshot") {
		t.Fatalf("expected the reason to name one of the two D166-added relations, got: %q", afterRegrant.Reason)
	}

	for _, table := range []string{"screening_ledger_event", "screening_ledger_snapshot"} {
		if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`REVOKE MAINTAIN ON TABLE %s FROM owl_migrator, PUBLIC`, table)); err != nil {
			t.Fatalf("re-revoke MAINTAIN on %s: %v", table, err)
		}
	}

	// The control that proves the mechanism is present rather than
	// absent (D179 test 1's own requirement): the SAME assertion on the
	// two ORIGINAL relations must still catch a self-re-grant, exactly
	// as D51/D60 shipped it.
	if _, err := superuserConn.Exec(ctx, `GRANT MAINTAIN ON TABLE screening_ledger_anchor, screening_ledger_retention_tombstone TO owl_ledger_ddl`); err != nil {
		t.Fatalf("re-grant MAINTAIN on the original two: %v", err)
	}
	afterOriginalRegrant, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState after original-pair re-grant: %v", err)
	}
	if afterOriginalRegrant.Provisioned {
		t.Fatal("ADR-0007 Addendum 7 D60 / Addendum 22 D174: the original two relations' own MAINTAIN assertion regressed -- expected a named failure with MAINTAIN re-granted to owl_ledger_ddl")
	}
	if !strings.Contains(afterOriginalRegrant.Reason, "MAINTAIN") {
		t.Fatalf("expected a reason naming MAINTAIN, got: %q", afterOriginalRegrant.Reason)
	}

	if _, err := superuserConn.Exec(ctx, `REVOKE MAINTAIN ON TABLE screening_ledger_anchor, screening_ledger_retention_tombstone FROM owl_ledger_ddl, PUBLIC`); err != nil {
		t.Fatalf("final re-revoke: %v", err)
	}
	final, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("final CheckProvisioningState: %v", err)
	}
	if !final.Provisioned {
		t.Fatalf("expected Provisioned=true once every relation's MAINTAIN grant is reverted, got Reason=%q", final.Reason)
	}
}

// TestD174ReindexConcurrentlyCancellationWedge is ADR-0007 Addendum 22
// D179 test 2 (C22-A's consequence): reproduces the wedge itself -- an
// ordinary REINDEX TABLE CONCURRENTLY on screening_ledger_event,
// cancelled by an ordinary statement_timeout, leaves invalid _ccnew
// indexes and wedges every DDL statement for every role including the
// bootstrap superuser -- against a clone with the pre-D174 gap
// (MAINTAIN re-granted), including the recovery property R24's own text
// does not carry (one-at-a-time DROP INDEX refused; a single statement
// naming every leftover succeeds for the owner). It then confirms the
// post-fix shape on the same relation: with the revoke in place, the
// same statement is a clean 42501 and the database stays healthy.
func TestD174ReindexConcurrentlyCancellationWedge(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	cloneMigratorDSN := withDatabase(t, migratorDSN, clone.dbName)

	seedD174EventRows(t, ctx, cloneMigratorDSN, 300000, "d174wedge")

	superuserConn, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuserConn.Close(context.Background())

	// ---- Sub-case A: the pre-D174 gap -- MAINTAIN re-granted to the owner ----
	if _, err := superuserConn.Exec(ctx, `GRANT MAINTAIN ON TABLE screening_ledger_event TO owl_migrator`); err != nil {
		t.Fatalf("re-grant MAINTAIN to simulate the pre-D174 gap: %v", err)
	}

	cancelConn, err := pgx.Connect(ctx, cloneMigratorDSN)
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	if _, err := cancelConn.Exec(ctx, `SET statement_timeout = '40ms'`); err != nil {
		t.Fatalf("set statement_timeout: %v", err)
	}
	_, reindexErr := cancelConn.Exec(ctx, `REINDEX TABLE CONCURRENTLY screening_ledger_event`)
	cancelConn.Close(context.Background())
	if reindexErr == nil {
		t.Fatal("expected REINDEX TABLE CONCURRENTLY to be cancelled by statement_timeout")
	}
	if code := pgErrorCode(reindexErr); code != "57014" {
		t.Fatalf("expected SQLSTATE 57014 (query canceled), got %q: %v", code, reindexErr)
	}

	// Confirm the wedge for BOTH owl_migrator and the bootstrap
	// superuser -- CAP #22's own finding: it is not the runtime writer's
	// problem alone.
	probeConn, err := pgx.Connect(ctx, cloneMigratorDSN)
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	_, wedgeErrMigrator := probeConn.Exec(ctx, `CREATE TABLE zz_d174_probe_mig(x int)`)
	probeConn.Close(context.Background())
	if wedgeErrMigrator == nil {
		t.Fatal("expected the wedge to block an unrelated CREATE TABLE as owl_migrator")
	}
	if code := pgErrorCode(wedgeErrMigrator); code != "P0001" {
		t.Fatalf("expected D50's SQLSTATE P0001, got %q: %v", code, wedgeErrMigrator)
	}
	_, wedgeErrSuper := superuserConn.Exec(ctx, `CREATE TABLE zz_d174_probe_super(x int)`)
	if wedgeErrSuper == nil {
		t.Fatal("expected the wedge to block the bootstrap superuser too -- 'including the bootstrap superuser' is C22-A's own point")
	}

	// The recovery property R24's text does not carry: one-at-a-time
	// DROP INDEX is refused (each intermediate state still diverges),
	// and a single statement naming every leftover succeeds for the
	// owner, with no event-trigger disable and no superuser.
	leftovers := []string{
		"screening_ledger_event_pkey_ccnew",
		"screening_ledger_event_event_sha256_key_ccnew",
		"screening_ledger_event_ledger_id_sequence_key_ccnew",
	}
	recoverConn, err := pgx.Connect(ctx, cloneMigratorDSN)
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	if _, err := recoverConn.Exec(ctx, `DROP INDEX `+leftovers[0]); err == nil {
		t.Fatal("expected dropping one leftover index at a time to be refused (D50)")
	}
	if _, err := recoverConn.Exec(ctx, `DROP INDEX `+strings.Join(leftovers, ", ")); err != nil {
		t.Fatalf("expected a single statement naming every leftover to succeed: %v", err)
	}
	recoverConn.Close(context.Background())
	assertHealthy(t, ctx, clone.superuserDSN, "zz_d174_health_probe_a")

	if _, err := superuserConn.Exec(ctx, `REVOKE MAINTAIN ON TABLE screening_ledger_event FROM owl_migrator, PUBLIC`); err != nil {
		t.Fatalf("revoke MAINTAIN before sub-case B: %v", err)
	}

	// ---- Sub-case B: with D174's revoke applied, no wedge at all -------------
	postFixConn, err := pgx.Connect(ctx, cloneMigratorDSN)
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	defer postFixConn.Close(context.Background())
	_, postFixErr := postFixConn.Exec(ctx, `REINDEX TABLE CONCURRENTLY screening_ledger_event`)
	if postFixErr == nil {
		t.Fatal("expected REINDEX TABLE CONCURRENTLY to fail once MAINTAIN is revoked (ADR-0007 Addendum 22 D174)")
	}
	if code := pgErrorCode(postFixErr); code != "42501" {
		t.Fatalf("expected a clean SQLSTATE 42501 (permission denied) post-fix, got %q: %v", code, postFixErr)
	}
	assertHealthy(t, ctx, clone.superuserDSN, "zz_d174_health_probe_b")
}

// TestD174RouteMatrixOnNewRelations is ADR-0007 Addendum 22 D179 test 3,
// completed by ADR-0007 Addendum 23 D185(1) (C23-D): the abbreviated
// version (event-only, direct/PUBLIC/pg_maintain, no NOINHERIT route)
// left three gaps CAP #23 named -- no snapshot coverage, no NOINHERIT
// route, and no D61 (table-privilege) route for either new relation.
// Table-driven over each of the four relations x {direct third-role
// grant, PUBLIC grant, pg_maintain membership, NOINHERIT member of a
// role that itself holds MAINTAIN directly}, plus a D61 UPDATE-grant
// row for each of the two D166-added relations. Non-vacuity against the
// specific regression this completes -- the pre-Addendum-22 population
// (D60/D61 scoped to requiredDDLOwnedTables, the anchor/tombstone pair
// alone) -- is TestD174D175D176DerivationGuard's sibling proof in this
// same package, plus the mutant comparison this test's own package
// comment/PR description records executed.
func TestD174RouteMatrixOnNewRelations(t *testing.T) {
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

	superuserConn, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuserConn.Close(context.Background())

	requireClean := func(t *testing.T, label string) {
		t.Helper()
		state, err := sink.CheckProvisioningState(ctx)
		if err != nil {
			t.Fatalf("CheckProvisioningState %s: %v", label, err)
		}
		if !state.Provisioned {
			t.Fatalf("%s: expected Provisioned=true, got Reason=%q", label, state.Reason)
		}
	}
	requireClean(t, "r0_clean (precondition)")

	relations := []string{
		"screening_ledger_anchor",
		"screening_ledger_retention_tombstone",
		"screening_ledger_event",
		"screening_ledger_snapshot",
	}

	// direct/public/noinherit routes: table-driven per relation. Each
	// setup returns a revert function so the relation is restored to a
	// clean state before the next case runs.
	type route struct {
		name  string
		setup func(t *testing.T, rel string) (revert func(t *testing.T))
		// wantNamesRelation: the direct/public/noinherit routes are
		// relation-scoped (they grant on exactly one relation), so the
		// reason must name it. pg_maintain is NOT relation-scoped -- a
		// pg_maintain membership confers MAINTAIN on every relation, so
		// maintainHoldersReason's iteration-order fixed point (the FIRST
		// relation in requiredProtectedRelationStates) is what actually
		// gets named, regardless of which relation this loop iteration
		// is nominally targeting. Asserting a specific relation name for
		// that route would be asserting something D174's own text does
		// not claim.
		wantNamesRelation bool
	}
	routes := []route{
		{
			name:              "direct_third_role_grant",
			wantNamesRelation: true,
			setup: func(t *testing.T, rel string) func(t *testing.T) {
				third := uniqueID("zz_d185_direct")
				if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s NOSUPERUSER NOLOGIN`, pgx.Identifier{third}.Sanitize())); err != nil {
					t.Fatalf("create third role: %v", err)
				}
				if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`GRANT MAINTAIN ON TABLE %s TO %s`, pgx.Identifier{rel}.Sanitize(), pgx.Identifier{third}.Sanitize())); err != nil {
					t.Fatalf("GRANT MAINTAIN TO third role: %v", err)
				}
				return func(t *testing.T) {
					// The ACL entry must be revoked before DROP ROLE, or
					// PostgreSQL refuses with "cannot be dropped because
					// some objects depend on it" (2BP01) -- unlike role
					// MEMBERSHIP (pg_auth_members), an ACL grant is a
					// dependency DROP ROLE does not clear on its own.
					if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`REVOKE MAINTAIN ON TABLE %s FROM %s`, pgx.Identifier{rel}.Sanitize(), pgx.Identifier{third}.Sanitize())); err != nil {
						t.Fatalf("revoke third role's MAINTAIN grant: %v", err)
					}
					if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`DROP ROLE %s`, pgx.Identifier{third}.Sanitize())); err != nil {
						t.Fatalf("drop third role: %v", err)
					}
				}
			},
		},
		{
			name:              "public_grant",
			wantNamesRelation: true,
			setup: func(t *testing.T, rel string) func(t *testing.T) {
				if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`GRANT MAINTAIN ON TABLE %s TO PUBLIC`, pgx.Identifier{rel}.Sanitize())); err != nil {
					t.Fatalf("GRANT MAINTAIN TO PUBLIC: %v", err)
				}
				return func(t *testing.T) {
					if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`REVOKE MAINTAIN ON TABLE %s FROM PUBLIC`, pgx.Identifier{rel}.Sanitize())); err != nil {
						t.Fatalf("REVOKE MAINTAIN FROM PUBLIC: %v", err)
					}
				}
			},
		},
		{
			name:              "pg_maintain_membership",
			wantNamesRelation: false,
			setup: func(t *testing.T, rel string) func(t *testing.T) {
				third := uniqueID("zz_d185_pgm")
				if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s NOSUPERUSER NOLOGIN`, pgx.Identifier{third}.Sanitize())); err != nil {
					t.Fatalf("create third role: %v", err)
				}
				if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`GRANT pg_maintain TO %s`, pgx.Identifier{third}.Sanitize())); err != nil {
					t.Fatalf("GRANT pg_maintain: %v", err)
				}
				return func(t *testing.T) {
					if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`DROP ROLE %s`, pgx.Identifier{third}.Sanitize())); err != nil {
						t.Fatalf("drop third role (also revokes its pg_maintain membership): %v", err)
					}
				}
			},
		},
		{
			// A role holding MAINTAIN directly on the target relation,
			// then a second role NOINHERIT member of it -- D73's own
			// MEMBER-side (pg_has_role) enumeration, applied to the two
			// new relations, which is exactly what D174 widened.
			name:              "noinherit_member_of_a_holding_role",
			wantNamesRelation: true,
			setup: func(t *testing.T, rel string) func(t *testing.T) {
				holder := uniqueID("zz_d185_holder")
				member := uniqueID("zz_d185_ni")
				if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s NOSUPERUSER NOLOGIN`, pgx.Identifier{holder}.Sanitize())); err != nil {
					t.Fatalf("create holder role: %v", err)
				}
				if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`GRANT MAINTAIN ON TABLE %s TO %s`, pgx.Identifier{rel}.Sanitize(), pgx.Identifier{holder}.Sanitize())); err != nil {
					t.Fatalf("GRANT MAINTAIN to holder role: %v", err)
				}
				if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s NOSUPERUSER NOLOGIN NOINHERIT`, pgx.Identifier{member}.Sanitize())); err != nil {
					t.Fatalf("create NOINHERIT member role: %v", err)
				}
				if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`GRANT %s TO %s`, pgx.Identifier{holder}.Sanitize(), pgx.Identifier{member}.Sanitize())); err != nil {
					t.Fatalf("GRANT holder TO NOINHERIT member: %v", err)
				}
				return func(t *testing.T) {
					// member's only dependency is its pg_auth_members
					// row (role membership), which DROP ROLE clears on
					// its own. holder's MAINTAIN grant is an ACL
					// dependency and must be revoked first (same 2BP01
					// reason as the direct-grant route above).
					if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`DROP ROLE %s`, pgx.Identifier{member}.Sanitize())); err != nil {
						t.Fatalf("drop NOINHERIT member role: %v", err)
					}
					if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`REVOKE MAINTAIN ON TABLE %s FROM %s`, pgx.Identifier{rel}.Sanitize(), pgx.Identifier{holder}.Sanitize())); err != nil {
						t.Fatalf("revoke holder role's MAINTAIN grant: %v", err)
					}
					if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`DROP ROLE %s`, pgx.Identifier{holder}.Sanitize())); err != nil {
						t.Fatalf("drop holder role: %v", err)
					}
				}
			},
		},
	}

	for _, rel := range relations {
		for _, rt := range routes {
			t.Run(rel+"/"+rt.name, func(t *testing.T) {
				revert := rt.setup(t, rel)
				defer func() {
					revert(t)
					requireClean(t, fmt.Sprintf("%s/%s (after revert)", rel, rt.name))
				}()

				state, err := sink.CheckProvisioningState(ctx)
				if err != nil {
					t.Fatalf("CheckProvisioningState: %v", err)
				}
				if state.Provisioned {
					t.Fatalf("ADR-0007 Addendum 22 D174 / Addendum 23 D185(1): route %q on %s was not caught (Provisioned=true)", rt.name, rel)
				}
				if !strings.Contains(state.Reason, "MAINTAIN") {
					t.Fatalf("expected the reason to name MAINTAIN, got %q", state.Reason)
				}
				if rt.wantNamesRelation && !strings.Contains(state.Reason, rel) {
					t.Fatalf("expected the reason to name %s, got %q", rel, state.Reason)
				}
			})
		}
	}

	// D61 UPDATE-grant route, one row per D166-added relation (D174's
	// own text: "plus a D61 row per new relation, an undeclared UPDATE
	// grant") -- the privilege-holder matrix's own population widen
	// (D175), exercised the same way D61's existing tests exercise
	// SELECT, to confirm the widened population catches an undeclared
	// grant of a DIFFERENT privilege kind too.
	for _, rel := range []string{"screening_ledger_event", "screening_ledger_snapshot"} {
		t.Run(rel+"/d61_undeclared_update_grant", func(t *testing.T) {
			third := uniqueID("zz_d185_d61")
			if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s NOSUPERUSER NOLOGIN`, pgx.Identifier{third}.Sanitize())); err != nil {
				t.Fatalf("create third role: %v", err)
			}
			defer func() {
				if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`REVOKE UPDATE ON %s FROM %s`, pgx.Identifier{rel}.Sanitize(), pgx.Identifier{third}.Sanitize())); err != nil {
					t.Fatalf("revoke third role's UPDATE grant: %v", err)
				}
				if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`DROP ROLE %s`, pgx.Identifier{third}.Sanitize())); err != nil {
					t.Fatalf("drop third role: %v", err)
				}
				requireClean(t, rel+"/d61_undeclared_update_grant (after revert)")
			}()
			if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`GRANT UPDATE ON %s TO %s`, pgx.Identifier{rel}.Sanitize(), pgx.Identifier{third}.Sanitize())); err != nil {
				t.Fatalf("GRANT UPDATE to third role: %v", err)
			}
			state, err := sink.CheckProvisioningState(ctx)
			if err != nil {
				t.Fatalf("CheckProvisioningState: %v", err)
			}
			if state.Provisioned {
				t.Fatalf("ADR-0007 Addendum 22 D175 / Addendum 23 D185(1): an undeclared UPDATE grant on %s was not caught", rel)
			}
			if !strings.Contains(state.Reason, rel) || !strings.Contains(state.Reason, "UPDATE") {
				t.Fatalf("expected the reason to name %s and UPDATE, got %q", rel, state.Reason)
			}
		})
	}

	// The over-tightening positive (D67 test 1): a clean database on
	// which pg_maintain exists and is untouched still returns
	// Provisioned=true -- this addendum must not make the mere
	// existence of the predefined role itself a failure.
	requireClean(t, "final positive control")
}

// TestD175PrivilegeHolderMatrixCoversAllFourRelations is ADR-0007
// Addendum 22 D179 test 4: before this addendum,
// requiredTablePrivilegeHolders had no rows for screening_ledger_event
// or screening_ledger_snapshot, so tablePrivilegeHoldersReason's
// set-equality comparison never ran against them -- an undeclared
// holder went unobserved in one direction, and a missing declared
// holder in the other.
func TestD175PrivilegeHolderMatrixCoversAllFourRelations(t *testing.T) {
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

	superuserConn, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuserConn.Close(context.Background())

	// Direction 1: an undeclared holder is a named failure.
	if _, err := superuserConn.Exec(ctx, `GRANT SELECT ON screening_ledger_event TO owl_app`); err != nil {
		t.Fatalf("grant undeclared SELECT: %v", err)
	}
	extra, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState with an undeclared holder: %v", err)
	}
	if extra.Provisioned {
		t.Fatal("ADR-0007 Addendum 22 D175: an undeclared SELECT holder (owl_app) on screening_ledger_event was not caught")
	}
	if !strings.Contains(extra.Reason, "screening_ledger_event") || !strings.Contains(extra.Reason, "SELECT") {
		t.Fatalf("expected the reason to name screening_ledger_event and SELECT, got %q", extra.Reason)
	}
	if _, err := superuserConn.Exec(ctx, `REVOKE SELECT ON screening_ledger_event FROM owl_app`); err != nil {
		t.Fatalf("revert undeclared SELECT: %v", err)
	}

	// Direction 2: a missing declared holder is equally a named failure
	// -- the direction that catches a provisioning step that silently
	// stopped granting what the design requires.
	if _, err := superuserConn.Exec(ctx, `REVOKE SELECT ON screening_ledger_snapshot FROM owl_ledger_ddl`); err != nil {
		t.Fatalf("revoke declared SELECT: %v", err)
	}
	missing, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState with a missing declared holder: %v", err)
	}
	if missing.Provisioned {
		t.Fatal("ADR-0007 Addendum 22 D175: a missing declared SELECT holder (owl_ledger_ddl) on screening_ledger_snapshot was not caught")
	}
	if !strings.Contains(missing.Reason, "screening_ledger_snapshot") || !strings.Contains(missing.Reason, "SELECT") {
		t.Fatalf("expected the reason to name screening_ledger_snapshot and SELECT, got %q", missing.Reason)
	}
	if _, err := superuserConn.Exec(ctx, `GRANT SELECT ON screening_ledger_snapshot TO owl_ledger_ddl`); err != nil {
		t.Fatalf("restore declared SELECT: %v", err)
	}

	clean, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState after reverting both: %v", err)
	}
	if !clean.Provisioned {
		t.Fatalf("expected Provisioned=true once both tamperings are reverted, got Reason=%q", clean.Reason)
	}
}

// TestD176OwnerAssertionDerivesExpectedValuePerRelation is ADR-0007
// Addendum 22 D179 test 5: D33's owner check now compares every
// protected relation's live owner against its OWN declared value in
// requiredProtectedRelationStates (owl_ledger_ddl for the original two,
// owl_migrator for the two D166 added) rather than a single hardcoded
// owl_ledger_ddl literal, which would false-fail the two new relations
// on every healthy database.
func TestD176OwnerAssertionDerivesExpectedValuePerRelation(t *testing.T) {
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
		t.Fatalf("baseline CheckProvisioningState: %v", err)
	}
	if !baseline.Provisioned {
		t.Fatalf("test precondition failed: the clean migration-bootstrapped clone must be Provisioned=true, got Reason=%q", baseline.Reason)
	}

	superuserConn, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuserConn.Close(context.Background())

	// Move the live owner of screening_ledger_event away from its
	// declared owner (owl_migrator) -- a named failure citing the
	// relation and both owners. D34's event trigger blocks ALTER TABLE
	// against a protected relation unconditionally, including for the
	// bootstrap superuser (measured), so this uses the same
	// withD34TriggersDisabled helper D46's own tests use to construct a
	// state the runtime control would otherwise itself prevent.
	withD34TriggersDisabled(t, ctx, superuserConn, func() {
		if _, err := superuserConn.Exec(ctx, `ALTER TABLE screening_ledger_event OWNER TO owl_ledger_ddl`); err != nil {
			t.Fatalf("ALTER TABLE OWNER TO with D34 disabled: %v", err)
		}
	})
	moved, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState with the owner moved: %v", err)
	}
	if moved.Provisioned {
		t.Fatal("ADR-0007 Addendum 22 D176: screening_ledger_event's owner was moved away from its declared value (owl_migrator) but CheckProvisioningState still reported Provisioned=true")
	}
	if !strings.Contains(moved.Reason, "screening_ledger_event") {
		t.Fatalf("expected the reason to name screening_ledger_event, got %q", moved.Reason)
	}
	if !strings.Contains(moved.Reason, "owl_migrator") || !strings.Contains(moved.Reason, "owl_ledger_ddl") {
		t.Fatalf("expected the reason to name both the expected owner (owl_migrator) and the live owner (owl_ledger_ddl), got %q", moved.Reason)
	}

	withD34TriggersDisabled(t, ctx, superuserConn, func() {
		if _, err := superuserConn.Exec(ctx, `ALTER TABLE screening_ledger_event OWNER TO owl_migrator`); err != nil {
			t.Fatalf("revert ALTER TABLE OWNER TO with D34 disabled: %v", err)
		}
	})
	// Measured side effect of the round trip: PostgreSQL drops an
	// explicit ACL entry for a role once that role briefly becomes the
	// object's owner (the grant is redundant against implicit owner
	// privilege while it lasts), so owl_ledger_ddl's declared SELECT
	// grant (D175) does not survive owning the table even briefly.
	// Restored explicitly so this test's own cleanup does not leave a
	// D175 violation for whichever test runs next.
	if _, err := superuserConn.Exec(ctx, `GRANT SELECT ON screening_ledger_event TO owl_ledger_ddl`); err != nil {
		t.Fatalf("restore owl_ledger_ddl's D175 SELECT grant after the ownership round trip: %v", err)
	}
	clean, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState after reverting ownership: %v", err)
	}
	if !clean.Provisioned {
		t.Fatalf("expected Provisioned=true once ownership is reverted, got Reason=%q", clean.Reason)
	}

	// The SchemaSQL-only path's early exit is genuinely unregressed:
	// checkProvisioningState reaches the owner loop only after the
	// event-trigger checks, so an unprovisioned database still reports
	// the event-trigger reason, not an owner reason -- the assertion
	// that would fail if D176 were implemented as an unconditional
	// owl_ledger_ddl comparison (every relation on this path is owned by
	// owl_migrator, including the two that must NOT be).
	schemaSQLDSN := requireSchemaSQLOnlyDatabaseURL(t)
	schemaSink, err := NewPostgresSink(ctx, schemaSQLDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink (SchemaSQL-only): %v", err)
	}
	defer schemaSink.Close(context.Background())
	schemaState, err := schemaSink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState (SchemaSQL-only): %v", err)
	}
	if schemaState.Provisioned {
		t.Fatal("test precondition failed: the SchemaSQL-only database must not be Provisioned (grant-ddl-ownership never ran against it)")
	}
	if !strings.Contains(schemaState.Reason, "event trigger") {
		t.Fatalf("ADR-0007 Addendum 22 D176: expected the SchemaSQL-only database's unprovisioned reason to still be the event-trigger reason (D176's owner loop must not run first), got %q", schemaState.Reason)
	}
}

// TestD174D175D176DerivationGuard is ADR-0007 Addendum 22 D179 test 6
// (DSN-free): the guard that catches the next registry growth. Every
// member of requiredProtectedRelations has exactly one
// requiredProtectedRelationStates entry; requiredDDLOwnedTables equals
// the derived owl_ledger_ddl subset of that literal; every protected
// relation is named by at least one requiredTablePrivilegeHolders row;
// and requiredProtectedRelationNames() -- what D60/D61 iterate -- is
// exactly the protected-relation set. A fifth protected relation added
// without its own MAINTAIN revoke, holder rows and declared owner fails
// here rather than shipping.
func TestD174D175D176DerivationGuard(t *testing.T) {
	stateIdentityCounts := map[string]int{}
	for _, s := range requiredProtectedRelationStates {
		stateIdentityCounts[s.identity]++
	}
	if len(requiredProtectedRelationStates) != len(requiredProtectedRelations) {
		t.Fatalf("requiredProtectedRelationStates has %d entries, requiredProtectedRelations has %d -- these two declarations must range over exactly the same population", len(requiredProtectedRelationStates), len(requiredProtectedRelations))
	}
	for _, id := range requiredProtectedRelations {
		if stateIdentityCounts[id] != 1 {
			t.Errorf("requiredProtectedRelationStates has %d entries for %q, expected exactly 1", stateIdentityCounts[id], id)
		}
	}

	gotNames := append([]string(nil), requiredProtectedRelationNames()...)
	sort.Strings(gotNames)
	wantNames := make([]string, len(requiredProtectedRelations))
	for i, id := range requiredProtectedRelations {
		wantNames[i] = protectedRelationTableName(id)
	}
	sort.Strings(wantNames)
	if !stringSlicesEqual(gotNames, wantNames) {
		t.Fatalf("requiredProtectedRelationNames() = %v, want %v (this is the population D60's MAINTAIN assertion and D61's privilege matrix iterate)", gotNames, wantNames)
	}

	var wantDDLOwned []string
	for _, s := range requiredProtectedRelationStates {
		if s.relowner == "owl_ledger_ddl" {
			wantDDLOwned = append(wantDDLOwned, protectedRelationTableName(s.identity))
		}
	}
	gotDDLOwned := append([]string(nil), requiredDDLOwnedTables...)
	sort.Strings(gotDDLOwned)
	sort.Strings(wantDDLOwned)
	if !stringSlicesEqual(gotDDLOwned, wantDDLOwned) {
		t.Fatalf("requiredDDLOwnedTables = %v, want the derived owl_ledger_ddl subset %v (ADR-0007 Addendum 22 D176)", gotDDLOwned, wantDDLOwned)
	}

	for _, table := range requiredProtectedRelationNames() {
		found := false
		for _, g := range requiredTablePrivilegeHolders {
			if g.table == table {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("requiredTablePrivilegeHolders has no row for protected relation %q (ADR-0007 Addendum 22 D175/D179 test 6): a protected relation added without its own privilege-holder rows would ship uncovered", table)
		}
	}
}
