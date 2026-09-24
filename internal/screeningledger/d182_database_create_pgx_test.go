// ADR-0007 Addendum 23 D182 (C23-A(b), Stage X1a): D41 part three gains
// a third fact -- owl_migrator holds no CREATE on the current database --
// beside its two existing owl_ledger_ddl facts. Defence in depth behind
// D181, not the fix for C23-A (D181, out of scope for this stage, is
// what actually closes the bare-name resolution gap); this asserts a
// coincidence a healthy database already has, exactly as D41 part
// three's existing owl_ledger_ddl facts already do one role over
// (postgres.go:449-454's own arrangement).
//
// Two routes give owl_migrator database CREATE: an explicit grant, and
// database ownership (which confers CREATE implicitly and survives a
// REVOKE because the owner can re-grant itself -- R25's class). Both are
// D179 test 3's (D182's own D188 item 3) reproduction scenarios,
// executed here rather than asserted from the design PR's transcript.
package screeningledger

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestD182ExplicitDatabaseCreateGrantToMigratorIsNamedFailure is ADR-0007
// Addendum 23 D188 item 3, first half: "GRANT CREATE ON DATABASE <clone>
// TO owl_migrator is a named failure after, and is accepted today."
func TestD182ExplicitDatabaseCreateGrantToMigratorIsNamedFailure(t *testing.T) {
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

	base, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState before the grant: %v", err)
	}
	if !base.Provisioned {
		t.Fatalf("precondition failed: expected Provisioned=true on a clean clone before this test's tampering, got Reason=%q", base.Reason)
	}

	if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`GRANT CREATE ON DATABASE %s TO owl_migrator`, pgx.Identifier{clone.dbName}.Sanitize())); err != nil {
		t.Fatalf("GRANT CREATE ON DATABASE: %v", err)
	}

	granted, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState with the grant: %v", err)
	}
	if granted.Provisioned {
		t.Fatal("ADR-0007 Addendum 23 D182: owl_migrator holding CREATE on the current database (via an explicit GRANT) was not caught")
	}
	if !strings.Contains(granted.Reason, "owl_migrator") || !strings.Contains(granted.Reason, "CREATE") {
		t.Fatalf("expected the reason to name owl_migrator and CREATE, got %q", granted.Reason)
	}

	if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`REVOKE CREATE ON DATABASE %s FROM owl_migrator`, pgx.Identifier{clone.dbName}.Sanitize())); err != nil {
		t.Fatalf("REVOKE CREATE ON DATABASE: %v", err)
	}
	clean, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState after the revoke: %v", err)
	}
	if !clean.Provisioned {
		t.Fatalf("expected Provisioned=true once the grant is reverted, got Reason=%q", clean.Reason)
	}
}

// TestD182DatabaseOwnedByMigratorIsNamedFailureNamingAlterDatabase is
// ADR-0007 Addendum 23 D188 item 3, second half: "A database *owned* by
// owl_migrator is a named failure whose reason names ALTER DATABASE ...
// OWNER TO." A REVOKE alone does not hold against this route -- the
// owner can re-grant itself CREATE (R25's class, D182's own text) -- so
// the reason must name the durable remediation, not the revoke.
func TestD182DatabaseOwnedByMigratorIsNamedFailureNamingAlterDatabase(t *testing.T) {
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

	base, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState before the ownership change: %v", err)
	}
	if !base.Provisioned {
		t.Fatalf("precondition failed: expected Provisioned=true on a clean clone before this test's tampering, got Reason=%q", base.Reason)
	}

	if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`ALTER DATABASE %s OWNER TO owl_migrator`, pgx.Identifier{clone.dbName}.Sanitize())); err != nil {
		t.Fatalf("ALTER DATABASE ... OWNER TO owl_migrator: %v", err)
	}

	owned, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState with owl_migrator as database owner: %v", err)
	}
	if owned.Provisioned {
		t.Fatal("ADR-0007 Addendum 23 D182: owl_migrator owning the current database (implicit CREATE) was not caught")
	}
	if !strings.Contains(owned.Reason, "ALTER DATABASE") || !strings.Contains(owned.Reason, "OWNER TO") {
		t.Fatalf("expected the reason to name the durable remediation (ALTER DATABASE ... OWNER TO), got %q", owned.Reason)
	}
	if !strings.Contains(owned.Reason, "sec7-database-copies.md") {
		t.Fatalf("expected the reason to point at the runbook section carrying this remediation, got %q", owned.Reason)
	}

	// R25/R91's own residual, measured rather than assumed: unlike table
	// ownership, PostgreSQL database CREATE is NOT implicitly held by
	// the owner -- a REVOKE genuinely clears has_database_privilege, and
	// D182's check (which reads exactly that fact) reports Provisioned=
	// true right after it, even though owl_migrator is still the owner
	// (confirmed empirically: `has_database_privilege` returns false and
	// `CREATE SCHEMA` fails with "permission denied for database"
	// immediately after this REVOKE). This is exactly the point-in-time
	// residual R25/R91 describe -- the REVOKE is not a security boundary
	// because, as owner, owl_migrator can always GRANT the privilege
	// back to itself (an owner may always GRANT on an object it owns,
	// regardless of whether it currently holds the privilege -- measured
	// below), and only the *next* CheckProvisioningState notices.
	if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`REVOKE CREATE ON DATABASE %s FROM owl_migrator`, pgx.Identifier{clone.dbName}.Sanitize())); err != nil {
		t.Fatalf("REVOKE CREATE ON DATABASE (owner route): %v", err)
	}
	afterRevoke, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState after REVOKE alone: %v", err)
	}
	if !afterRevoke.Provisioned {
		t.Fatalf("R25/R91's own point did not reproduce: expected Provisioned=true immediately after the bare REVOKE (a database owner's CREATE, unlike a table owner's implicit privileges, IS cleared by REVOKE -- the residual is that the owner can re-grant it, not that the REVOKE has no effect), got Reason=%q", afterRevoke.Reason)
	}

	// The owner re-grants itself -- as owner, it may GRANT on the
	// database it owns even without currently holding CREATE itself.
	// This is the capability D182's runbook remediation exists to
	// remove durably (by moving ownership), which a REVOKE alone cannot.
	if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`SET ROLE owl_migrator; GRANT CREATE ON DATABASE %s TO owl_migrator; RESET ROLE`, pgx.Identifier{clone.dbName}.Sanitize())); err != nil {
		t.Fatalf("owl_migrator re-grants itself CREATE as owner: %v", err)
	}
	reGranted, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState after the owner re-grants itself: %v", err)
	}
	if reGranted.Provisioned {
		t.Fatal("ADR-0007 Addendum 23 D182 / R25: expected Provisioned=false again once owl_migrator, as owner, re-granted itself CREATE -- the REVOKE was not a durable fix")
	}

	// The durable fix: move ownership away. The explicit self-grant does
	// not evaporate on its own when ownership moves (it is a separate
	// ACL entry), so it is revoked too -- otherwise this test's own
	// "clean" assertion below would fail for a reason unrelated to
	// ownership, which is not what this test is proving.
	if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`ALTER DATABASE %s OWNER TO owl_ci`, pgx.Identifier{clone.dbName}.Sanitize())); err != nil {
		t.Fatalf("ALTER DATABASE ... OWNER TO owl_ci (revert): %v", err)
	}
	if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`REVOKE CREATE ON DATABASE %s FROM owl_migrator`, pgx.Identifier{clone.dbName}.Sanitize())); err != nil {
		t.Fatalf("REVOKE CREATE ON DATABASE (final cleanup of the self-grant): %v", err)
	}
	clean, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState after reverting ownership: %v", err)
	}
	if !clean.Provisioned {
		t.Fatalf("expected Provisioned=true once ownership is moved off owl_migrator, got Reason=%q", clean.Reason)
	}
}

// TestD182FixturesKeepTheirVerdicts is ADR-0007 Addendum 23 D188 item 3's
// third clause: "The CI primary and every fixture keep their verdicts
// (the M2 matrix above)." owl_ci_schemasql_only is OWNER owl_migrator
// (provision_test_roles.sh create-schemasql-only-database), so
// owl_migrator holds database CREATE there today -- exactly the state
// D182 targets. It must still report the event-trigger reason
// unchanged, because grant-ddl-ownership never ran against it and
// checkProvisioningState's event-trigger check returns before D41 part
// three is ever reached (postgres.go's own ordering, confirmed by
// reading checkProvisioningState top to bottom).
func TestD182FixturesKeepTheirVerdicts(t *testing.T) {
	dsn := requireSchemaSQLOnlyDatabaseURL(t)
	ctx := context.Background()

	sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to confirm the precondition: %v", err)
	}
	defer conn.Close(context.Background())
	var migratorCreate bool
	if err := conn.QueryRow(ctx, `SELECT has_database_privilege('owl_migrator', current_database(), 'CREATE')`).Scan(&migratorCreate); err != nil {
		t.Fatalf("checking owl_migrator database CREATE on the fixture: %v", err)
	}
	if !migratorCreate {
		t.Fatal("test construction bug: owl_ci_schemasql_only must be OWNER owl_migrator (provision_test_roles.sh create-schemasql-only-database) -- this test's whole point is that D182's route is already open on this fixture")
	}

	state, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState on owl_ci_schemasql_only: %v", err)
	}
	if state.Provisioned {
		t.Fatal("expected owl_ci_schemasql_only to remain unprovisioned (no grant-ddl-ownership has run against it)")
	}
	if !strings.Contains(state.Reason, "DDL event trigger") {
		t.Fatalf("expected the unchanged event-trigger reason (D182 must not be reached before it), got %q", state.Reason)
	}
	if strings.Contains(state.Reason, "CREATE on the current database") {
		t.Fatalf("D182's reason fired on owl_ci_schemasql_only ahead of the event-trigger check -- checkProvisioningState's ordering has changed, got %q", state.Reason)
	}
}
