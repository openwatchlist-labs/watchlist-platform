// ADR-0007 Addendum 5 D43/D49 test 2 and test 3 (I-A, MEDIUM): the
// population D34/D40/D41 are meaningful over. D41 already refuses every
// copy whose relation OIDs were reassigned (a pg_dump-based restore or
// clone); a `CREATE DATABASE ... TEMPLATE` clone preserves them and stays
// genuinely provisioned. This file proves both directions against real
// Postgres fixtures rather than reasoning about them: the two disposable
// databases scripts/ci/provision_test_roles.sh create-restored-database
// builds (CAP #4 §7.6's two variants, made a permanent CI fixture per
// D49 test 1), and a template clone built fresh by each test run.
package screeningledger

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func requireRestoredDatabaseURL(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OWL_MIGRATOR_RESTORED_DATABASE_URL")
	if dsn == "" {
		t.Skip("OWL_MIGRATOR_RESTORED_DATABASE_URL not set; ADR-0007 Addendum 5 D43/D49 test 2 requires a live Postgres database restored from a plain pg_dump|psql of the primary database (see scripts/ci/provision_test_roles.sh create-restored-database and scripts/ci/run-ci.sh)")
	}
	return dsn
}

func requireClonedDatabaseURL(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OWL_MIGRATOR_CLONED_DATABASE_URL")
	if dsn == "" {
		t.Skip("OWL_MIGRATOR_CLONED_DATABASE_URL not set; ADR-0007 Addendum 5 D43/D49 test 2 requires a live Postgres database cloned via pg_dump --schema-only of the primary database (see scripts/ci/provision_test_roles.sh create-restored-database and scripts/ci/run-ci.sh)")
	}
	return dsn
}

// withDatabase returns dsn with its database path swapped for dbname,
// leaving user/password/host/port untouched -- used to reach a
// template-cloned database with the same owl_migrator credentials the
// primary database's DSN already carries, since roles are cluster-wide.
func withDatabase(t *testing.T, dsn, dbname string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse DSN %q: %v", dsn, err)
	}
	u.Path = "/" + dbname
	return u.String()
}

// TestVerifyAnchoredRefusesRestoredDatabase is D43/D49 test 2's first
// half: a full pg_dump|psql restore carries every registry row (D41's
// identity assertion is the detector), not an empty registry (D41's
// population assertion, tested by the clone case below) -- the two states
// fail for different reasons, and this test asserts the specific one.
func TestVerifyAnchoredRefusesRestoredDatabase(t *testing.T) {
	dsn := requireRestoredDatabaseURL(t)
	ctx := context.Background()

	sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())

	state, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState: %v", err)
	}
	if state.Provisioned {
		t.Fatal("ADR-0007 Addendum 5 D43: CheckProvisioningState reported Provisioned=true against a plain pg_dump|psql restore -- every registry OID in this database is dangling (CAP #4 §7.6 variant 1)")
	}
	if !strings.Contains(state.Reason, "no row whose OID resolves") {
		t.Fatalf("expected D41's identity-mismatch reason (a restore carries the rows, not an empty registry), got: %q", state.Reason)
	}

	store, err := NewStore(t.TempDir(), testKey(), uniqueID("sec7-restored"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(testAppendInput()); err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(store.ledgerID)
	kAnchor := make([]byte, 32)
	for i := range kAnchor {
		kAnchor[i] = byte(i + 11)
	}

	_, err = store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: policy, Purges: sink},
		Anchors:       sink, Provisioning: sink, KAnchor: kAnchor, AllowGenesis: true,
	})
	if err == nil {
		t.Fatal("ADR-0007 Addendum 5 D43: VerifyAnchored succeeded against a pg_dump|psql-restored database")
	}
	if !strings.Contains(err.Error(), "not fully provisioned") {
		t.Fatalf("expected the error to name provisioning incompleteness (ADR-0007 Addendum 3 D33), got: %v", err)
	}
}

// TestVerifyAnchoredRefusesSchemaOnlyClone is D43/D49 test 2's second
// half: a pg_dump --schema-only clone carries no registry rows at all
// (D41's population assertion is the detector) -- the "clone production
// into staging" command CAP #4 found leaves D34/D40 entirely inert while
// every structural indicator (owners, event-trigger evtenabled) reports
// them installed.
func TestVerifyAnchoredRefusesSchemaOnlyClone(t *testing.T) {
	dsn := requireClonedDatabaseURL(t)
	ctx := context.Background()

	sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())

	state, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState: %v", err)
	}
	if state.Provisioned {
		t.Fatal("ADR-0007 Addendum 5 D43: CheckProvisioningState reported Provisioned=true against a pg_dump --schema-only clone -- both registries are empty in this database (CAP #4 §7.6 variant 2)")
	}
	if !strings.Contains(state.Reason, "expected exactly") {
		t.Fatalf("expected D41's population-count reason (a schema-only clone carries no rows, not repointed ones), got: %q", state.Reason)
	}

	// Confirm the finding CAP #4 §7.6 demonstrated live: with the
	// registry empty, D40's second phase never fires (it loops over
	// sec7_protected_relation, which has zero rows), so the table
	// owner really can neuter a protected table's own guard -- this is
	// what makes D41's catch load-bearing rather than cosmetic.
	ledgerDDLDSN := withDatabase(t, requireLedgerDDLDatabaseURL(t), dbNameFromDSN(t, dsn))
	ownerConn, err := pgx.Connect(ctx, ledgerDDLDSN)
	if err != nil {
		t.Fatalf("connect as owl_ledger_ddl to the schema-only clone: %v", err)
	}
	defer ownerConn.Close(context.Background())
	if _, err := ownerConn.Exec(ctx, `DROP TRIGGER screening_ledger_anchor_immutable ON screening_ledger_anchor`); err != nil {
		t.Fatalf("expected the table owner's DROP TRIGGER to succeed on an inert schema-only clone (that is CAP #4 §7.6 variant 2's finding), got: %v", err)
	}

	store, err := NewStore(t.TempDir(), testKey(), uniqueID("sec7-cloned"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(testAppendInput()); err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(store.ledgerID)
	kAnchor := make([]byte, 32)
	for i := range kAnchor {
		kAnchor[i] = byte(i + 13)
	}

	_, err = store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: policy, Purges: sink},
		Anchors:       sink, Provisioning: sink, KAnchor: kAnchor, AllowGenesis: true,
	})
	if err == nil {
		t.Fatal("ADR-0007 Addendum 5 D43: VerifyAnchored succeeded against a pg_dump --schema-only clone")
	}
	if !strings.Contains(err.Error(), "not fully provisioned") {
		t.Fatalf("expected the error to name provisioning incompleteness (ADR-0007 Addendum 3 D33), got: %v", err)
	}
}

// dbNameFromDSN extracts the database name from a DSN produced by
// provision_test_roles.sh -- these are always plain postgresql:// URLs
// with the database as the sole path segment.
func dbNameFromDSN(t *testing.T, dsn string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse DSN %q: %v", dsn, err)
	}
	return strings.TrimPrefix(u.Path, "/")
}

// TestProvisioningStateAcceptsTemplateClone is D43/D49 test 3, D37's
// collateral-damage discipline applied to this addendum: a suite that
// proves only the refusals has not proven the design is safe to install.
// `CREATE DATABASE ... TEMPLATE` preserves relation OIDs (confirmed by
// execution during this addendum's design pass, D43's third transcript),
// so the resulting clone must still read as fully provisioned, and its
// D34/D40 controls must still genuinely enforce.
func TestProvisioningStateAcceptsTemplateClone(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	superuser, err := pgx.Connect(ctx, superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())

	sourceDB := dbNameFromDSN(t, migratorDSN)
	cloneDB := fmt.Sprintf("owl_ci_sec7_tmplclone_%d", time.Now().UnixNano())

	if _, err := superuser.Exec(ctx, fmt.Sprintf(
		`CREATE DATABASE %s TEMPLATE %s`,
		pgx.Identifier{cloneDB}.Sanitize(), pgx.Identifier{sourceDB}.Sanitize(),
	)); err != nil {
		t.Fatalf("CREATE DATABASE ... TEMPLATE: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		c, err := pgx.Connect(bg, superuserDSN)
		if err != nil {
			t.Errorf("drop template clone: connect: %v", err)
			return
		}
		defer c.Close(bg)
		if _, err := c.Exec(bg, fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, pgx.Identifier{cloneDB}.Sanitize())); err != nil {
			t.Errorf("drop template clone %s: %v", cloneDB, err)
		}
	})

	cloneMigratorDSN := withDatabase(t, migratorDSN, cloneDB)
	sink, err := NewPostgresSink(ctx, cloneMigratorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink against the template clone: %v", err)
	}
	defer sink.Close(context.Background())

	state, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState against the template clone: %v", err)
	}
	if !state.Provisioned {
		t.Fatalf("ADR-0007 Addendum 5 D43/D45: CheckProvisioningState reported Provisioned=false against a CREATE DATABASE ... TEMPLATE clone, whose relation OIDs are preserved and whose controls are genuinely live (Reason=%q)", state.Reason)
	}

	// The collateral-damage half: the clone's controls must actually be
	// enforcing, not merely pass CheckProvisioningState by coincidence.
	cloneLedgerDDLDSN := withDatabase(t, ledgerDDLDSN, cloneDB)
	owner, err := pgx.Connect(ctx, cloneLedgerDDLDSN)
	if err != nil {
		t.Fatalf("connect as owl_ledger_ddl to the template clone: %v", err)
	}
	defer owner.Close(context.Background())
	_, err = owner.Exec(ctx, `CREATE RULE d43_tmplclone_rule AS ON INSERT TO screening_ledger_anchor DO INSTEAD NOTHING`)
	if err == nil {
		t.Fatal("ADR-0007 Addendum 5 D43: CREATE RULE succeeded against a protected table in a template clone -- the controls must remain live, not merely pass CheckProvisioningState")
	}
	if !strings.Contains(err.Error(), "D40") {
		t.Fatalf("expected D40's rewrite-RULE refusal, got: %v", err)
	}
}
