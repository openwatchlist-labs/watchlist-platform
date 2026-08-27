// ADR-0007 Addendum 7 D61/D67 test 2 (H-C generalized): D39's three
// named-role probes are re-quantified over the live role population
// against requiredTablePrivilegeHolders' declared five-row matrix.
// Covers both directions D61 requires: an extra live holder outside the
// matrix is a named failure, and a declared holder missing its
// privilege is equally a named failure -- the second direction D39
// never had. The column-level routes D39 established (CAP #3 §7.1) are
// proven un-regressed by construction, since this replaces
// has_table_privilege with the same has_column_privilege mechanism for
// the four privilege kinds that support it.
package screeningledger

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestProvisioningStateAcceptsDeclaredPrivilegeMatrix(t *testing.T) {
	sink, ctx := newTestSink(t)
	state, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState: %v", err)
	}
	if !state.Provisioned {
		t.Fatalf("ADR-0007 Addendum 7 D61: the shipped, declared five-row matrix should read Provisioned=true on the primary database, got Reason=%q", state.Reason)
	}
}

func TestProvisioningStateDetectsPrivilegeGrantToUndeclaredRole(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	cases := []struct {
		name     string
		table    string
		priv     string
		wantWord string
		asRole   string // "ledger_ddl" (the owner) grants it
	}{
		// Column-granularity routes (D39's own mechanism), reproduced
		// against an undeclared role rather than a named one.
		{name: "select_to_undeclared_role_column", table: "screening_ledger_anchor", priv: "SELECT", wantWord: "SELECT", asRole: "ledger_ddl"},
		{name: "insert_to_undeclared_role_column", table: "screening_ledger_retention_tombstone", priv: "INSERT", wantWord: "INSERT", asRole: "ledger_ddl"},
		// Table-only routes (no column form): DELETE, TRUNCATE, TRIGGER.
		{name: "delete_to_undeclared_role_table", table: "screening_ledger_anchor", priv: "DELETE", wantWord: "DELETE", asRole: "ledger_ddl"},
		{name: "truncate_to_undeclared_role_table", table: "screening_ledger_anchor", priv: "TRUNCATE", wantWord: "TRUNCATE", asRole: "ledger_ddl"},
		{name: "trigger_to_undeclared_role_table", table: "screening_ledger_retention_tombstone", priv: "TRIGGER", wantWord: "TRIGGER", asRole: "ledger_ddl"},
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

			// owl_app holds nothing on either protected relation
			// (requiredTablePrivilegeHolders' own D17 confirmation) --
			// the undeclared role this grant moves the privilege to.
			ownerConn, err := pgx.Connect(ctx, clone.ledgerDDLDSN)
			if err != nil {
				t.Fatalf("connect as owl_ledger_ddl: %v", err)
			}
			defer ownerConn.Close(context.Background())
			if _, err := ownerConn.Exec(ctx, `GRANT `+c.priv+` ON `+c.table+` TO owl_app`); err != nil {
				t.Fatalf("GRANT %s ON %s TO owl_app: %v", c.priv, c.table, err)
			}

			after, err := sink.CheckProvisioningState(ctx)
			if err != nil {
				t.Fatalf("CheckProvisioningState after grant: %v", err)
			}
			if after.Provisioned {
				t.Fatalf("ADR-0007 Addendum 7 D61: CheckProvisioningState reported Provisioned=true after granting %s on %s to owl_app (undeclared)", c.priv, c.table)
			}
			if !strings.Contains(after.Reason, c.wantWord) || !strings.Contains(after.Reason, "owl_app") {
				t.Fatalf("expected a reason naming %s and owl_app, got: %q", c.wantWord, after.Reason)
			}
		})
	}
}

// TestProvisioningStateDetectsMissingDeclaredPrivilege is D61's second,
// new direction: a privilege the design REQUIRES a declared role to
// hold is equally a named failure when missing -- D39's own probes
// never checked this at all.
func TestProvisioningStateDetectsMissingDeclaredPrivilege(t *testing.T) {
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

	ownerConn, err := pgx.Connect(ctx, clone.ledgerDDLDSN)
	if err != nil {
		t.Fatalf("connect as owl_ledger_ddl: %v", err)
	}
	defer ownerConn.Close(context.Background())
	// requiredTablePrivilegeHolders declares owl_ledger_anchor holds
	// INSERT on screening_ledger_anchor -- revoking it is a declared
	// holder missing its required privilege.
	if _, err := ownerConn.Exec(ctx, `REVOKE INSERT ON screening_ledger_anchor FROM owl_ledger_anchor`); err != nil {
		t.Fatalf("REVOKE INSERT ON screening_ledger_anchor FROM owl_ledger_anchor: %v", err)
	}

	after, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState after revoke: %v", err)
	}
	if after.Provisioned {
		t.Fatal("ADR-0007 Addendum 7 D61: CheckProvisioningState reported Provisioned=true after revoking owl_ledger_anchor's required INSERT privilege")
	}
	if !strings.Contains(after.Reason, "INSERT") || !strings.Contains(after.Reason, "owl_ledger_anchor") {
		t.Fatalf("expected a reason naming INSERT and owl_ledger_anchor, got: %q", after.Reason)
	}
}
