// ADR-0007 Addendum 23 D186 (C23-E, Stage X1a): D176's owner-mismatch
// reason names the actually-applicable remediation, chosen by the
// relation's declared owner. Before this decision, the reason said
// "grant-ddl-ownership has not transferred ownership" for every
// protected relation -- correct for the two owl_ledger_ddl-transferred
// relations, and misdirecting for the two owl_migrator-owned-by-design
// relations (re-running grant-ddl-ownership never transfers those, so
// the named remediation cannot fix the case that names it). D188 item 6
// scopes this to the DDL-free CheckProvisioningState reason text, not
// the grant-ddl-ownership recovery path (a separate mechanism, D79/D90,
// unaffected by this decision).
package screeningledger

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestD186ReasonNamesApplicableRemediationForMigratorOwnedRelation is
// ADR-0007 Addendum 23 D188 item 6, first half: after drift, the
// owl_migrator-declared relation's reason contains "ALTER TABLE
// public.<relation> OWNER TO owl_migrator" and does not contain "has not
// transferred ownership".
func TestD186ReasonNamesApplicableRemediationForMigratorOwnedRelation(t *testing.T) {
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
		t.Fatalf("test precondition failed: the clean clone must be Provisioned=true, got Reason=%q", baseline.Reason)
	}

	superuserConn, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuserConn.Close(context.Background())

	// screening_ledger_event is declared owl_migrator-owned
	// (requiredProtectedRelationStates). Move it away, inside the D56
	// disable window -- D34's event trigger blocks ALTER TABLE against a
	// protected relation unconditionally, including for the bootstrap
	// superuser (measured elsewhere in this suite).
	withD34TriggersDisabled(t, ctx, superuserConn, func() {
		if _, err := superuserConn.Exec(ctx, `ALTER TABLE screening_ledger_event OWNER TO owl_ledger_ddl`); err != nil {
			t.Fatalf("ALTER TABLE OWNER TO with D34 disabled: %v", err)
		}
	})

	drifted, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState with the owner drifted: %v", err)
	}
	if drifted.Provisioned {
		t.Fatal("ADR-0007 Addendum 23 D186: screening_ledger_event's owner was moved away from its declared value but CheckProvisioningState still reported Provisioned=true")
	}
	if !strings.Contains(drifted.Reason, "ALTER TABLE") {
		t.Fatalf("expected the reason to name the ALTER TABLE remediation, got %q", drifted.Reason)
	}
	if !strings.Contains(drifted.Reason, "OWNER TO owl_migrator") {
		t.Fatalf("expected the reason to name the durable fix (OWNER TO owl_migrator), got %q", drifted.Reason)
	}
	if strings.Contains(drifted.Reason, "has not transferred ownership") {
		t.Fatalf("ADR-0007 Addendum 23 D186: the shipped D176 text (naming a remediation that does not apply to an owl_migrator-owned-by-design relation) is still present: %q", drifted.Reason)
	}
	if !strings.Contains(drifted.Reason, "screening_ledger_event") {
		t.Fatalf("expected the reason to name the relation, got %q", drifted.Reason)
	}

	withD34TriggersDisabled(t, ctx, superuserConn, func() {
		if _, err := superuserConn.Exec(ctx, `ALTER TABLE screening_ledger_event OWNER TO owl_migrator`); err != nil {
			t.Fatalf("revert ALTER TABLE OWNER TO with D34 disabled: %v", err)
		}
	})
	// Measured side effect (D174 test's own note): PostgreSQL drops an
	// explicit ACL entry for a role once that role briefly becomes the
	// object's owner, so owl_ledger_ddl's declared SELECT grant (D175)
	// does not survive the round trip and must be restored explicitly.
	if _, err := superuserConn.Exec(ctx, `GRANT SELECT ON screening_ledger_event TO owl_ledger_ddl`); err != nil {
		t.Fatalf("restore owl_ledger_ddl's D175 SELECT grant after the round trip: %v", err)
	}
	clean, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState after reverting: %v", err)
	}
	if !clean.Provisioned {
		t.Fatalf("expected Provisioned=true once ownership is reverted, got Reason=%q", clean.Reason)
	}
}

// TestD186KeepsShippedTextForLedgerDDLOwnedRelation is ADR-0007
// Addendum 23 D188 item 6, second half: "The same drift on an
// owl_ledger_ddl-declared relation keeps D176's text." D186 must not
// change behaviour for the two original protected relations.
func TestD186KeepsShippedTextForLedgerDDLOwnedRelation(t *testing.T) {
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
		t.Fatalf("test precondition failed: the clean clone must be Provisioned=true, got Reason=%q", baseline.Reason)
	}

	superuserConn, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuserConn.Close(context.Background())

	// screening_ledger_anchor is declared owl_ledger_ddl-owned. Move it
	// away, inside the disable window.
	withD34TriggersDisabled(t, ctx, superuserConn, func() {
		if _, err := superuserConn.Exec(ctx, `ALTER TABLE screening_ledger_anchor OWNER TO owl_migrator`); err != nil {
			t.Fatalf("ALTER TABLE OWNER TO with D34 disabled: %v", err)
		}
	})

	drifted, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState with the owner drifted: %v", err)
	}
	if drifted.Provisioned {
		t.Fatal("ADR-0007 Addendum 23 D186 regression check: screening_ledger_anchor's owner was moved away from its declared value but CheckProvisioningState still reported Provisioned=true")
	}
	if !strings.Contains(drifted.Reason, "screening_ledger_anchor") {
		t.Fatalf("expected the reason to name the relation, got %q", drifted.Reason)
	}
	if !strings.Contains(drifted.Reason, "has not transferred ownership") {
		t.Fatalf("ADR-0007 Addendum 23 D186: the owl_ledger_ddl case must keep D176's shipped text, got %q", drifted.Reason)
	}
	if strings.Contains(drifted.Reason, "owned by design") {
		t.Fatalf("ADR-0007 Addendum 23 D186: the owl_migrator-owned-by-design text leaked into the owl_ledger_ddl case, got %q", drifted.Reason)
	}

	withD34TriggersDisabled(t, ctx, superuserConn, func() {
		if _, err := superuserConn.Exec(ctx, `ALTER TABLE screening_ledger_anchor OWNER TO owl_ledger_ddl`); err != nil {
			t.Fatalf("revert ALTER TABLE OWNER TO with D34 disabled: %v", err)
		}
	})
	// Measured side effect (same as the migrator-owned test above):
	// owl_migrator's own declared SELECT grant (D61) becomes redundant
	// with its implicit owner privileges while it briefly owns the
	// relation, and does not survive the round trip either.
	if _, err := superuserConn.Exec(ctx, `GRANT INSERT ON screening_ledger_anchor TO owl_ledger_anchor`); err != nil {
		t.Fatalf("restore owl_ledger_anchor's INSERT grant after the round trip: %v", err)
	}
	if _, err := superuserConn.Exec(ctx, `GRANT SELECT ON screening_ledger_anchor TO owl_migrator`); err != nil {
		t.Fatalf("restore owl_migrator's D61 SELECT grant after the round trip: %v", err)
	}
	clean, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState after reverting: %v", err)
	}
	if !clean.Provisioned {
		t.Fatalf("expected Provisioned=true once ownership is reverted, got Reason=%q", clean.Reason)
	}
}
