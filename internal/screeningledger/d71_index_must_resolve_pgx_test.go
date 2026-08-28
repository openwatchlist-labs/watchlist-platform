// ADR-0007 Addendum 8 D71/D75 test 3 (L-C, HIGH): a declared index name
// must be asserted to resolve to a LIVE object, in both the installer
// and the verifier -- CAP #7 §7.3's exact reproduction: dropping the
// anchor's primary key entirely, which the pre-Addendum-8 mechanism
// accepts vacuously (both index_defs sides become the empty array, and
// D65's validity branch is vacuously true over zero rows), leaving a
// forged duplicate row insertable.
package screeningledger

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestDeclaredIndexMustResolveToALiveObject(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()
	scriptPath := d62ScriptPath(t)

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	superuser, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())

	if _, err := superuser.Exec(ctx, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE`); err != nil {
		t.Fatalf("disable ddl_command_end event trigger: %v", err)
	}
	// CAP #7 §7.3's exact drop -- the primary key, not merely a
	// secondary index.
	if _, err := superuser.Exec(ctx, `ALTER TABLE screening_ledger_anchor DROP CONSTRAINT screening_ledger_anchor_pkey`); err != nil {
		t.Fatalf("drop the anchor's primary key: %v", err)
	}

	var liveIndexCount int
	if err := superuser.QueryRow(ctx, `SELECT count(*) FROM pg_index WHERE indrelid='screening_ledger_anchor'::regclass`).Scan(&liveIndexCount); err != nil {
		t.Fatal(err)
	}
	if liveIndexCount != 0 {
		t.Fatalf("test precondition failed: expected zero live indexes on screening_ledger_anchor after dropping its primary key, got %d", liveIndexCount)
	}

	// The launder, reconstructed directly (bypassing the shipped
	// script's own precondition, which now refuses this exact launder --
	// see below): before ADR-0007 Addendum 8, re-running
	// grant-ddl-ownership over a relation whose declared index no longer
	// exists recorded index_defs = {} as legitimate, because D62(a)'s
	// precondition checked for UNDECLARED extras only, never for a
	// declared name that no longer resolves to anything.
	// preD62RecordProtectedObjectRegistry/preD62RecordProtectedRelationState
	// (d69_trigger_referent_pgx_test.go / d62_launder_refusal_pgx_test.go)
	// are that exact DELETE/INSERT sequence, unchanged by D69/D71 (which
	// added preconditions BEFORE it, not a different recording).
	withD34TriggersDisabled(t, ctx, superuser, func() {
		preD62RecordProtectedObjectRegistry(t, ctx, superuser)
		preD62RecordProtectedRelationState(t, ctx, superuser)
	})

	var recordedIndexDefs []string
	if err := superuser.QueryRow(ctx, `SELECT index_defs FROM sec7_protected_relation WHERE identity='public.screening_ledger_anchor'`).Scan(&recordedIndexDefs); err != nil {
		t.Fatal(err)
	}
	if len(recordedIndexDefs) != 0 {
		t.Fatalf("test precondition failed: expected recorded index_defs to be empty after the launder, got %v", recordedIndexDefs)
	}

	// The forgery itself: a duplicate (ledger_id, sequence) row, refused
	// only by the primary key that is now gone.
	ledgerAnchorConn, err := pgx.Connect(ctx, withDatabase(t, requireAnchorDatabaseURL(t), clone.dbName))
	if err != nil {
		t.Fatalf("connect as owl_ledger_anchor: %v", err)
	}
	defer ledgerAnchorConn.Close(context.Background())
	if _, err := ledgerAnchorConn.Exec(ctx,
		`INSERT INTO screening_ledger_anchor (ledger_id, sequence, event_sha256, audit_sha256, anchor_mac, audit_sequence, policy_sha256)
		 VALUES ('d71-dupe',9,'esha-a','audit-a','mac-a',1,'psha'),('d71-dupe',9,'esha-b','audit-b','mac-b',1,'psha')`,
	); err != nil {
		t.Fatalf("expected the duplicate-row insert to succeed with no primary key (proves the consequence, not merely the check): %v", err)
	}

	sink, err := NewPostgresSink(ctx, withDatabase(t, migratorDSN, clone.dbName), 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())

	pre := preD69And71ProvisioningState(t, ctx, sink)
	if !pre.Provisioned {
		t.Fatalf("ADR-0007 Addendum 8 D71: expected the pre-Addendum-8 reconstruction to accept the missing primary key as legitimate (Provisioned=true), got Reason=%q -- this must reproduce the vacuous-pass gap, not a probe that never exercised it", pre.Reason)
	}

	after, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState: %v", err)
	}
	if after.Provisioned {
		t.Fatal("ADR-0007 Addendum 8 D71: expected CheckProvisioningState to refuse a relation whose declared index does not exist")
	}
	if !strings.Contains(after.Reason, "D71") {
		t.Fatalf("expected the refusal to cite ADR-0007 Addendum 8 D71, got: %q", after.Reason)
	}

	// The installer-side half: grant-ddl-ownership must ALSO now refuse
	// to perform the launder it used to perform silently. Its own
	// idempotent guards skip the ALTER TABLE OWNER TO paths (ownership
	// already owl_ledger_ddl from clone provisioning), which is fine --
	// D71's own precondition runs unconditionally, before those guards
	// would matter, on every invocation.
	host, port, superuserUser, superpassword := pgConnParamsFromDSN(t, clone.superuserDSN)
	cmd := exec.Command(scriptPath, "grant-ddl-ownership")
	cmd.Env = append(cmd.Environ(),
		"PGHOST="+host, "PGPORT="+port, "PGDATABASE="+clone.dbName,
		"PGSUPERUSER="+superuserUser, "PGSUPERPASSWORD="+superpassword,
	)
	output, runErr := cmd.CombinedOutput()
	if runErr == nil {
		t.Fatalf("ADR-0007 Addendum 8 D71: grant-ddl-ownership succeeded against a database whose declared primary-key index does not exist -- expected refusal\n%s", output)
	}
	if !strings.Contains(string(output), "screening_ledger_anchor_pkey") {
		t.Fatalf("expected the refusal to name the missing index, got:\n%s", output)
	}
	if !strings.Contains(string(output), "D71") {
		t.Fatalf("expected the refusal to cite ADR-0007 Addendum 8 D71, got:\n%s", output)
	}
}

// TestD71AcceptsCleanBaseline is the over-tightening positive: both
// protected relations, with their declared indexes present, are
// accepted.
func TestD71AcceptsCleanBaseline(t *testing.T) {
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
		t.Fatalf("expected a clean clone (both declared indexes present) to read Provisioned=true, got Reason=%q", state.Reason)
	}
}
