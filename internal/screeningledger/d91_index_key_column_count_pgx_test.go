// ADR-0007 Addendum 10 D91/D95 test 5 (N-C, MEDIUM): the declared index
// gains indnkeyatts -- the only declared property that distinguishes
// "PRIMARY KEY (ledger_id, sequence)" from "PRIMARY KEY (ledger_id)
// INCLUDE (sequence)", since pg_index.indkey renders identically for
// both (it lists key AND INCLUDE columns alike) and D80's other four
// properties (indisunique, indisprimary, indkey, no partial/expression)
// all still match the substitution.
package screeningledger

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestDeclaredIndexKeyColumnCountIsVerified reproduces CAP #9 section
// 7.4's exact PRIMARY KEY (ledger_id) INCLUDE (sequence) substitution:
// grant-ddl-ownership and CheckProvisioningState both now refuse it, and
// the consequence (a second anchor for one ledger, previously blocked
// only by the genuine 2-column uniqueness) is proven rejected before the
// substitution and accepted after it, so the test cannot pass by the
// consequence being unreachable either way.
func TestDeclaredIndexKeyColumnCountIsVerified(t *testing.T) {
	ctx := context.Background()
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	cloneMigratorDSN := withDatabase(t, migratorDSN, clone.dbName)
	cloneLedgerAnchorDSN := withDatabase(t, requireAnchorDatabaseURL(t), clone.dbName)

	sink, err := NewPostgresSink(ctx, cloneMigratorDSN, 0)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())

	// One anchor row for a scratch ledger, seeded before the substitution
	// -- only one, so building the substituted (ledger_id)-only unique
	// index does not itself fail on a pre-existing duplicate.
	anchorConn, err := pgx.Connect(ctx, cloneLedgerAnchorDSN)
	if err != nil {
		t.Fatalf("connect as owl_ledger_anchor: %v", err)
	}
	defer anchorConn.Close(context.Background())
	insertAnchorRow := func(seq int64) error {
		_, err := anchorConn.Exec(ctx,
			`INSERT INTO screening_ledger_anchor(ledger_id,sequence,event_sha256,audit_sha256,audit_sequence,policy_sha256,anchor_mac,anchored_at) VALUES ('d91-idx-probe',$1,'a','a',1,'a','a',clock_timestamp())`,
			seq)
		return err
	}
	if err := insertAnchorRow(1); err != nil {
		t.Fatalf("first anchor insert should succeed: %v", err)
	}

	superuser, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())
	// Deliberately does NOT use withD34TriggersDisabled here: that helper
	// re-enables the event triggers as soon as the callback returns,
	// which would immediately trip D50's own live re-validation against
	// the now-stale sec7_protected_relation row (the substituted index's
	// definition differs from what was recorded) -- the same reason
	// d70Chain.restoreGuardTrigger leaves them disabled and lets
	// grant-ddl-ownership's own run re-populate the registry before
	// re-enabling. Left disabled here; grant-ddl-ownership's own DROP
	// EVENT TRIGGER (idempotent) and refusal below never re-enable them.
	mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop DISABLE`)
	mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE`)
	mustExec(t, ctx, superuser, `ALTER TABLE screening_ledger_anchor DROP CONSTRAINT screening_ledger_anchor_pkey`)
	mustExec(t, ctx, superuser, `ALTER TABLE screening_ledger_anchor ADD CONSTRAINT screening_ledger_anchor_pkey PRIMARY KEY (ledger_id) INCLUDE (sequence)`)

	output, runErr := runGrantDDLOwnership(t, d62ScriptPath(t), clone.superuserDSN, clone.dbName)
	if runErr == nil {
		t.Fatalf("ADR-0007 Addendum 10 D91: expected grant-ddl-ownership to refuse the weakened index, got exit 0:\n%s", output)
	}
	if !strings.Contains(output, "D91") && !strings.Contains(output, "indnkeyatts") {
		t.Fatalf("expected the refusal to cite D91/indnkeyatts, got:\n%s", output)
	}

	// Isolates D91's own check from D33's event-trigger-state check and
	// from D50's own set-membership comparison: the registry's recorded
	// index_defs is re-synced to match the substituted index's own live
	// definition (as a blind re-recording by grant-ddl-ownership would
	// do), so pg_get_indexdef's TEXT rendering agrees with what is
	// recorded -- D91's own point is that this is not enough, because
	// indnkeyatts is a property index_defs's text never carries.
	var liveIndexDef string
	if err := superuser.QueryRow(ctx, `SELECT pg_get_indexdef('screening_ledger_anchor_pkey'::regclass)`).Scan(&liveIndexDef); err != nil {
		t.Fatal(err)
	}
	mustExecArgs(t, ctx, superuser, `UPDATE sec7_protected_relation SET index_defs = ARRAY[$1::text] WHERE identity='public.screening_ledger_anchor'`, liveIndexDef)
	mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop ENABLE ALWAYS`)
	mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter ENABLE ALWAYS`)

	provisioning, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState: %v", err)
	}
	if provisioning.Provisioned {
		t.Fatalf("ADR-0007 Addendum 10 D91: CheckProvisioningState reported Provisioned=true despite the weakened anchor index, even with index_defs re-synced to match")
	}
	if !strings.Contains(provisioning.Reason, "D91") {
		t.Fatalf("expected the reason to cite ADR-0007 Addendum 10 D91, got %q", provisioning.Reason)
	}

	// The consequence, confirmed reachable with the weakened index still
	// installed (grant-ddl-ownership refused, so it was never restored):
	// D91's own text -- "the anchor table can now hold at most one row
	// per ledger, so the external commitment section 8's closing
	// condition rests on can no longer be extended." A SECOND, entirely
	// legitimate anchor for the same ledger is rejected under the
	// weakened (ledger_id)-only uniqueness, where the genuine 2-column
	// primary key would have accepted it.
	if err := insertAnchorRow(2); err == nil {
		t.Fatalf("ADR-0007 Addendum 10 D91: a second, legitimate anchor for the same ledger succeeded under the weakened (ledger_id)-only uniqueness -- expected it to be rejected (proving the weakened index forecloses future anchoring, D91's own stated consequence)")
	}
}

// TestD91AcceptsCleanBaselineAndD80Unregressed is the over-tightening
// positive: both declared relations' genuine indexes are accepted, and
// D65's validity branch / D80's five original properties are unaffected.
func TestD91AcceptsCleanBaselineAndD80Unregressed(t *testing.T) {
	ctx := context.Background()
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	cloneMigratorDSN := withDatabase(t, migratorDSN, clone.dbName)
	sink, err := NewPostgresSink(ctx, cloneMigratorDSN, 0)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())
	provisioning, err := sink.CheckProvisioningState(ctx)
	if err != nil || !provisioning.Provisioned {
		t.Fatalf("expected a clean clone to be Provisioned=true, got %+v err=%v", provisioning, err)
	}
}
