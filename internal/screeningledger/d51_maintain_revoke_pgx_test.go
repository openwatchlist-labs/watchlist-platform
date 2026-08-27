// ADR-0007 Addendum 6 D51/D58 test 3 (J-A defence in depth): the
// MAINTAIN privilege is removed from owl_ledger_ddl at its source
// (grant-ddl-ownership's REVOKE), and CheckProvisioningState asserts
// the negative fact -- but the owner can re-grant MAINTAIN to itself
// (GRANT reports objid=NULL, so D34 never sees it, R25), so D51 is an
// accident boundary, not a security boundary. All three halves D58
// requires: the pre-D51 gap this addendum closes, the revoke's clean
// permission error (not a wedge), and the self-re-grant's specifically
// named provisioning failure.
package screeningledger

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// preD51ProvisioningState reconstructs ADR-0007 Addendum 5's shipped
// checkProvisioningState sequence, calling the same private helpers and
// literal declarations the real implementation uses for every fact
// except D51's MAINTAIN block, which is omitted -- so this is a
// faithful reconstruction of "what the check that shipped before this
// addendum would have concluded," not an approximation, per D42/D47's
// convention: proving only the post-fix refusal cannot distinguish a
// working fix from a test that never exercised the gap.
func preD51ProvisioningState(t *testing.T, ctx context.Context, p *PostgresSink) ProvisioningState {
	t.Helper()
	for _, name := range requiredEventTriggers {
		var enabled string
		if err := p.conn.QueryRow(ctx, `SELECT evtenabled FROM pg_event_trigger WHERE evtname=$1`, name).Scan(&enabled); err != nil || enabled != "A" {
			return ProvisioningState{Reason: "event trigger " + name + " not installed/enabled"}
		}
	}
	for _, table := range requiredDDLOwnedTables {
		owner, err := p.SchemaObjectOwner(ctx, table)
		if err != nil || owner != "owl_ledger_ddl" {
			return ProvisioningState{Reason: table + " not owned by owl_ledger_ddl"}
		}
	}
	for _, fn := range requiredDefinerFunctions {
		signature := fn.name + "(" + fn.identityArgs + ")"
		var definer bool
		var owner string
		if err := p.conn.QueryRow(ctx, `SELECT prosecdef, pg_get_userbyid(proowner) FROM pg_proc WHERE oid = $1::regprocedure`, signature).Scan(&definer, &owner); err != nil || !definer || owner != "owl_ledger_ddl" {
			return ProvisioningState{Reason: signature + " not definer/owned"}
		}
	}
	migratorMustNotHave := []struct{ table, priv string }{
		{"screening_ledger_retention_tombstone", "INSERT"},
		{"screening_ledger_anchor", "INSERT"},
	}
	for _, check := range migratorMustNotHave {
		has, err := p.anyColumnPrivilege(ctx, "owl_migrator", check.table, check.priv)
		if err != nil || has {
			return ProvisioningState{Reason: "owl_migrator holds " + check.priv + " on " + check.table}
		}
	}
	anchorWriterCanSelect, err := p.anyColumnPrivilege(ctx, "owl_ledger_anchor", "screening_ledger_anchor", "SELECT")
	if err != nil || anchorWriterCanSelect {
		return ProvisioningState{Reason: "owl_ledger_anchor can SELECT"}
	}
	// ADR-0007 Addendum 6 D51: deliberately does NOT check MAINTAIN --
	// this omission is the gap this addendum closes.
	if reason, err := p.protectedObjectIdentityReason(ctx); err != nil || reason != "" {
		return ProvisioningState{Reason: reason}
	}
	if reason, err := p.protectedRelationIdentityReason(ctx); err != nil || reason != "" {
		return ProvisioningState{Reason: reason}
	}
	if reason, err := p.protectedRelationStateReason(ctx); err != nil || reason != "" {
		return ProvisioningState{Reason: reason}
	}
	var ddlHasSchemaCreate, ddlHasDatabaseCreate bool
	if err := p.conn.QueryRow(ctx, `SELECT has_schema_privilege('owl_ledger_ddl', 'public', 'CREATE')`).Scan(&ddlHasSchemaCreate); err != nil || ddlHasSchemaCreate {
		return ProvisioningState{Reason: "owl_ledger_ddl has CREATE on schema public"}
	}
	if err := p.conn.QueryRow(ctx, `SELECT has_database_privilege('owl_ledger_ddl', current_database(), 'CREATE')`).Scan(&ddlHasDatabaseCreate); err != nil || ddlHasDatabaseCreate {
		return ProvisioningState{Reason: "owl_ledger_ddl has CREATE on the current database"}
	}
	return ProvisioningState{Provisioned: true}
}

func TestProvisioningStateDetectsMaintainRegrant(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	cloneMigratorDSN := withDatabase(t, migratorDSN, clone.dbName)
	cloneLedgerDDLDSN := withDatabase(t, ledgerDDLDSN, clone.dbName)

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

	// Self-re-grant, as owl_ledger_ddl itself -- R25's exact residual,
	// confirmed by execution during this addendum's design pass: an
	// owner can GRANT a privilege on its own table back to itself, and
	// GRANT reports objid=NULL to the event trigger system, so D34
	// never sees it.
	ownerConn, err := pgx.Connect(ctx, cloneLedgerDDLDSN)
	if err != nil {
		t.Fatalf("connect as owl_ledger_ddl: %v", err)
	}
	if _, err := ownerConn.Exec(ctx, `GRANT MAINTAIN ON TABLE screening_ledger_anchor, screening_ledger_retention_tombstone TO owl_ledger_ddl`); err != nil {
		t.Fatalf("self-re-grant MAINTAIN as owl_ledger_ddl: %v", err)
	}
	ownerConn.Close(context.Background())

	// Half 1: "CheckProvisioningState returns Provisioned=true today
	// with MAINTAIN held" -- the pre-D51 reconstruction, which checks
	// every fact the shipped code asserted before this addendum and
	// nothing about MAINTAIN, must still read this exact state as fully
	// provisioned. That is the gap D51 closes, reproduced live rather
	// than asserted from the ADR's transcript.
	pre := preD51ProvisioningState(t, ctx, sink)
	if !pre.Provisioned {
		t.Fatalf("ADR-0007 Addendum 6 D51: the pre-D51 reconstruction should still read Provisioned=true with a self-re-granted MAINTAIN privilege -- that is the gap this addendum closes (Reason=%q)", pre.Reason)
	}

	// Half 3: the shipped, current CheckProvisioningState detects the
	// same state and names it specifically -- not a generic refusal.
	afterRegrant, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState after self-re-grant: %v", err)
	}
	if afterRegrant.Provisioned {
		t.Fatal("ADR-0007 Addendum 6 D51: CheckProvisioningState reported Provisioned=true with a self-re-granted MAINTAIN privilege held by owl_ledger_ddl")
	}
	if !strings.Contains(afterRegrant.Reason, "MAINTAIN") {
		t.Fatalf("expected a reason naming MAINTAIN specifically, got: %q", afterRegrant.Reason)
	}

	// Half 2: the revoke itself. REINDEX ... CONCURRENTLY as
	// owl_ledger_ddl now fails with a clean permission error (42501),
	// not a wedge -- confirmed by an unrelated CREATE TABLE succeeding
	// immediately after.
	superuserConn, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuserConn.Close(context.Background())
	if _, err := superuserConn.Exec(ctx, `REVOKE MAINTAIN ON TABLE screening_ledger_anchor, screening_ledger_retention_tombstone FROM owl_ledger_ddl`); err != nil {
		t.Fatalf("REVOKE MAINTAIN: %v", err)
	}

	reindexConn, err := pgx.Connect(ctx, cloneLedgerDDLDSN)
	if err != nil {
		t.Fatalf("connect as owl_ledger_ddl: %v", err)
	}
	defer reindexConn.Close(context.Background())
	_, reindexErr := reindexConn.Exec(ctx, `REINDEX INDEX CONCURRENTLY screening_ledger_anchor_pkey`)
	if reindexErr == nil {
		t.Fatal("ADR-0007 Addendum 6 D51: REINDEX INDEX CONCURRENTLY succeeded as owl_ledger_ddl after MAINTAIN was revoked")
	}
	var pgErr *pgconn.PgError
	if !errors.As(reindexErr, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("expected SQLSTATE 42501 (permission denied), got %q: %v", pgErrorCode(reindexErr), reindexErr)
	}
	assertHealthy(t, ctx, clone.superuserDSN, "zz_d51_health_probe")

	// The revoke did not over-reach: ALTER TABLE is still refused
	// separately by D34, not by this privilege.
	_, alterErr := reindexConn.Exec(ctx, `ALTER TABLE screening_ledger_anchor ADD COLUMN zz_d51_probe int`)
	if alterErr == nil {
		t.Fatal("ADR-0007 Addendum 6 D51: ALTER TABLE ADD COLUMN succeeded as owl_ledger_ddl -- D34's protection must be independent of the MAINTAIN revoke")
	}
	if code := pgErrorCode(alterErr); code != "P0001" {
		t.Fatalf("expected D34's SQLSTATE P0001, got %q: %v", code, alterErr)
	}

	final, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("final CheckProvisioningState: %v", err)
	}
	if !final.Provisioned {
		t.Fatalf("expected Provisioned=true once the REVOKE restores the shipped state, got Reason=%q", final.Reason)
	}
}
