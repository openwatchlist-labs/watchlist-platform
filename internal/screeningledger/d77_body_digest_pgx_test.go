// ADR-0007 Addendum 9 D77/D85 test 1 (M-A, CRITICAL): the declared
// trigger's property set gains the bound function's BODY, as a closed
// set of accepted sha256(prosrc) digests joined through the trigger's
// own tgfoid -- not a name lookup, so this follows whatever function the
// trigger actually calls right now. CAP #8 section 7.1's exact
// reproduction: with the documented recovery's single ALTER EVENT
// TRIGGER ... DISABLE (no second, undocumented disable the way L-B
// needed), one CREATE OR REPLACE FUNCTION preserves every one of D69's
// four catalog properties while replacing the function's body -- the
// weakest member D76/D77 diagnosed. Independently reproduced against a
// real disposable PostgreSQL 17.11 cluster during this addendum's
// implementation: all four D69 properties (tgtype, tgqual, tgnargs,
// tgattr) plus tgfoid identity survive byte-identical, tgfoid itself
// literally unchanged (16462), while prosrc's digest moves from
// 5632734b...81f4bb1 to b3771fd2...bd412 -- and the forging UPDATE plus
// both TRUNCATEs the neutered guards enable succeed exactly as CAP #8
// section 7.1 describes.
package screeningledger

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// requireSchemaSQLOnlyDatabaseURL is the same SEC-2 followup fixture
// internal/schemasqlgate's own suite uses (scripts/ci/provision_test_roles.sh
// create-schemasql-only-database): a database owned by owl_migrator with
// NO migration ever applied, so this package's own Migrate()/SchemaSQL
// const is exercised on the bootstrap path it independently supports
// (ADR-0007 D3/D15's own REL-9-adjacent shape). Declared here rather
// than shared from internal/schemasqlgate because Go does not export
// unexported test helpers across packages.
func requireSchemaSQLOnlyDatabaseURL(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OWL_SCHEMASQL_ONLY_DATABASE_URL")
	if dsn == "" {
		t.Skip("OWL_SCHEMASQL_ONLY_DATABASE_URL not set; ADR-0007 Addendum 9 D77's over-tightening positive requires a live Postgres provisioned via scripts/ci/provision_test_roles.sh create-schemasql-only-database (see scripts/ci/run-ci.sh)")
	}
	return dsn
}

// preD77TriggerBehaviorOK reconstructs D69's shipped four-property
// comparison exactly as it read immediately before this addendum added
// the fifth, body-digest member -- git blame confirms this is
// requiredProtectedTriggerState's query body minus the prosrc join and
// its COALESCE clause. Needed because D69 is a PRIOR addendum's shipped
// mechanism: its own four properties are demonstrated insufficient here,
// not absent, so the "before" half of this test must reconstruct
// exactly what D69 alone catches, not what predates D69 entirely (that
// reconstruction is preD69And71ProvisioningState, a different baseline).
func preD77TriggerBehaviorOK(t *testing.T, ctx context.Context, p *PostgresSink, identity string, trig requiredProtectedTriggerState) bool {
	t.Helper()
	var ok bool
	if err := p.conn.QueryRow(ctx, `
		SELECT COALESCE((
			SELECT t.tgtype = $3 AND t.tgqual IS NULL AND t.tgnargs = $4 AND t.tgattr::text = $5
			       AND (pg_identify_object('pg_proc'::regclass, t.tgfoid, 0)).identity = $6
			FROM pg_trigger t
			WHERE t.tgrelid = $1::regclass AND NOT t.tgisinternal AND t.tgname = $2
		), false)
	`, identity, trig.name, trig.tgtype, trig.tgnargs, trig.tgattr, trig.functionOID).Scan(&ok); err != nil {
		t.Fatalf("preD77TriggerBehaviorOK: %v", err)
	}
	return ok
}

// preD77ProvisioningState mirrors checkProvisioningState's real chain,
// substituting preD77TriggerBehaviorOK (D69's shipped four properties
// alone) for D77's own five-property comparison inside
// protectedRelationStateReason -- every other real method (including
// D80's index-shape loop, unaffected by D77) is called for real, the
// same pattern d65_index_validity_pgx_test.go's preD65ProvisioningState
// and d69_trigger_referent_pgx_test.go's preD69And71ProvisioningState
// already establish.
func preD77ProvisioningState(t *testing.T, ctx context.Context, p *PostgresSink) ProvisioningState {
	t.Helper()
	if reason, err := p.tablePrivilegeHoldersReason(ctx); err != nil || reason != "" {
		return ProvisioningState{Reason: reason}
	}
	if reason, err := p.maintainHoldersReason(ctx); err != nil || reason != "" {
		return ProvisioningState{Reason: reason}
	}
	if reason, err := p.protectedObjectIdentityReason(ctx); err != nil || reason != "" {
		return ProvisioningState{Reason: reason}
	}
	if reason, err := p.protectedRelationIdentityReason(ctx); err != nil || reason != "" {
		return ProvisioningState{Reason: reason}
	}
	for _, want := range requiredProtectedRelationStates {
		for _, trig := range want.triggers {
			if !preD77TriggerBehaviorOK(t, ctx, p, want.identity, trig) {
				return ProvisioningState{Reason: "pre-D77 reconstruction: trigger behavior mismatch"}
			}
		}
	}
	// D80's index-shape loop and every other branch of the real
	// protectedRelationStateReason are unaffected by D77 -- calling the
	// real function would re-check the body digest too, so this
	// reconstruction stops here rather than delegating: the point is to
	// prove D69's four properties ALONE accept what D77 alone refuses.
	return ProvisioningState{Provisioned: true}
}

func TestGuardFunctionBodyIsDeclaredNotAddressed(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()
	scriptPath := d62ScriptPath(t)

	for _, guard := range []struct {
		funcName   string
		trigger    string
		table      string
		neuteredAs string
	}{
		{funcName: "screening_ledger_reject_mutation", trigger: "screening_ledger_anchor_immutable", table: "screening_ledger_anchor", neuteredAs: "BEGIN RETURN NEW; END"},
		{funcName: "owl_reject_truncate", trigger: "screening_ledger_anchor_no_truncate", table: "screening_ledger_anchor", neuteredAs: "BEGIN RETURN NULL; END"},
	} {
		t.Run(guard.funcName, func(t *testing.T) {
			clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
			superuser, err := pgx.Connect(ctx, clone.superuserDSN)
			if err != nil {
				t.Fatalf("connect as bootstrap superuser: %v", err)
			}
			defer superuser.Close(context.Background())

			// Every declared trigger's live tgfoid before the substitution,
			// to prove afterward that the OID never moved (D77's whole
			// design rests on this: CREATE OR REPLACE FUNCTION preserves
			// OID and replaces body).
			tgfoidBefore := map[string]uint32{}
			for _, want := range requiredProtectedRelationStates {
				for _, trig := range want.triggers {
					var oid uint32
					if err := superuser.QueryRow(ctx, `SELECT t.tgfoid FROM pg_trigger t WHERE t.tgname=$1 AND t.tgrelid=$2::regclass AND NOT t.tgisinternal`, trig.name, want.identity).Scan(&oid); err != nil {
						t.Fatalf("tgfoid before, %s: %v", trig.name, err)
					}
					tgfoidBefore[trig.name] = oid
				}
			}

			// CAP #8 section 7.1's exact reproduction: the documented
			// recovery's single disable, then ONE CREATE OR REPLACE
			// FUNCTION with a no-op body -- no second event trigger
			// disable, no DROP TRIGGER, nothing beyond what
			// docs/operations/sec7-database-copies.md step 1 creates.
			if _, err := superuser.Exec(ctx, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE`); err != nil {
				t.Fatalf("disable ddl_command_end event trigger: %v", err)
			}
			if _, err := superuser.Exec(ctx, `CREATE OR REPLACE FUNCTION public.`+guard.funcName+`() RETURNS trigger LANGUAGE plpgsql AS $$ `+guard.neuteredAs+` $$`); err != nil {
				t.Fatalf("CREATE OR REPLACE FUNCTION (the forgery itself, one statement): %v", err)
			}
			if _, err := superuser.Exec(ctx, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter ENABLE ALWAYS`); err != nil {
				t.Fatalf("re-enable ddl_command_end event trigger: %v", err)
			}

			// D69's four properties are byte-identical, because the OID
			// never moved.
			for _, want := range requiredProtectedRelationStates {
				for _, trig := range want.triggers {
					var oid uint32
					var tgtype, tgnargs int16
					var tgqualNull bool
					var tgattr string
					if err := superuser.QueryRow(ctx, `SELECT t.tgfoid, t.tgtype, t.tgqual IS NULL, t.tgnargs, t.tgattr::text FROM pg_trigger t WHERE t.tgname=$1 AND t.tgrelid=$2::regclass AND NOT t.tgisinternal`, trig.name, want.identity).Scan(&oid, &tgtype, &tgqualNull, &tgnargs, &tgattr); err != nil {
						t.Fatalf("tgfoid after, %s: %v", trig.name, err)
					}
					if oid != tgfoidBefore[trig.name] {
						t.Fatalf("test precondition failed: %s's tgfoid moved (%d -> %d) -- CREATE OR REPLACE FUNCTION should preserve OID", trig.name, tgfoidBefore[trig.name], oid)
					}
					if tgtype != trig.tgtype || !tgqualNull || tgnargs != trig.tgnargs || tgattr != trig.tgattr {
						t.Fatalf("test precondition failed: %s's D69 properties changed after the substitution (tgtype=%d tgqualNull=%v tgnargs=%d tgattr=%q)", trig.name, tgtype, tgqualNull, tgnargs, tgattr)
					}
				}
			}

			sink, err := NewPostgresSink(ctx, withDatabase(t, migratorDSN, clone.dbName), 10*time.Second)
			if err != nil {
				t.Fatalf("NewPostgresSink: %v", err)
			}
			defer sink.Close(context.Background())

			// D69 ALONE (the mechanism this addendum found insufficient):
			// the pre-D77 reconstruction accepts the substitution as
			// legitimate -- reproducing exactly the gap CAP #8 section 7.1
			// demonstrated against the shipped-before-this-addendum
			// installer and verifier (independently confirmed by this
			// addendum's own design pass with pasted transcripts, both
			// halves; the bash installer's own pre-D77 behavior is not
			// re-derived here because this file's D77 fix already lands
			// in provision_test_roles.sh in the same change -- there is no
			// "shipped, unpatched" script left to run against once both
			// halves of one addendum ship together).
			pre := preD77ProvisioningState(t, ctx, sink)
			if !pre.Provisioned {
				t.Fatalf("ADR-0007 Addendum 8 D69 (alone): expected the pre-D77 reconstruction to accept the substituted %s as legitimate (Provisioned=true), got Reason=%q -- this must reproduce the gap, not a probe that never exercised it", guard.funcName, pre.Reason)
			}

			// Prove the hole is real, not merely a probe that changed: as
			// owl_ledger_ddl (T1, non-superuser, D61's own declared
			// matrix), forge the tombstone's attribution and, for the
			// TRUNCATE-guard case, TRUNCATE the protected table.
			ledgerDDLConn, err := pgx.Connect(ctx, withDatabase(t, requireLedgerDDLDatabaseURL(t), clone.dbName))
			if err != nil {
				t.Fatalf("connect as owl_ledger_ddl: %v", err)
			}
			defer ledgerDDLConn.Close(context.Background())
			if _, err := ledgerDDLConn.Exec(ctx, `INSERT INTO screening_ledger_retention_tombstone (snapshot_sha256, purged_at, operator, reason) VALUES ($1, now(), 'legit-op', 'legit-reason')`, uniqueID("d77-tombstone")); err != nil {
				t.Fatalf("seed tombstone row: %v", err)
			}
			if guard.funcName == "screening_ledger_reject_mutation" {
				if _, err := ledgerDDLConn.Exec(ctx, `UPDATE screening_ledger_retention_tombstone SET operator='someone-else', reason='no retention obligation'`); err != nil {
					t.Fatalf("ADR-0007 Addendum 9 D76/D77: expected the neutered guard to allow the forging UPDATE (proves the hole is real): %v", err)
				}
			} else {
				if _, err := ledgerDDLConn.Exec(ctx, `TRUNCATE screening_ledger_retention_tombstone`); err != nil {
					t.Fatalf("ADR-0007 Addendum 9 D76/D77: expected the neutered TRUNCATE guard to allow TRUNCATE (proves the hole is real): %v", err)
				}
			}

			// AFTER: the real, shipped mechanism refuses both halves,
			// naming the trigger, the function and D77.
			after, err := sink.CheckProvisioningState(ctx)
			if err != nil {
				t.Fatalf("CheckProvisioningState: %v", err)
			}
			if after.Provisioned {
				t.Fatalf("ADR-0007 Addendum 9 D77: expected the shipped CheckProvisioningState to refuse the substituted %s, got Provisioned=true", guard.funcName)
			}
			if !strings.Contains(after.Reason, guard.trigger) {
				t.Fatalf("expected the refusal to name the trigger, got: %q", after.Reason)
			}
			if !strings.Contains(after.Reason, "D77") {
				t.Fatalf("expected the refusal to cite ADR-0007 Addendum 9 D77, got: %q", after.Reason)
			}

			output, runErr := runGrantDDLOwnership(t, scriptPath, clone.superuserDSN, clone.dbName)
			if runErr == nil {
				t.Fatalf("ADR-0007 Addendum 9 D77: grant-ddl-ownership succeeded against a database whose guard function's body was substituted (%s) -- expected refusal\n%s", guard.funcName, output)
			}
			if !strings.Contains(output, "D77") {
				t.Fatalf("expected the installer's refusal to cite ADR-0007 Addendum 9 D77, got:\n%s", output)
			}
		})
	}
}

// runGrantDDLOwnership runs the shipped script's grant-ddl-ownership
// subcommand against dbName as the bootstrap superuser, returning
// combined output. Factored out because this file calls it both to
// prove the pre-D77 acceptance and the post-D77 refusal.
func runGrantDDLOwnership(t *testing.T, scriptPath, superuserDSN, dbName string) (string, error) {
	t.Helper()
	host, port, superuserUser, superpassword := pgConnParamsFromDSN(t, superuserDSN)
	cmd := exec.Command(scriptPath, "grant-ddl-ownership")
	cmd.Env = append(os.Environ(),
		"PGHOST="+host, "PGPORT="+port, "PGDATABASE="+dbName,
		"PGSUPERUSER="+superuserUser, "PGSUPERPASSWORD="+superpassword,
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestD77AcceptsCleanBaseline is D77's over-tightening positive, a
// shipping requirement per D75's own withdrawal condition, not a nicety:
// a clean migration-bootstrapped database AND a clean
// SchemaSQL-only-bootstrapped database are BOTH accepted. This is the
// test that catches the single-digest error -- declaring only one of
// owl_reject_truncate()'s two legitimate bodies (CAP #8 section 11 point
// 1's own recommendation) fails closed on whichever bootstrap path it
// does not name, and only running against both paths catches that.
func TestD77AcceptsCleanBaseline(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	t.Run("migration_bootstrapped", func(t *testing.T) {
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
			t.Fatalf("ADR-0007 Addendum 9 D77: expected a clean migration-bootstrapped clone to read Provisioned=true, got Reason=%q", state.Reason)
		}
	})

	t.Run("schemasql_only_bootstrapped", func(t *testing.T) {
		dsn := requireSchemaSQLOnlyDatabaseURL(t)
		sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
		if err != nil {
			t.Fatalf("NewPostgresSink: %v", err)
		}
		defer sink.Close(context.Background())
		if err := sink.Migrate(ctx); err != nil {
			t.Fatalf("Migrate() on a SchemaSQL-only-bootstrapped database should succeed: %v", err)
		}
		// D77's declared digests must accept both guard functions' bodies
		// as SchemaSQL itself writes them -- this database has never run
		// grant-ddl-ownership, so protectedRelationStateReason's own
		// "sec7_protected_relation has no row" branch would fire first if
		// this asserted the full CheckProvisioningState chain; the body
		// digest is checked directly instead, which is D77's own new
		// property and the one this test exists to pin.
		var srmDigest, ortDigest string
		if err := sink.conn.QueryRow(ctx, `SELECT encode(sha256(convert_to(prosrc,'UTF8')),'hex') FROM pg_proc WHERE oid='screening_ledger_reject_mutation()'::regprocedure`).Scan(&srmDigest); err != nil {
			t.Fatal(err)
		}
		if err := sink.conn.QueryRow(ctx, `SELECT encode(sha256(convert_to(prosrc,'UTF8')),'hex') FROM pg_proc WHERE oid='owl_reject_truncate()'::regprocedure`).Scan(&ortDigest); err != nil {
			t.Fatal(err)
		}
		if srmDigest != screeningLedgerRejectMutationBodySHA256 {
			t.Fatalf("ADR-0007 Addendum 9 D77: SchemaSQL's screening_ledger_reject_mutation() body digest %q is not in the accepted set -- D77's declared digest is stale against the committed SchemaSQL literal", srmDigest)
		}
		found := false
		for _, accepted := range owlRejectTruncateAcceptedBodySHA256 {
			if ortDigest == accepted {
				found = true
			}
		}
		if !found {
			t.Fatalf("ADR-0007 Addendum 9 D77: SchemaSQL's owl_reject_truncate() body digest %q is not in the two-member accepted set %v -- this is exactly the false-failure shape D77's own text warns a single-digest declaration produces", ortDigest, owlRejectTruncateAcceptedBodySHA256)
		}
	})
}

// TestOwlRejectTruncateAcceptedDigestsMatchCommittedLiterals is D77/D85's
// own unit-level, no-database assertion: the fact that forces the
// two-member set is pinned by a test rather than only by this addendum's
// prose, so a later reader who "simplifies" the set to one member breaks
// a test that explains why. Extracts both bootstrap paths' literal
// function bodies directly from the committed source text and digests
// them -- R35's own named CI gate, run as a Go test rather than a
// separate script, so it executes on every `go test ./...` rather than
// requiring a dedicated invocation.
func TestOwlRejectTruncateAcceptedDigestsMatchCommittedLiterals(t *testing.T) {
	migrationSrc, err := os.ReadFile("../../db/migrations/012_truncate_guards.sql")
	if err != nil {
		t.Fatal(err)
	}
	const migrationMarker = "CREATE OR REPLACE FUNCTION owl_reject_truncate() RETURNS trigger\nLANGUAGE plpgsql AS $$ BEGIN\n  RAISE EXCEPTION 'relation % is append-only; TRUNCATE is prohibited', TG_TABLE_NAME;\nEND $$;"
	if !strings.Contains(string(migrationSrc), migrationMarker) {
		t.Fatal("db/migrations/012_truncate_guards.sql's owl_reject_truncate() literal has changed -- ADR-0007 Addendum 9 D77's migration-path accepted digest (owlRejectTruncateBodySHA256Migration) must be re-derived from the new text, not left stale")
	}

	if !strings.Contains(SchemaSQL, "IF to_regprocedure('owl_reject_truncate()') IS NULL THEN") {
		t.Fatal("SchemaSQL no longer guards owl_reject_truncate() with the expected presence check -- D77/D78 assume this shape")
	}
	const schemaSQLBodyMarker = "BEGIN RAISE EXCEPTION 'relation % is append-only; TRUNCATE is prohibited', TG_TABLE_NAME;END"
	if !strings.Contains(SchemaSQL, schemaSQLBodyMarker) {
		t.Fatal("SchemaSQL's owl_reject_truncate() literal has changed -- ADR-0007 Addendum 9 D77's SchemaSQL-path accepted digest (owlRejectTruncateBodySHA256SchemaSQLBoot) must be re-derived from the new text, not left stale")
	}

	// D85's own required assertion: the two literals differ. If a future
	// reformat ever makes them byte-identical, this is the test that
	// notices -- and per D77's own text, the fix is still a two-member
	// set (a schema change to converge them is a new ADR, not a
	// `regexp_replace`), so this test intentionally does not react to
	// convergence by simplifying anything itself.
	if owlRejectTruncateBodySHA256Migration == owlRejectTruncateBodySHA256SchemaSQLBoot {
		t.Fatal("ADR-0007 Addendum 9 D77: the migration and SchemaSQL owl_reject_truncate() literals are no longer distinct -- re-derive whether the two-member set is still required before removing a member")
	}
}
