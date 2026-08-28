// ADR-0007 Addendum 8 D69/D75 test 1 (L-B, CRITICAL): the declared
// trigger referent becomes a closed set of session-independent catalog
// properties, not a name. Reproduces all four of D69's demonstrated
// substitutions -- rebind to a different function in the same schema,
// rebind to a same-named no-op in another schema, WHEN (false) with the
// real function, and BEFORE ... UPDATE OF <column> with the real
// function and no WHEN clause -- against a real, disposable clone.
//
// Per D42/D47's convention: each case proves both halves. The
// "pre-Addendum-8" mechanism is reconstructed verbatim from this
// package's own shipped-before-this-addendum text (the exact body
// protectedRelationStateReason had immediately before D69/D71 were
// added -- git blame confirms it) and proves the substitution is
// accepted as legitimate once grant-ddl-ownership has been re-run over
// it (D69's own drift note: the launder requires a documented recovery
// window PLUS one undocumented ALTER EVENT TRIGGER ... DISABLE). The
// shipped mechanism (the real protectedRelationStateReason) then proves
// the same state is refused, naming the trigger and the property.
package screeningledger

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// preD62RecordProtectedObjectRegistry reconstructs
// scripts/ci/provision_test_roles.sh's sec7_protected_object
// DELETE/INSERT verbatim (unchanged by D69/D71, which added
// preconditions before it, not a different recording) -- needed
// alongside preD62RecordProtectedRelationState because
// checkProvisioningState's chain checks protectedObjectIdentityReason
// (D41) before protectedRelationStateReason, so a launder reproduction
// that only re-populates sec7_protected_relation still fails at the
// object-registry step on the substituted trigger's new OID.
func preD62RecordProtectedObjectRegistry(t *testing.T, ctx context.Context, superuser *pgx.Conn) {
	t.Helper()
	if _, err := superuser.Exec(ctx, `DELETE FROM sec7_protected_object`); err != nil {
		t.Fatalf("pre-D62 DELETE FROM sec7_protected_object: %v", err)
	}
	if _, err := superuser.Exec(ctx, `
		INSERT INTO sec7_protected_object (objid, classid, note) VALUES
		  ('screening_ledger_anchor'::regclass::oid, 'pg_class'::regclass::oid, 'table: screening_ledger_anchor'),
		  ('screening_ledger_retention_tombstone'::regclass::oid, 'pg_class'::regclass::oid, 'table: screening_ledger_retention_tombstone'),
		  ((SELECT oid FROM pg_trigger WHERE tgname='screening_ledger_anchor_immutable' AND tgrelid='screening_ledger_anchor'::regclass), 'pg_trigger'::regclass::oid, 'trigger: screening_ledger_anchor_immutable'),
		  ((SELECT oid FROM pg_trigger WHERE tgname='screening_ledger_anchor_no_truncate' AND tgrelid='screening_ledger_anchor'::regclass), 'pg_trigger'::regclass::oid, 'trigger: screening_ledger_anchor_no_truncate'),
		  ((SELECT oid FROM pg_trigger WHERE tgname='screening_ledger_retention_tombstone_immutable' AND tgrelid='screening_ledger_retention_tombstone'::regclass), 'pg_trigger'::regclass::oid, 'trigger: screening_ledger_retention_tombstone_immutable'),
		  ((SELECT oid FROM pg_trigger WHERE tgname='screening_ledger_retention_tombstone_no_truncate' AND tgrelid='screening_ledger_retention_tombstone'::regclass), 'pg_trigger'::regclass::oid, 'trigger: screening_ledger_retention_tombstone_no_truncate'),
		  ('screening_ledger_reject_mutation()'::regprocedure::oid, 'pg_proc'::regclass::oid, 'function: screening_ledger_reject_mutation'),
		  ('owl_reject_truncate()'::regprocedure::oid, 'pg_proc'::regclass::oid, 'function: owl_reject_truncate'),
		  ('screening_ledger_purge_snapshots(timestamptz,text,text)'::regprocedure::oid, 'pg_proc'::regclass::oid, 'function: screening_ledger_purge_snapshots(timestamptz,text,text)'),
		  ('screening_ledger_purge_snapshots(text[],timestamptz,text,text)'::regprocedure::oid, 'pg_proc'::regclass::oid, 'function: screening_ledger_purge_snapshots(text[],timestamptz,text,text)'),
		  ('sec7_protected_object'::regclass::oid, 'pg_class'::regclass::oid, 'table: sec7_protected_object'),
		  ('sec7_protected_relation'::regclass::oid, 'pg_class'::regclass::oid, 'table: sec7_protected_relation'),
		  ('sec7_instance_binding'::regclass::oid, 'pg_class'::regclass::oid, 'table: sec7_instance_binding')
	`); err != nil {
		t.Fatalf("pre-D62 INSERT INTO sec7_protected_object: %v", err)
	}
}

// preD69And71ProtectedRelationStateReason reconstructs
// protectedRelationStateReason as it read immediately before ADR-0007
// Addendum 8 (D69's trigger-behavior loop and D71's index-existence
// assertion both absent) -- the same recorded-vs-declared comparison
// d65_index_validity_pgx_test.go's preD65ProvisioningState uses for its
// own older baseline, extended here with D65's index-validity branch
// (shipped and unaffected by Addendum 8, so it stays).
func preD69And71ProtectedRelationStateReason(t *testing.T, ctx context.Context, p *PostgresSink) (string, error) {
	t.Helper()
	for _, want := range requiredProtectedRelationStates {
		var ownerOK, kindOK, rlsOK, forceRLSOK, triggersOK, indexesOK, indexesValidOK, policiesOK, identityOK bool
		err := p.conn.QueryRow(ctx, `
			SELECT
				r.relowner = $2::regrole::oid,
				r.relkind = $3,
				r.relrowsecurity = $4,
				r.relforcerowsecurity = $5,
				r.trigger_oids = (
					SELECT COALESCE(array_agg(t.oid ORDER BY t.oid), ARRAY[]::oid[])
					FROM pg_trigger t
					WHERE t.tgrelid = r.objid AND NOT t.tgisinternal AND t.tgname = ANY($6)
				),
				r.index_defs = (
					SELECT COALESCE(array_agg(pg_get_indexdef(ix.indexrelid) ORDER BY pg_get_indexdef(ix.indexrelid)), ARRAY[]::text[])
					FROM pg_index ix JOIN pg_class ic ON ic.oid = ix.indexrelid
					WHERE ix.indrelid = r.objid AND ic.relname = ANY($7)
				),
				NOT EXISTS (
					SELECT 1 FROM pg_index ix JOIN pg_class ic ON ic.oid = ix.indexrelid
					WHERE ix.indrelid = r.objid AND ic.relname = ANY($7)
					  AND NOT (ix.indisvalid AND ix.indisready)
				),
				r.policy_oids = ARRAY[]::oid[],
				r.identity = $1
			FROM sec7_protected_relation r
			WHERE (pg_identify_object('pg_class'::regclass, r.objid, 0)).identity = $1
		`, want.identity, want.relowner, want.relkind, want.relrowsecurity, want.relforcerowsecurity, want.triggerNames(), want.indexNames).
			Scan(&ownerOK, &kindOK, &rlsOK, &forceRLSOK, &triggersOK, &indexesOK, &indexesValidOK, &policiesOK, &identityOK)
		if err != nil {
			return "", fmt.Errorf("checking sec7_protected_relation recorded state for %s: %w", want.identity, err)
		}
		switch {
		case !ownerOK, !kindOK, !rlsOK, !forceRLSOK, !triggersOK, !indexesOK, !indexesValidOK, !policiesOK, !identityOK:
			return fmt.Sprintf("recorded state mismatch for %s (pre-Addendum-8 reconstruction)", want.identity), nil
		}
	}
	return "", nil
}

// preD69And71ProvisioningState mirrors checkProvisioningState's real
// chain, substituting the pre-Addendum-8 relation-state reconstruction
// for the shipped protectedRelationStateReason -- every other real
// method is unaffected by D69/D71 and is called for real, exactly
// d65_index_validity_pgx_test.go's preD65ProvisioningState pattern.
func preD69And71ProvisioningState(t *testing.T, ctx context.Context, p *PostgresSink) ProvisioningState {
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
	if reason, err := preD69And71ProtectedRelationStateReason(t, ctx, p); err != nil || reason != "" {
		return ProvisioningState{Reason: reason}
	}
	return ProvisioningState{Provisioned: true}
}

type d69Substitution struct {
	name string
	// setup runs as the bootstrap superuser with both event triggers
	// disabled, and with screening_ledger_retention_tombstone_immutable
	// already dropped -- it must (re)create that trigger as the
	// substitution.
	setup func(t *testing.T, ctx context.Context, superuser *pgx.Conn)
}

var d69Substitutions = []d69Substitution{
	{
		name: "rebind_to_different_function_same_schema",
		setup: func(t *testing.T, ctx context.Context, superuser *pgx.Conn) {
			if _, err := superuser.Exec(ctx, `CREATE FUNCTION cap7_noop() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RETURN NEW; END; $f$`); err != nil {
				t.Fatalf("create cap7_noop: %v", err)
			}
			if _, err := superuser.Exec(ctx, `
				CREATE TRIGGER screening_ledger_retention_tombstone_immutable
				  BEFORE DELETE OR UPDATE ON screening_ledger_retention_tombstone
				  FOR EACH ROW EXECUTE FUNCTION cap7_noop()`); err != nil {
				t.Fatalf("rebind trigger to cap7_noop: %v", err)
			}
		},
	},
	{
		name: "rebind_to_same_named_noop_another_schema",
		setup: func(t *testing.T, ctx context.Context, superuser *pgx.Conn) {
			if _, err := superuser.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS owl_migrator AUTHORIZATION owl_migrator`); err != nil {
				t.Fatalf("create schema owl_migrator: %v", err)
			}
			if _, err := superuser.Exec(ctx, `CREATE FUNCTION owl_migrator.screening_ledger_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RETURN NEW; END; $f$`); err != nil {
				t.Fatalf("create shadow no-op: %v", err)
			}
			if _, err := superuser.Exec(ctx, `
				CREATE TRIGGER screening_ledger_retention_tombstone_immutable
				  BEFORE DELETE OR UPDATE ON screening_ledger_retention_tombstone
				  FOR EACH ROW EXECUTE FUNCTION owl_migrator.screening_ledger_reject_mutation()`); err != nil {
				t.Fatalf("rebind trigger to shadow no-op: %v", err)
			}
		},
	},
	{
		name: "when_false_real_function",
		setup: func(t *testing.T, ctx context.Context, superuser *pgx.Conn) {
			if _, err := superuser.Exec(ctx, `
				CREATE TRIGGER screening_ledger_retention_tombstone_immutable
				  BEFORE DELETE OR UPDATE ON screening_ledger_retention_tombstone
				  FOR EACH ROW WHEN (false) EXECUTE FUNCTION screening_ledger_reject_mutation()`); err != nil {
				t.Fatalf("recreate trigger with WHEN (false): %v", err)
			}
		},
	},
	{
		name: "update_of_single_column_no_when",
		setup: func(t *testing.T, ctx context.Context, superuser *pgx.Conn) {
			if _, err := superuser.Exec(ctx, `
				CREATE TRIGGER screening_ledger_retention_tombstone_immutable
				  BEFORE DELETE OR UPDATE OF snapshot_sha256 ON screening_ledger_retention_tombstone
				  FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation()`); err != nil {
				t.Fatalf("recreate trigger narrowed to UPDATE OF snapshot_sha256: %v", err)
			}
		},
	},
}

func TestD69TriggerReferentIsBehaviourNotName(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()
	scriptPath := d62ScriptPath(t)

	for _, sub := range d69Substitutions {
		t.Run(sub.name, func(t *testing.T) {
			clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
			superuser, err := pgx.Connect(ctx, clone.superuserDSN)
			if err != nil {
				t.Fatalf("connect as bootstrap superuser: %v", err)
			}
			defer superuser.Close(context.Background())

			// D69's drift note: the documented recovery window
			// (_on_alter DISABLE alone) is not sufficient -- D34 refuses
			// the DROP TRIGGER unless _on_drop is ALSO disabled.
			if _, err := superuser.Exec(ctx, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE`); err != nil {
				t.Fatalf("disable ddl_command_end event trigger: %v", err)
			}
			if _, err := superuser.Exec(ctx, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop DISABLE`); err != nil {
				t.Fatalf("disable sql_drop event trigger: %v", err)
			}
			if _, err := superuser.Exec(ctx, `DROP TRIGGER screening_ledger_retention_tombstone_immutable ON screening_ledger_retention_tombstone`); err != nil {
				t.Fatalf("drop the guard trigger: %v", err)
			}
			sub.setup(t, ctx, superuser)

			// Seed a tombstone row as owl_ledger_ddl (its declared INSERT
			// privilege, D61's matrix) to forge against.
			ledgerDDLConn, err := pgx.Connect(ctx, clone.ledgerDDLDSN)
			if err != nil {
				t.Fatalf("connect as owl_ledger_ddl: %v", err)
			}
			defer ledgerDDLConn.Close(context.Background())
			if _, err := ledgerDDLConn.Exec(ctx,
				`INSERT INTO screening_ledger_retention_tombstone (snapshot_sha256, purged_at, operator, reason) VALUES ($1, now(), 'legit-op', 'legit-reason')`,
				uniqueID("d69-tombstone"),
			); err != nil {
				t.Fatalf("seed tombstone row: %v", err)
			}
			var seededSHA string
			if err := superuser.QueryRow(ctx, `SELECT snapshot_sha256 FROM screening_ledger_retention_tombstone ORDER BY purged_at DESC LIMIT 1`).Scan(&seededSHA); err != nil {
				t.Fatalf("read seeded snapshot_sha256: %v", err)
			}

			// The forgery itself: with the guard trigger substituted and
			// no launder needed for THIS assertion, owl_ledger_ddl can
			// already rewrite the tombstone's attribution.
			if _, err := ledgerDDLConn.Exec(ctx,
				`UPDATE screening_ledger_retention_tombstone SET operator='someone-else', reason='forged' WHERE snapshot_sha256=$1`,
				seededSHA,
			); err != nil {
				t.Fatalf("expected the neutered guard to allow the forging UPDATE (proves the substitution actually disables the control, not merely that a probe changed): %v", err)
			}

			// The launder, reconstructed directly (bypassing the shipped
			// script's own precondition, which now refuses this exact
			// launder -- see below): before ADR-0007 Addendum 8, re-running
			// grant-ddl-ownership over a same-named substitution recorded
			// its live state as legitimate, because D62(a)'s precondition
			// checked names only. preD62RecordProtectedRelationState
			// (d62_launder_refusal_pgx_test.go) is that exact DELETE/INSERT
			// sequence, unchanged by D69/D71 (which added preconditions
			// BEFORE it, not a different recording).
			withD34TriggersDisabled(t, ctx, superuser, func() {
				preD62RecordProtectedObjectRegistry(t, ctx, superuser)
				preD62RecordProtectedRelationState(t, ctx, superuser)
			})

			sink, err := NewPostgresSink(ctx, withDatabase(t, migratorDSN, clone.dbName), 10*time.Second)
			if err != nil {
				t.Fatalf("NewPostgresSink: %v", err)
			}
			defer sink.Close(context.Background())

			pre := preD69And71ProvisioningState(t, ctx, sink)
			if !pre.Provisioned {
				t.Fatalf("ADR-0007 Addendum 8 D69: expected the pre-Addendum-8 reconstruction to accept the laundered substitution as legitimate (Provisioned=true), got Reason=%q -- this must reproduce the gap, not a probe that never exercised it", pre.Reason)
			}

			after, err := sink.CheckProvisioningState(ctx)
			if err != nil {
				t.Fatalf("CheckProvisioningState: %v", err)
			}
			if after.Provisioned {
				t.Fatalf("ADR-0007 Addendum 8 D69: expected the shipped CheckProvisioningState to refuse the substituted trigger %q, got Provisioned=true", sub.name)
			}
			if !strings.Contains(after.Reason, "screening_ledger_retention_tombstone_immutable") {
				t.Fatalf("expected the refusal to name the trigger, got: %q", after.Reason)
			}
			if !strings.Contains(after.Reason, "D69") {
				t.Fatalf("expected the refusal to cite ADR-0007 Addendum 8 D69, got: %q", after.Reason)
			}

			// The installer-side half: the shipped grant-ddl-ownership
			// (run for real, not reconstructed) must ALSO now refuse to
			// perform the launder it used to perform silently.
			host, port, superuserUser, superpassword := pgConnParamsFromDSN(t, clone.superuserDSN)
			cmd := exec.Command(scriptPath, "grant-ddl-ownership")
			cmd.Env = append(cmd.Environ(),
				"PGHOST="+host, "PGPORT="+port, "PGDATABASE="+clone.dbName,
				"PGSUPERUSER="+superuserUser, "PGSUPERPASSWORD="+superpassword,
			)
			output, runErr := cmd.CombinedOutput()
			if runErr == nil {
				t.Fatalf("ADR-0007 Addendum 8 D69: grant-ddl-ownership succeeded against a database whose declared trigger's live behavior does not match (%s) -- expected refusal\n%s", sub.name, output)
			}
			if !strings.Contains(string(output), "D69") {
				t.Fatalf("expected the installer's refusal to cite ADR-0007 Addendum 8 D69, got:\n%s", output)
			}
		})
	}
}

// TestD69AcceptsCleanBaseline is D69's over-tightening positive: a clean
// provisioned database, and a database on which grant-ddl-ownership has
// been re-run, both accepted -- the shipping requirement D75 states,
// not a nicety.
func TestD69AcceptsCleanBaseline(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()
	scriptPath := d62ScriptPath(t)

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)

	sink, err := NewPostgresSink(ctx, withDatabase(t, migratorDSN, clone.dbName), 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())

	if state, err := sink.CheckProvisioningState(ctx); err != nil || !state.Provisioned {
		t.Fatalf("expected a clean clone to read Provisioned=true, got Provisioned=%v Reason=%q err=%v", state.Provisioned, state.Reason, err)
	}

	host, port, superuserUser, superpassword := pgConnParamsFromDSN(t, clone.superuserDSN)
	cmd := exec.Command(scriptPath, "grant-ddl-ownership")
	cmd.Env = append(cmd.Environ(),
		"PGHOST="+host, "PGPORT="+port, "PGDATABASE="+clone.dbName,
		"PGSUPERUSER="+superuserUser, "PGSUPERPASSWORD="+superpassword,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("re-running grant-ddl-ownership on a clean clone should succeed: %v\n%s", err, output)
	}

	if state, err := sink.CheckProvisioningState(ctx); err != nil || !state.Provisioned {
		t.Fatalf("expected a clean clone to still read Provisioned=true after re-running grant-ddl-ownership, got Provisioned=%v Reason=%q err=%v", state.Provisioned, state.Reason, err)
	}
}

// TestPgGetTriggerdefRendersIdenticallyAcrossSchemas is D69's own
// unit-level fact, pre-declared as a required assertion (D75) so a later
// reader who rediscovers pg_get_triggerdef finds this before
// implementing it: the same substituted trigger, rendered by the
// verifying role's own session (search_path "$user", public), is
// byte-identical to the legitimate rendering when a schema exists named
// after that role.
func TestPgGetTriggerdefRendersIdenticallyAcrossSchemas(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	superuser, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())

	migratorConn, err := pgx.Connect(ctx, withDatabase(t, migratorDSN, clone.dbName))
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	defer migratorConn.Close(context.Background())

	// The "legitimate" reference rendering is captured from the
	// verifier's own session BEFORE any substitution or shadow function
	// exists in this database -- the fact D69 states is that the
	// verifier renders the SUBSTITUTED trigger identically to how it
	// would render an untouched one, not that it matches some other
	// trigger's rendering in an already-contaminated session (creating
	// the shadow owl_migrator.screening_ledger_reject_mutation() function
	// changes how the verifier resolves EVERY unqualified reference to
	// that name in this database, including the anchor's own legitimate
	// trigger).
	var legitimateDef string
	if err := migratorConn.QueryRow(ctx, `SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgname='screening_ledger_retention_tombstone_immutable'`).Scan(&legitimateDef); err != nil {
		t.Fatal(err)
	}

	if _, err := superuser.Exec(ctx, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE`); err != nil {
		t.Fatal(err)
	}
	if _, err := superuser.Exec(ctx, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop DISABLE`); err != nil {
		t.Fatal(err)
	}
	if _, err := superuser.Exec(ctx, `DROP TRIGGER screening_ledger_retention_tombstone_immutable ON screening_ledger_retention_tombstone`); err != nil {
		t.Fatal(err)
	}
	if _, err := superuser.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS owl_migrator AUTHORIZATION owl_migrator`); err != nil {
		t.Fatal(err)
	}
	if _, err := superuser.Exec(ctx, `CREATE FUNCTION owl_migrator.screening_ledger_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RETURN NEW; END; $f$`); err != nil {
		t.Fatal(err)
	}
	if _, err := superuser.Exec(ctx, `
		CREATE TRIGGER screening_ledger_retention_tombstone_immutable
		  BEFORE DELETE OR UPDATE ON screening_ledger_retention_tombstone
		  FOR EACH ROW EXECUTE FUNCTION owl_migrator.screening_ledger_reject_mutation()`); err != nil {
		t.Fatal(err)
	}

	var recorderDef, verifierDef string
	if err := superuser.QueryRow(ctx, `SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgname='screening_ledger_retention_tombstone_immutable'`).Scan(&recorderDef); err != nil {
		t.Fatal(err)
	}
	if err := migratorConn.QueryRow(ctx, `SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgname='screening_ledger_retention_tombstone_immutable'`).Scan(&verifierDef); err != nil {
		t.Fatal(err)
	}
	if recorderDef == verifierDef {
		t.Fatalf("test precondition failed: expected the recorder (default search_path) and verifier (search_path \"$user\",public) sessions to render this trigger DIFFERENTLY -- recorder=%q verifier=%q", recorderDef, verifierDef)
	}
	if verifierDef != legitimateDef {
		t.Fatalf("ADR-0007 Addendum 8 D69: expected the verifying session's rendering of the SUBSTITUTED trigger to be byte-identical to a LEGITIMATE (untouched) trigger's rendering in that same session -- substituted=%q legitimate=%q", verifierDef, legitimateDef)
	}
}
