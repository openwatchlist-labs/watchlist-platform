// ADR-0007 Addendum 9 D79/D85 test 3 (M-D, HIGH): a refusal must not
// disarm the database. D62(a)'s, D69/D77's and D56/D71/D80's precondition
// checks are hoisted above grant-ddl-ownership's own DROP EVENT TRIGGER
// statements, and a trap restores both event triggers on any non-zero
// exit if the step itself took them down -- "either fully provisioned,
// or exactly as protected as when I started," not the fail-open middle
// CAP #8 demonstrated (today: both triggers fully DROPPED, count 0).
//
// Each case's setup necessarily leaves the event triggers in whatever
// state that specific substitution requires to perform (measured by
// execution, not assumed): D40/D50's EXISTING runtime re-validation
// already fires on ANY change to a protected relation's trigger_oids or
// index_defs SET the moment enforcement resumes, so a structural
// substitution (an extra trigger/index, a dropped trigger, a
// wrong-shape index) cannot be re-enabled cleanly before invoking
// grant-ddl-ownership -- only the D69/D77 function-BODY swap can, because
// it changes neither tracked set (same trigger OID, same index
// definition), which is the exact reason D77 exists. The invariant this
// test asserts is therefore general -- unchanged from whatever state
// immediately preceded the invocation -- and, for the D69/D77 case
// specifically (where returning to fully-enabled is mechanically
// possible and is CAP #8's own exact transcript), the literal stronger
// claim D85 states: both evtenabled='A'.
package screeningledger

import (
	"context"
	"os/exec"
	"testing"

	"github.com/jackc/pgx/v5"
)

// refusalCase is one of D79's five named refusal paths. setup returns
// the event-trigger enabled states it deliberately leaves behind
// (evtname -> evtenabled), which is exactly the state grant-ddl-ownership
// must not disturb.
type refusalCase struct {
	name  string
	setup func(t *testing.T, ctx context.Context, superuser *pgx.Conn)
}

var d79RefusalCases = []refusalCase{
	{
		name: "d62a_undeclared_trigger",
		setup: func(t *testing.T, ctx context.Context, superuser *pgx.Conn) {
			// CREATE TRIGGER on a protected relation changes its
			// trigger_oids set -- D40's existing runtime check fires the
			// instant _on_alter is live again, so this stays disabled
			// (measured: re-enabling immediately raises "its trigger set
			// changed").
			mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE`)
			mustExec(t, ctx, superuser, `CREATE FUNCTION cap9_noop() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RETURN NEW; END; $f$`)
			mustExec(t, ctx, superuser, `CREATE TRIGGER cap9_extra_trigger BEFORE UPDATE ON screening_ledger_anchor FOR EACH ROW EXECUTE FUNCTION cap9_noop()`)
		},
	},
	{
		name: "d62a_undeclared_index",
		setup: func(t *testing.T, ctx context.Context, superuser *pgx.Conn) {
			mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE`)
			mustExec(t, ctx, superuser, `CREATE INDEX cap9_extra_index ON screening_ledger_anchor (event_sha256)`)
		},
	},
	{
		name: "d69_d77_behavior",
		setup: func(t *testing.T, ctx context.Context, superuser *pgx.Conn) {
			// CAP #8's own exact three-statement transcript: the
			// substitution changes neither trigger_oids nor index_defs (the
			// trigger's OID and definition are both unchanged; only the
			// bound function's body changed), so re-enabling completes
			// cleanly -- this is the one case that reaches fully-'A' again
			// before grant-ddl-ownership ever runs.
			mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE`)
			mustExec(t, ctx, superuser, `CREATE OR REPLACE FUNCTION public.screening_ledger_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$`)
			mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter ENABLE ALWAYS`)
		},
	},
	{
		name: "d56_d71_missing_object",
		setup: func(t *testing.T, ctx context.Context, superuser *pgx.Conn) {
			// D69's own drift note: DROP TRIGGER needs BOTH event triggers
			// disabled, not _on_alter alone.
			mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE`)
			mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop DISABLE`)
			mustExec(t, ctx, superuser, `DROP TRIGGER screening_ledger_anchor_no_truncate ON screening_ledger_anchor`)
		},
	},
	{
		name: "d80_index_shape",
		setup: func(t *testing.T, ctx context.Context, superuser *pgx.Conn) {
			mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE`)
			mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop DISABLE`)
			mustExec(t, ctx, superuser, `ALTER TABLE screening_ledger_anchor DROP CONSTRAINT screening_ledger_anchor_pkey`)
			mustExec(t, ctx, superuser, `CREATE INDEX screening_ledger_anchor_pkey ON screening_ledger_anchor (ledger_id)`)
		},
	},
}

func mustExec(t *testing.T, ctx context.Context, conn *pgx.Conn, sql string) {
	t.Helper()
	if _, err := conn.Exec(ctx, sql); err != nil {
		t.Fatalf("setup statement %q: %v", sql, err)
	}
}

func eventTriggerStates(t *testing.T, ctx context.Context, conn *pgx.Conn) map[string]string {
	t.Helper()
	rows, err := conn.Query(ctx, `SELECT evtname, evtenabled FROM pg_event_trigger`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	states := map[string]string{}
	for rows.Next() {
		var name, enabled string
		if err := rows.Scan(&name, &enabled); err != nil {
			t.Fatal(err)
		}
		states[name] = enabled
	}
	return states
}

// TestRefusalPathLeavesEnforcementInstalled is D85 test 3: for each of
// the five refusal paths, grant-ddl-ownership exits 1 AND the event
// triggers are left in EXACTLY the state they were in immediately before
// the invocation -- never fewer rows (today: 0, both fully DROPPED), and
// never a different enabled/disabled state than the operator/attacker
// themselves left. Also asserts the named consequence regression (D34
// still refuses DROP TABLE as owl_ledger_ddl after a refusal, where CAP
// #8 found it succeeds without this fix).
func TestRefusalPathLeavesEnforcementInstalled(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()
	scriptPath := d62ScriptPath(t)

	for _, rc := range d79RefusalCases {
		t.Run(rc.name, func(t *testing.T) {
			clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
			superuser, err := pgx.Connect(ctx, clone.superuserDSN)
			if err != nil {
				t.Fatalf("connect as bootstrap superuser: %v", err)
			}
			defer superuser.Close(context.Background())

			rc.setup(t, ctx, superuser)
			before := eventTriggerStates(t, ctx, superuser)
			if len(before) != 2 {
				t.Fatalf("test precondition failed: expected 2 event triggers before invoking grant-ddl-ownership (%s), got %v", rc.name, before)
			}

			host, port, superuserUser, superpassword := pgConnParamsFromDSN(t, clone.superuserDSN)
			cmd := exec.Command(scriptPath, "grant-ddl-ownership")
			cmd.Env = append(cmd.Environ(),
				"PGHOST="+host, "PGPORT="+port, "PGDATABASE="+clone.dbName,
				"PGSUPERUSER="+superuserUser, "PGSUPERPASSWORD="+superpassword,
			)
			output, runErr := cmd.CombinedOutput()
			if runErr == nil {
				t.Fatalf("ADR-0007 Addendum 9 D79: expected grant-ddl-ownership to refuse (%s), got exit 0:\n%s", rc.name, output)
			}

			after := eventTriggerStates(t, ctx, superuser)
			if len(after) != 2 {
				t.Fatalf("ADR-0007 Addendum 9 D79: expected pg_event_trigger to still have 2 rows after the refusal (%s) -- today this is 0, both fully DROPPED. got %v\noutput:\n%s", rc.name, after, output)
			}
			for name, wantEnabled := range before {
				if after[name] != wantEnabled {
					t.Fatalf("ADR-0007 Addendum 9 D79: %s's evtenabled changed from %q to %q across the refusal (%s) -- \"either fully provisioned, or exactly as protected as when I started\"\noutput:\n%s", name, wantEnabled, after[name], rc.name, output)
				}
			}
			// D69/D77's own case reaches fully-'A' before invocation
			// (CAP #8's exact transcript), so it gets the literal stronger
			// assertion D85 states for this case.
			if rc.name == "d69_d77_behavior" {
				for name, enabled := range after {
					if enabled != "A" {
						t.Fatalf("ADR-0007 Addendum 9 D79: expected %s to read ENABLE ALWAYS after the refusal (%s), got %q", name, rc.name, enabled)
					}
				}
			}

			// The named consequence regression: D34 still refuses DROP
			// TABLE as owl_ledger_ddl after the refusal -- CAP #8's M-D
			// demonstrated this succeeding once a refusal left the
			// triggers down. Only meaningful where _on_drop (the event
			// DROP TABLE fires) was actually live immediately before this
			// invocation -- two of the five cases (d56_d71_missing_object,
			// d80_index_shape) need _on_drop disabled for their OWN setup
			// DDL to succeed at all, so DROP TABLE succeeding there is the
			// pre-existing T2 exposure (R30) the operator's own action
			// already created, not a regression this step introduced; the
			// "unchanged from before" assertion above already covers that
			// case correctly.
			if before["sec7_protect_ddl_objects_on_drop"] == "A" {
				ledgerDDLConn, err := pgx.Connect(ctx, withDatabase(t, requireLedgerDDLDatabaseURL(t), clone.dbName))
				if err != nil {
					t.Fatalf("connect as owl_ledger_ddl: %v", err)
				}
				defer ledgerDDLConn.Close(context.Background())
				if _, err := ledgerDDLConn.Exec(ctx, `DROP TABLE screening_ledger_anchor CASCADE`); err == nil {
					t.Fatalf("ADR-0007 Addendum 9 D79: DROP TABLE screening_ledger_anchor succeeded as owl_ledger_ddl after a refusal (%s) -- enforcement was left disabled", rc.name)
				}
			}
		})
	}
}

// TestD79AcceptsCleanBaseline is the over-tightening positive: a clean
// run still provisions and still installs both triggers, with the
// preconditions now running before any DDL rather than after.
func TestD79AcceptsCleanBaseline(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()
	scriptPath := d62ScriptPath(t)

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	host, port, superuserUser, superpassword := pgConnParamsFromDSN(t, clone.superuserDSN)
	cmd := exec.Command(scriptPath, "grant-ddl-ownership")
	cmd.Env = append(cmd.Environ(),
		"PGHOST="+host, "PGPORT="+port, "PGDATABASE="+clone.dbName,
		"PGSUPERUSER="+superuserUser, "PGSUPERPASSWORD="+superpassword,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clean grant-ddl-ownership should succeed with the hoisted preconditions: %v\n%s", err, output)
	}

	superuser, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer superuser.Close(context.Background())
	var enabledCount int
	if err := superuser.QueryRow(ctx, `SELECT count(*) FROM pg_event_trigger WHERE evtenabled='A'`).Scan(&enabledCount); err != nil {
		t.Fatal(err)
	}
	if enabledCount != 2 {
		t.Fatalf("expected both event triggers ENABLE ALWAYS after a clean run, got %d", enabledCount)
	}
}
