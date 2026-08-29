// ADR-0007 Addendum 9 D80/D85 test 4 (M-C, HIGH): the declared index
// gains the properties that make a primary-key index the control it is
// -- D71's EXISTS check accepts ANY object bearing the declared name,
// unique or not, primary or not, on the right columns or not. CAP #8
// section 7.3's exact substitution: a non-unique index on the wrong
// column, which D71 alone accepts.
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

// preD80ProtectedRelationStateReason reconstructs protectedRelationStateReason
// exactly as it reads today MINUS D80's own index-shape loop -- D71's
// existence check (already shipped, unaffected by D80) is kept for real,
// so this genuinely isolates "the declared index resolves to something"
// from "the declared index has the declared shape," rather than falling
// back to the much older pre-D69/D71 baseline (which would also miss
// D71's own existence check, already fixed, and so would not isolate
// D80's specific gap).
func preD80ProtectedRelationStateReason(t *testing.T, ctx context.Context, p *PostgresSink) (string, error) {
	t.Helper()
	for _, want := range requiredProtectedRelationStates {
		var ownerOK, kindOK, rlsOK, forceRLSOK, triggersOK, indexesOK, indexesValidOK, indexesPresentOK, policiesOK, identityOK bool
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
				NOT EXISTS (
					SELECT 1 FROM unnest($7::text[]) AS decl(name)
					WHERE NOT EXISTS (
						SELECT 1 FROM pg_index ix JOIN pg_class ic ON ic.oid = ix.indexrelid
						WHERE ix.indrelid = r.objid AND ic.relname = decl.name
					)
				),
				r.policy_oids = ARRAY[]::oid[],
				r.identity = $1
			FROM sec7_protected_relation r
			WHERE (pg_identify_object('pg_class'::regclass, r.objid, 0)).identity = $1
		`, want.identity, want.relowner, want.relkind, want.relrowsecurity, want.relforcerowsecurity, want.triggerNames(), want.indexNames()).
			Scan(&ownerOK, &kindOK, &rlsOK, &forceRLSOK, &triggersOK, &indexesOK, &indexesValidOK, &indexesPresentOK, &policiesOK, &identityOK)
		if err != nil {
			return "", fmt.Errorf("checking sec7_protected_relation recorded state for %s: %w", want.identity, err)
		}
		switch {
		case !ownerOK, !kindOK, !rlsOK, !forceRLSOK, !triggersOK, !indexesOK, !indexesValidOK, !indexesPresentOK, !policiesOK, !identityOK:
			return fmt.Sprintf("recorded state mismatch for %s (pre-D80 reconstruction)", want.identity), nil
		}
		for _, trig := range want.triggers {
			var tgtypeOK, tgqualIsNullOK, tgnargsOK, tgattrOK, functionOK, presentOK bool
			err := p.conn.QueryRow(ctx, `
				SELECT
					EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid = $1::regclass AND NOT t.tgisinternal AND t.tgname = $2),
					COALESCE((SELECT t.tgtype = $3 FROM pg_trigger t WHERE t.tgrelid = $1::regclass AND NOT t.tgisinternal AND t.tgname = $2), false),
					COALESCE((SELECT t.tgqual IS NULL FROM pg_trigger t WHERE t.tgrelid = $1::regclass AND NOT t.tgisinternal AND t.tgname = $2), false),
					COALESCE((SELECT t.tgnargs = $4 FROM pg_trigger t WHERE t.tgrelid = $1::regclass AND NOT t.tgisinternal AND t.tgname = $2), false),
					COALESCE((SELECT t.tgattr::text = $5 FROM pg_trigger t WHERE t.tgrelid = $1::regclass AND NOT t.tgisinternal AND t.tgname = $2), false),
					COALESCE((SELECT (pg_identify_object('pg_proc'::regclass, t.tgfoid, 0)).identity = $6 FROM pg_trigger t WHERE t.tgrelid = $1::regclass AND NOT t.tgisinternal AND t.tgname = $2), false)
			`, want.identity, trig.name, trig.tgtype, trig.tgnargs, trig.tgattr, trig.functionOID).
				Scan(&presentOK, &tgtypeOK, &tgqualIsNullOK, &tgnargsOK, &tgattrOK, &functionOK)
			if err != nil {
				return "", fmt.Errorf("checking trigger %s behavior on %s: %w", trig.name, want.identity, err)
			}
			if !presentOK || !functionOK || !tgtypeOK || !tgqualIsNullOK || !tgnargsOK || !tgattrOK {
				return fmt.Sprintf("recorded trigger behavior mismatch for %s on %s (pre-D80 reconstruction)", trig.name, want.identity), nil
			}
		}
		// D80's own new loop is deliberately NOT called here -- this is
		// the isolation point.
	}
	return "", nil
}

func preD80ProvisioningState(t *testing.T, ctx context.Context, p *PostgresSink) ProvisioningState {
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
	if reason, err := preD80ProtectedRelationStateReason(t, ctx, p); err != nil || reason != "" {
		return ProvisioningState{Reason: reason}
	}
	return ProvisioningState{Provisioned: true}
}

type d80Substitution struct {
	name string
	// ddl replaces screening_ledger_anchor_pkey with a wrong-shape index
	// of the same declared name, run with both event triggers disabled.
	ddl string
	// duplicateInsert is a statement that would violate a genuine
	// PRIMARY KEY (ledger_id, sequence) but succeeds against this
	// specific wrong shape -- tailored per substitution, since each
	// shape fails to enforce the real invariant a different way
	// (non-unique: no uniqueness at all; unique-but-not-primary: this
	// one shape genuinely still enforces row uniqueness -- what it
	// breaks is being constraint-backed for ON CONFLICT/foreign-key
	// resolution, not admitting a duplicate row, so no duplicate-insert
	// consequence applies and this field is left empty; wrong columns:
	// same (ledger_id, sequence) pair, different event_sha256, unique on
	// the wrong column so it passes; partial: rows outside the
	// predicate are not covered by the index at all; expression: an
	// expression over an unrelated column does not cover sequence at
	// all).
	duplicateInsert string
}

var d80Substitutions = []d80Substitution{
	{
		name:            "non_unique",
		ddl:             `CREATE INDEX screening_ledger_anchor_pkey ON screening_ledger_anchor (ledger_id, sequence)`,
		duplicateInsert: `INSERT INTO screening_ledger_anchor (ledger_id, sequence, event_sha256, audit_sha256, anchor_mac, audit_sequence, policy_sha256) VALUES ('d80-dupe',9,'esha-a','audit-a','mac-a',1,'psha'),('d80-dupe',9,'esha-b','audit-b','mac-b',1,'psha')`,
	},
	{
		name: "unique_but_not_primary",
		ddl:  `CREATE UNIQUE INDEX screening_ledger_anchor_pkey ON screening_ledger_anchor (ledger_id, sequence)`,
		// No duplicate-row consequence: this shape genuinely still
		// enforces uniqueness on the correct columns. What it breaks
		// (ON CONFLICT's default target, foreign-key referenceability)
		// is not reproduced here; D80's own text names indisprimary as
		// load-bearing for exactly that reason without claiming a
		// duplicate-row bypass for this specific shape.
	},
	{
		name:            "correct_uniqueness_wrong_columns",
		ddl:             `ALTER TABLE screening_ledger_anchor ADD CONSTRAINT screening_ledger_anchor_pkey PRIMARY KEY (ledger_id, event_sha256)`,
		duplicateInsert: `INSERT INTO screening_ledger_anchor (ledger_id, sequence, event_sha256, audit_sha256, anchor_mac, audit_sequence, policy_sha256) VALUES ('d80-dupe',9,'esha-a','audit-a','mac-a',1,'psha'),('d80-dupe',9,'esha-b','audit-b','mac-b',1,'psha')`,
	},
	{
		name:            "partial",
		ddl:             `CREATE UNIQUE INDEX screening_ledger_anchor_pkey ON screening_ledger_anchor (ledger_id, sequence) WHERE audit_sequence > 0`,
		duplicateInsert: `INSERT INTO screening_ledger_anchor (ledger_id, sequence, event_sha256, audit_sha256, anchor_mac, audit_sequence, policy_sha256) VALUES ('d80-dupe',9,'esha-a','audit-a','mac-a',0,'psha'),('d80-dupe',9,'esha-b','audit-b','mac-b',0,'psha')`,
	},
	{
		name:            "expression",
		ddl:             `CREATE UNIQUE INDEX screening_ledger_anchor_pkey ON screening_ledger_anchor (ledger_id, (lower(event_sha256)))`,
		duplicateInsert: `INSERT INTO screening_ledger_anchor (ledger_id, sequence, event_sha256, audit_sha256, anchor_mac, audit_sequence, policy_sha256) VALUES ('d80-dupe',9,'esha-a','audit-a','mac-a',1,'psha'),('d80-dupe',9,'esha-b','audit-b','mac-b',1,'psha')`,
	},
}

func TestDeclaredIndexShapeIsVerifiedNotOnlyPresence(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()
	scriptPath := d62ScriptPath(t)

	for _, sub := range d80Substitutions {
		t.Run(sub.name, func(t *testing.T) {
			clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
			superuser, err := pgx.Connect(ctx, clone.superuserDSN)
			if err != nil {
				t.Fatalf("connect as bootstrap superuser: %v", err)
			}
			defer superuser.Close(context.Background())

			mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE`)
			mustExec(t, ctx, superuser, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop DISABLE`)
			mustExec(t, ctx, superuser, `ALTER TABLE screening_ledger_anchor DROP CONSTRAINT screening_ledger_anchor_pkey`)
			if _, err := superuser.Exec(ctx, sub.ddl); err != nil {
				t.Fatalf("substitution DDL: %v", err)
			}

			// The launder: bypass D62(a)/D69/D71/D80's own preconditions
			// exactly as d69_trigger_referent_pgx_test.go's own launder
			// does, to reach the state where the registry has already
			// been (mis)recorded as legitimate -- proving D80 is a
			// verification gap, not merely an installer precondition that
			// would also catch this on the very next grant-ddl-ownership
			// run.
			withD34TriggersDisabled(t, ctx, superuser, func() {
				preD62RecordProtectedObjectRegistry(t, ctx, superuser)
				preD62RecordProtectedRelationState(t, ctx, superuser)
			})

			// The forgery itself, where this substitution has one: a
			// duplicate (ledger_id, sequence) row, refused only by a
			// genuine primary key.
			if sub.duplicateInsert != "" {
				ledgerAnchorConn, err := pgx.Connect(ctx, withDatabase(t, requireAnchorDatabaseURL(t), clone.dbName))
				if err != nil {
					t.Fatalf("connect as owl_ledger_anchor: %v", err)
				}
				defer ledgerAnchorConn.Close(context.Background())
				if _, err := ledgerAnchorConn.Exec(ctx, sub.duplicateInsert); err != nil {
					t.Fatalf("expected the duplicate-row insert to succeed against the wrong-shape index (proves the consequence): %v", err)
				}
			}

			sink, err := NewPostgresSink(ctx, withDatabase(t, migratorDSN, clone.dbName), 10*time.Second)
			if err != nil {
				t.Fatalf("NewPostgresSink: %v", err)
			}
			defer sink.Close(context.Background())

			// D71 ALONE (existence only, already shipped) accepts this
			// TODAY.
			pre := preD80ProvisioningState(t, ctx, sink)
			if !pre.Provisioned {
				t.Fatalf("ADR-0007 Addendum 8 D71 (alone): expected the pre-D80 reconstruction to accept the wrong-shape index as legitimate (Provisioned=true), got Reason=%q -- this must reproduce the vacuous-pass gap, not a probe that never exercised it", pre.Reason)
			}

			// AFTER: the shipped mechanism refuses, naming the index and
			// D80.
			after, err := sink.CheckProvisioningState(ctx)
			if err != nil {
				t.Fatalf("CheckProvisioningState: %v", err)
			}
			if after.Provisioned {
				t.Fatalf("ADR-0007 Addendum 9 D80: expected CheckProvisioningState to refuse the %s substitution, got Provisioned=true", sub.name)
			}
			if !strings.Contains(after.Reason, "screening_ledger_anchor_pkey") {
				t.Fatalf("expected the refusal to name the index, got: %q", after.Reason)
			}
			if !strings.Contains(after.Reason, "D80") {
				t.Fatalf("expected the refusal to cite ADR-0007 Addendum 9 D80, got: %q", after.Reason)
			}

			// The installer-side half: the shipped grant-ddl-ownership
			// must also refuse.
			host, port, superuserUser, superpassword := pgConnParamsFromDSN(t, clone.superuserDSN)
			cmd := exec.Command(scriptPath, "grant-ddl-ownership")
			cmd.Env = append(cmd.Environ(),
				"PGHOST="+host, "PGPORT="+port, "PGDATABASE="+clone.dbName,
				"PGSUPERUSER="+superuserUser, "PGSUPERPASSWORD="+superpassword,
			)
			output, runErr := cmd.CombinedOutput()
			if runErr == nil {
				t.Fatalf("ADR-0007 Addendum 9 D80: grant-ddl-ownership succeeded against a database whose declared index shape does not match (%s) -- expected refusal\n%s", sub.name, output)
			}
			if !strings.Contains(string(output), "D80") {
				t.Fatalf("expected the installer's refusal to cite ADR-0007 Addendum 9 D80, got:\n%s", output)
			}
		})
	}
}

// TestD80AcceptsCleanBaselineAndD65Unregressed is the over-tightening
// positive: both clean relations are accepted, and D65's index-validity
// branch (indisvalid/indisready) is unregressed by D80's addition beside
// it.
func TestD80AcceptsCleanBaselineAndD65Unregressed(t *testing.T) {
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

	if state, err := sink.CheckProvisioningState(ctx); err != nil || !state.Provisioned {
		t.Fatalf("expected a clean clone (both declared indexes correctly shaped) to read Provisioned=true, got Provisioned=%v Reason=%q err=%v", state.Provisioned, state.Reason, err)
	}

	// D65's own regression (indisvalid=false, indisready=true still
	// enforces uniqueness, and the shipped mechanism catches an
	// invalidated index) is unaffected by D80's addition: reuse the
	// same live behavior this file's sibling suite already proves,
	// checked here only for the "still refuses" half via a REINDEX
	// CONCURRENTLY cancellation is out of scope for this file (covered
	// by d65_index_validity_pgx_test.go); this test only confirms D80's
	// own new assertions do not fire spuriously on a healthy,
	// valid/ready index.
	var indisvalid, indisready bool
	if err := sink.conn.QueryRow(ctx, `SELECT indisvalid, indisready FROM pg_index WHERE indexrelid='screening_ledger_anchor_pkey'::regclass`).Scan(&indisvalid, &indisready); err != nil {
		t.Fatal(err)
	}
	if !indisvalid || !indisready {
		t.Fatalf("test precondition failed: expected a clean clone's primary key to be valid and ready, got indisvalid=%v indisready=%v", indisvalid, indisready)
	}
}
