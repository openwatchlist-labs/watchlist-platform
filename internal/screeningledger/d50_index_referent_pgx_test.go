// ADR-0007 Addendum 6 D50/D58 test 1 (J-A, HIGH): the index referent
// becomes the index *definition* set, not its OID set, because
// REINDEX ... CONCURRENTLY preserves everything about an index except
// its OID -- comparing OIDs makes an ordinary index rebuild
// indistinguishable from an attack, and because the statement commits
// its catalog swap in an internal transaction the exception cannot
// undo, the result is a wedge (every subsequent DDL statement fails,
// including the bootstrap superuser's) rather than a refusal.
//
// Per D58/D42's convention: several assertions below are stated as
// "must wedge under the OLD (index_oids) mechanism, and stay healthy
// under the shipped (index_defs) one" -- a test asserting only the
// post-fix health cannot distinguish a working fix from a test that
// never exercised the path this addendum repairs. The old mechanism is
// reconstructed verbatim (from ADR-0007 Addendum 4's shipped text) and
// installed on a disposable TEMPLATE clone for exactly this comparison;
// nothing in the primary database or in any other test is touched.
//
// D26/D34/D40's own forms (five original D26 forms, three CAP #2
// escapes, three inheritance forms plus the TEMP variant, CREATE RULE,
// CREATE TRIGGER, CREATE UNIQUE INDEX ... ((1)), CREATE POLICY) are
// proven unchanged by ddl_event_trigger_pgx_test.go,
// d34_object_scoped_pgx_test.go and d40_protected_relation_pgx_test.go,
// already running in this same package -- not re-asserted here, per
// the convention d40_protected_relation_pgx_test.go's own header sets.
package screeningledger

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// d50CloneFixture is a disposable CREATE DATABASE ... TEMPLATE clone of
// the primary database, torn down in t.Cleanup. CREATE DATABASE ...
// TEMPLATE preserves relation OIDs (confirmed by execution, D43's own
// transcript, reused by TestProvisioningStateAcceptsTemplateClone in
// d43_copy_population_pgx_test.go) -- exactly the byte-identical
// starting state D50's own design-pass transcripts require.
type d50CloneFixture struct {
	dbName       string
	superuserDSN string
	ledgerDDLDSN string
}

func newD50Clone(t *testing.T, ctx context.Context, superuserDSN, migratorDSN, ledgerDDLDSN string) d50CloneFixture {
	t.Helper()
	superuser, err := pgx.Connect(ctx, superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())

	sourceDB := dbNameFromDSN(t, migratorDSN)
	cloneDB := fmt.Sprintf("owl_ci_d50_clone_%d", time.Now().UnixNano())
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
			t.Errorf("drop d50 clone %s: connect: %v", cloneDB, err)
			return
		}
		defer c.Close(bg)
		if _, err := c.Exec(bg, fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, pgx.Identifier{cloneDB}.Sanitize())); err != nil {
			t.Errorf("drop d50 clone %s: %v", cloneDB, err)
		}
	})

	return d50CloneFixture{
		dbName:       cloneDB,
		superuserDSN: withDatabase(t, superuserDSN, cloneDB),
		ledgerDDLDSN: withDatabase(t, ledgerDDLDSN, cloneDB),
	}
}

// installPreD50IndexOIDsMechanism reconstructs ADR-0007 Addendum 4's
// shipped sec7_protect_ddl_objects() second phase verbatim -- the
// index_oids column and the `cur_indexes IS DISTINCT FROM
// rel.index_oids` comparison this addendum's D50 replaces -- on a
// clone that otherwise runs the current, shipped schema. This is not a
// simulation: it is the literal pre-D50 mechanism, installed so the
// wedge D50 repairs can be reproduced against a real database rather
// than asserted from the ADR's transcript.
func installPreD50IndexOIDsMechanism(t *testing.T, ctx context.Context, superuser *pgx.Conn) {
	t.Helper()
	withD34TriggersDisabled(t, ctx, superuser, func() {
		if _, err := superuser.Exec(ctx, `ALTER TABLE sec7_protected_relation ADD COLUMN index_oids oid[]`); err != nil {
			t.Fatalf("add pre-D50 index_oids column: %v", err)
		}
		if _, err := superuser.Exec(ctx, `
			UPDATE sec7_protected_relation r SET index_oids = (
				SELECT COALESCE(array_agg(ix.indexrelid ORDER BY ix.indexrelid), ARRAY[]::oid[])
				FROM pg_index ix WHERE ix.indrelid = r.objid
			)
		`); err != nil {
			t.Fatalf("populate pre-D50 index_oids column: %v", err)
		}
		if _, err := superuser.Exec(ctx, `ALTER TABLE sec7_protected_relation ALTER COLUMN index_oids SET NOT NULL`); err != nil {
			t.Fatalf("set pre-D50 index_oids NOT NULL: %v", err)
		}
		if _, err := superuser.Exec(ctx, `
			CREATE OR REPLACE FUNCTION sec7_protect_ddl_objects() RETURNS event_trigger LANGUAGE plpgsql
			SECURITY DEFINER SET search_path = pg_catalog, public AS $$
			DECLARE
				obj record;
				rel record;
				cur_owner oid;
				cur_kind "char";
				cur_rls boolean;
				cur_force_rls boolean;
				cur_triggers oid[];
				cur_indexes oid[];
				cur_policies oid[];
			BEGIN
				IF TG_EVENT = 'sql_drop' THEN
					FOR obj IN SELECT * FROM pg_event_trigger_dropped_objects() LOOP
						IF obj.objid IN (SELECT objid FROM sec7_protected_object) THEN
							RAISE EXCEPTION 'ADR-0007 Addendum 3 D34: % (objid %) is protected by a superuser-only DDL event trigger and cannot be dropped', obj.object_identity, obj.objid;
						END IF;
					END LOOP;
				ELSIF TG_EVENT = 'ddl_command_end' THEN
					FOR obj IN SELECT * FROM pg_event_trigger_ddl_commands() LOOP
						IF obj.objid IS NOT NULL AND obj.objid IN (SELECT objid FROM sec7_protected_object) THEN
							RAISE EXCEPTION 'ADR-0007 Addendum 3 D34: % (objid %, tag %) is protected by a superuser-only DDL event trigger', obj.object_identity, obj.objid, obj.command_tag;
						END IF;
					END LOOP;
					FOR rel IN SELECT * FROM sec7_protected_relation LOOP
						CONTINUE WHEN NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = rel.objid);
						SELECT c.relowner, c.relkind, c.relrowsecurity, c.relforcerowsecurity
							INTO cur_owner, cur_kind, cur_rls, cur_force_rls
							FROM pg_class c WHERE c.oid = rel.objid;
						IF cur_owner IS DISTINCT FROM rel.relowner THEN
							RAISE EXCEPTION 'ADR-0007 Addendum 4 D40: protected relation (objid %): its owner changed', rel.objid;
						END IF;
						IF cur_kind IS DISTINCT FROM rel.relkind THEN
							RAISE EXCEPTION 'ADR-0007 Addendum 4 D40: protected relation (objid %): its relkind changed', rel.objid;
						END IF;
						IF cur_rls IS DISTINCT FROM rel.relrowsecurity OR cur_force_rls IS DISTINCT FROM rel.relforcerowsecurity THEN
							RAISE EXCEPTION 'ADR-0007 Addendum 4 D40: protected relation (objid %): its row-level-security flags changed', rel.objid;
						END IF;
						IF EXISTS (SELECT 1 FROM pg_rewrite r WHERE r.ev_class = rel.objid) THEN
							RAISE EXCEPTION 'ADR-0007 Addendum 4 D40: protected relation (objid %): a rewrite RULE exists on it', rel.objid;
						END IF;
						IF EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhparent = rel.objid OR i.inhrelid = rel.objid) THEN
							RAISE EXCEPTION 'ADR-0007 Addendum 4 D40: protected relation (objid %): an inheritance child is attached (or it has itself been attached as a child)', rel.objid;
						END IF;
						SELECT COALESCE(array_agg(t.oid ORDER BY t.oid), ARRAY[]::oid[]) INTO cur_triggers
							FROM pg_trigger t WHERE t.tgrelid = rel.objid AND NOT t.tgisinternal;
						IF cur_triggers IS DISTINCT FROM rel.trigger_oids THEN
							RAISE EXCEPTION 'ADR-0007 Addendum 4 D40: protected relation (objid %): its trigger set changed', rel.objid;
						END IF;
						SELECT COALESCE(array_agg(ix.indexrelid ORDER BY ix.indexrelid), ARRAY[]::oid[]) INTO cur_indexes
							FROM pg_index ix WHERE ix.indrelid = rel.objid;
						IF cur_indexes IS DISTINCT FROM rel.index_oids THEN
							RAISE EXCEPTION 'ADR-0007 Addendum 4 D40: protected relation (objid %): its index set changed', rel.objid;
						END IF;
						SELECT COALESCE(array_agg(p.oid ORDER BY p.oid), ARRAY[]::oid[]) INTO cur_policies
							FROM pg_policy p WHERE p.polrelid = rel.objid;
						IF cur_policies IS DISTINCT FROM rel.policy_oids THEN
							RAISE EXCEPTION 'ADR-0007 Addendum 4 D40: protected relation (objid %): its RLS policy set changed', rel.objid;
						END IF;
						IF EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid = rel.objid AND NOT t.tgisinternal AND t.tgenabled <> 'O') THEN
							RAISE EXCEPTION 'ADR-0007 Addendum 4 D40: protected relation (objid %): one of its triggers is not ENABLE (tgenabled <> ''O'')', rel.objid;
						END IF;
					END LOOP;
				END IF;
			END;
			$$;
		`); err != nil {
			t.Fatalf("install pre-D50 sec7_protect_ddl_objects(): %v", err)
		}
	})
}

// assertWedged confirms an unrelated CREATE TABLE, run as the bootstrap
// superuser, fails -- the operational definition of "wedged" this
// addendum's own transcripts use throughout. The SQLSTATE is captured,
// not inferred, per D58's own requirement.
func assertWedged(t *testing.T, ctx context.Context, superuserDSN, probeName string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser to probe wedge state: %v", err)
	}
	defer conn.Close(context.Background())
	_, err = conn.Exec(ctx, `CREATE TABLE `+probeName+` (id int)`)
	if err == nil {
		t.Fatalf("expected the database to be wedged (unrelated CREATE TABLE %s should fail) but it succeeded", probeName)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("expected a captured SQLSTATE on the wedge probe, got a non-Postgres error: %v", err)
	}
	t.Logf("wedge confirmed: unrelated CREATE TABLE failed with SQLSTATE %s: %v", pgErr.Code, err)
}

// assertHealthy confirms an unrelated CREATE TABLE, run as the
// bootstrap superuser, succeeds -- and cleans it up.
func assertHealthy(t *testing.T, ctx context.Context, superuserDSN, probeName string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser to probe health state: %v", err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(ctx, `CREATE TABLE `+probeName+` (id int)`); err != nil {
		t.Fatalf("expected the database to be healthy (unrelated CREATE TABLE %s should succeed), got: %v", probeName, err)
	}
	if _, err := conn.Exec(ctx, `DROP TABLE `+probeName); err != nil {
		t.Fatalf("cleanup %s: %v", probeName, err)
	}
}

// d50ReindexForm is one of the five CONCURRENTLY forms D50's own
// transcript demonstrates wedge under the pre-D50 mechanism.
type d50ReindexForm struct {
	name    string
	asRole  string // "ledger_ddl" or "superuser"
	stmtFor func(dbName string) string
}

var d50ReindexForms = []d50ReindexForm{
	{
		name:   "REINDEX_INDEX_CONCURRENTLY_anchor_pkey",
		asRole: "ledger_ddl",
		stmtFor: func(string) string {
			return `REINDEX INDEX CONCURRENTLY screening_ledger_anchor_pkey`
		},
	},
	{
		name:   "REINDEX_TABLE_CONCURRENTLY_anchor",
		asRole: "ledger_ddl",
		stmtFor: func(string) string {
			return `REINDEX TABLE CONCURRENTLY screening_ledger_anchor`
		},
	},
	{
		name:   "REINDEX_TABLE_CONCURRENTLY_tombstone",
		asRole: "ledger_ddl",
		stmtFor: func(string) string {
			return `REINDEX TABLE CONCURRENTLY screening_ledger_retention_tombstone`
		},
	},
	{
		name:   "REINDEX_SCHEMA_CONCURRENTLY_public",
		asRole: "superuser",
		stmtFor: func(string) string {
			return `REINDEX SCHEMA CONCURRENTLY public`
		},
	},
	{
		name:   "REINDEX_DATABASE_CONCURRENTLY",
		asRole: "superuser",
		stmtFor: func(dbName string) string {
			return `REINDEX DATABASE CONCURRENTLY ` + pgx.Identifier{dbName}.Sanitize()
		},
	},
}

// runReindexForm connects as the form's role and executes its
// statement, returning the error (if any). REINDEX ... CONCURRENTLY
// cannot run inside a transaction block, so this is a bare Exec, not
// attemptBlocked's transaction-and-rollback pattern.
func runReindexForm(t *testing.T, ctx context.Context, clone d50CloneFixture, ledgerDDLBaseDSN string, form d50ReindexForm) error {
	t.Helper()
	dsn := clone.superuserDSN
	if form.asRole == "ledger_ddl" {
		dsn = withDatabase(t, ledgerDDLBaseDSN, clone.dbName)
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("%s: connect as %s: %v", form.name, form.asRole, err)
	}
	defer conn.Close(context.Background())
	_, execErr := conn.Exec(ctx, form.stmtFor(clone.dbName))
	return execErr
}

// grantMaintainBack undoes ADR-0007 Addendum 6 D51's revoke on a clone,
// so TestD50IndexReferentSurvivesConcurrentRebuild isolates D50 (the
// index referent) from D51 (the MAINTAIN privilege) -- exactly the
// order the addendum's own design pass tested them in. D51 has its own
// dedicated test (TestProvisioningStateDetectsMaintainRegrant).
func grantMaintainBack(t *testing.T, ctx context.Context, superuserDSN string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser to grant MAINTAIN back: %v", err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(ctx, `GRANT MAINTAIN ON TABLE screening_ledger_anchor, screening_ledger_retention_tombstone TO owl_ledger_ddl`); err != nil {
		t.Fatalf("grant MAINTAIN back to owl_ledger_ddl: %v", err)
	}
}

func TestD50IndexReferentSurvivesConcurrentRebuild(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	for _, form := range d50ReindexForms {
		form := form
		t.Run(form.name, func(t *testing.T) {
			t.Run("wedged_under_pre_D50_mechanism", func(t *testing.T) {
				clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
				grantMaintainBack(t, ctx, clone.superuserDSN)

				superuser, err := pgx.Connect(ctx, clone.superuserDSN)
				if err != nil {
					t.Fatalf("connect as bootstrap superuser: %v", err)
				}
				installPreD50IndexOIDsMechanism(t, ctx, superuser)
				superuser.Close(context.Background())

				execErr := runReindexForm(t, ctx, clone, ledgerDDLDSN, form)
				if execErr == nil {
					t.Fatalf("%s: expected the pre-D50 (index_oids) mechanism to raise on this CONCURRENTLY form, it did not", form.name)
				}
				var pgErr *pgconn.PgError
				if !errors.As(execErr, &pgErr) {
					t.Fatalf("%s: expected a captured SQLSTATE, got a non-Postgres error: %v", form.name, execErr)
				}
				t.Logf("%s: pre-D50 mechanism raised SQLSTATE %s: %v", form.name, pgErr.Code, execErr)
				assertWedged(t, ctx, clone.superuserDSN, "zz_d50_wedge_probe")
			})

			t.Run("healthy_under_shipped_D50_mechanism", func(t *testing.T) {
				clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
				grantMaintainBack(t, ctx, clone.superuserDSN)

				execErr := runReindexForm(t, ctx, clone, ledgerDDLDSN, form)
				if execErr != nil {
					t.Fatalf("%s: expected the shipped (index_defs) mechanism to let this CONCURRENTLY form succeed, got: %v", form.name, execErr)
				}
				assertHealthy(t, ctx, clone.superuserDSN, "zz_d50_health_probe")
			})
		})
	}

	// D58's tightening proof: ALTER INDEX ... RENAME succeeds today
	// (the OID it reports is the index's own, unchanged by RENAME, so
	// D40's pre-D50 OID comparison never sees it) and is blocked after
	// D50 (the definition -- which renders the name -- changes).
	t.Run("ALTER_INDEX_RENAME_tightening", func(t *testing.T) {
		t.Run("succeeds_under_pre_D50_mechanism", func(t *testing.T) {
			clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
			superuser, err := pgx.Connect(ctx, clone.superuserDSN)
			if err != nil {
				t.Fatalf("connect as bootstrap superuser: %v", err)
			}
			installPreD50IndexOIDsMechanism(t, ctx, superuser)
			if _, err := superuser.Exec(ctx, `ALTER INDEX screening_ledger_anchor_pkey RENAME TO zz_d50_pre_renamed`); err != nil {
				t.Fatalf("expected ALTER INDEX ... RENAME to succeed under the pre-D50 (OID-keyed) mechanism, got: %v", err)
			}
			superuser.Close(context.Background())
		})
		t.Run("blocked_under_shipped_D50_mechanism", func(t *testing.T) {
			clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
			superuser, err := pgx.Connect(ctx, clone.superuserDSN)
			if err != nil {
				t.Fatalf("connect as bootstrap superuser: %v", err)
			}
			defer superuser.Close(context.Background())
			_, err = superuser.Exec(ctx, `ALTER INDEX screening_ledger_anchor_pkey RENAME TO zz_d50_post_renamed`)
			if err == nil {
				t.Fatal("ADR-0007 Addendum 6 D50: ALTER INDEX ... RENAME succeeded against the shipped (index_defs) mechanism -- this is the tightening proof, not just the repair proof")
			}
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "P0001" {
				t.Fatalf("expected SQLSTATE P0001 (D50's raise_exception), got %q: %v", pgErrorCode(err), err)
			}
		})
	})

	// D37's rule verbatim: a suite that proves only the blocks has not
	// proven D50 is safe to install. This collateral-damage set is the
	// one specific to D50's own change (index-comparison-adjacent
	// CONCURRENTLY forms and the collateral cases D50's own battery
	// names); the general D26/D34/D40 collateral set is covered by the
	// sibling test files this package already runs (see file header).
	t.Run("collateral_damage", func(t *testing.T) {
		clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
		superuserConn, err := pgx.Connect(ctx, clone.superuserDSN)
		if err != nil {
			t.Fatalf("connect as bootstrap superuser: %v", err)
		}
		defer superuserConn.Close(context.Background())

		t.Run("REINDEX_TABLE_CONCURRENTLY_on_unprotected_relation", func(t *testing.T) {
			if _, err := superuserConn.Exec(ctx, `REINDEX TABLE CONCURRENTLY screening_ledger_event`); err != nil {
				t.Fatalf("REINDEX TABLE CONCURRENTLY on an unprotected relation should succeed under D50: %v", err)
			}
		})
		t.Run("CREATE_INDEX_CONCURRENTLY_on_unprotected_relation", func(t *testing.T) {
			if _, err := superuserConn.Exec(ctx, `CREATE INDEX CONCURRENTLY zz_d50_collateral_idx ON screening_ledger_event (ledger_id)`); err != nil {
				t.Fatalf("CREATE INDEX CONCURRENTLY on an unprotected relation should succeed under D50: %v", err)
			}
			if _, err := superuserConn.Exec(ctx, `DROP INDEX zz_d50_collateral_idx`); err != nil {
				t.Fatalf("cleanup zz_d50_collateral_idx: %v", err)
			}
		})
		t.Run("CREATE_VIEW_over_protected_table", func(t *testing.T) {
			if _, err := superuserConn.Exec(ctx, `CREATE VIEW zz_d50_view AS SELECT * FROM screening_ledger_anchor`); err != nil {
				t.Fatalf("CREATE VIEW over a protected table should succeed under D50: %v", err)
			}
			if _, err := superuserConn.Exec(ctx, `DROP VIEW zz_d50_view`); err != nil {
				t.Fatalf("cleanup zz_d50_view: %v", err)
			}
		})
		t.Run("unrelated_CREATE_and_DROP_TABLE", func(t *testing.T) {
			if _, err := superuserConn.Exec(ctx, `CREATE TABLE zz_d50_unrelated (id int)`); err != nil {
				t.Fatalf("unrelated CREATE TABLE should succeed under D50: %v", err)
			}
			if _, err := superuserConn.Exec(ctx, `DROP TABLE zz_d50_unrelated`); err != nil {
				t.Fatalf("unrelated DROP TABLE should succeed under D50: %v", err)
			}
		})
		t.Run("unrelated_CREATE_OR_REPLACE_FUNCTION", func(t *testing.T) {
			if _, err := superuserConn.Exec(ctx, `CREATE OR REPLACE FUNCTION zz_d50_fn() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$`); err != nil {
				t.Fatalf("unrelated CREATE OR REPLACE FUNCTION should succeed under D50: %v", err)
			}
			if _, err := superuserConn.Exec(ctx, `DROP FUNCTION zz_d50_fn()`); err != nil {
				t.Fatalf("cleanup zz_d50_fn: %v", err)
			}
		})
	})
}

// TestCreateIndexConcurrentlyWedgeIsSelfHealing is D50's residual
// (D58 test 2, R24): CREATE INDEX CONCURRENTLY on a protected relation
// still wedges -- it genuinely adds a definition, and refusing it is
// correct -- but the wedge is self-healing by DROP INDEX with no
// event-trigger disable and no re-provisioning. This is the property
// that keeps R24 an accepted residual rather than a second J-A. Run
// as the bootstrap superuser: CREATE INDEX CONCURRENTLY needs CREATE
// on schema public, which owl_ledger_ddl deliberately lacks (D41 part
// three) -- unreachable to owl_ledger_ddl is a separate, already-
// checked precondition, not what this test is about.
func TestCreateIndexConcurrentlyWedgeIsSelfHealing(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	conn, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer conn.Close(context.Background())

	_, err = conn.Exec(ctx, `CREATE INDEX CONCURRENTLY zz_d50_cic ON screening_ledger_anchor (anchored_at)`)
	if err == nil {
		t.Fatal("ADR-0007 Addendum 6 D50: expected CREATE INDEX CONCURRENTLY on a protected relation to be refused (it genuinely adds a definition)")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P0001" {
		t.Fatalf("expected SQLSTATE P0001, got %q: %v", pgErrorCode(err), err)
	}
	assertWedged(t, ctx, clone.superuserDSN, "zz_d50_cic_wedge_probe")

	// Self-healing: DROP INDEX clears it, with no event-trigger disable
	// and no re-provisioning -- the property R24 depends on.
	if _, err := conn.Exec(ctx, `DROP INDEX zz_d50_cic_ccnew`); err != nil {
		// PostgreSQL names the invalid partial index left behind by a
		// failed CONCURRENTLY build with a _ccnew suffix; fall back to
		// discovering the actual name if the server-version-specific
		// suffix ever changes, rather than hard-coding a second guess.
		var actual string
		lookupErr := conn.QueryRow(ctx, `
			SELECT c.relname FROM pg_class c
			JOIN pg_index ix ON ix.indexrelid = c.oid
			WHERE ix.indrelid = 'screening_ledger_anchor'::regclass AND NOT ix.indisvalid
		`).Scan(&actual)
		if lookupErr != nil {
			t.Fatalf("DROP INDEX zz_d50_cic_ccnew failed (%v) and could not discover the actual invalid index name: %v", err, lookupErr)
		}
		if _, err := conn.Exec(ctx, `DROP INDEX `+pgx.Identifier{actual}.Sanitize()); err != nil {
			t.Fatalf("DROP INDEX %s: %v", actual, err)
		}
	}
	assertHealthy(t, ctx, clone.superuserDSN, "zz_d50_cic_health_probe")
}
