// ADR-0007 Addendum 7 D65/D67 test 6 (K-F, LOW): pg_get_indexdef renders
// what an index IS, not whether it is IN FORCE -- CAP #6 §7.10's exact
// UPDATE pg_index left the anchor's primary key silently disabled with
// CheckProvisioningState still reporting Provisioned=true and a forged
// duplicate row insertable. indisvalid/indisready join the referent set
// beside D40's existing trigger-enablement branch. The tempting "filter
// invalid indexes out of the comparison" fix is REJECTED because an
// indisvalid=false, indisready=true index (a cancelled REINDEX ...
// CONCURRENTLY's own leftover, R24) still enforces uniqueness on writes
// -- filtering it out would hide a live, write-blocking object. This
// file reproduces CAP #6's exact UPDATE, proves the pre-D65 mechanism
// (both Go-side and the trigger function) misses it, proves the shipped
// mechanism catches it on both sides, proves every D50/D40/D34/D26 form
// -- including all five REINDEX ... CONCURRENTLY forms -- is unaffected,
// and proves the unit-level fact that refutes the filter design.
package screeningledger

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// preD65ProvisioningState reconstructs checkProvisioningState's shipped
// sequence with protectedRelationStateReason's D65 index-validity
// assertion omitted -- a faithful reconstruction of "what the check
// that shipped before this addendum would have concluded," per
// D42/D47's convention (the same pattern
// d51_maintain_revoke_pgx_test.go's preD51ProvisioningState uses).
func preD65ProvisioningState(t *testing.T, ctx context.Context, p *PostgresSink) ProvisioningState {
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
	// D65's own assertion, deliberately omitted: for each
	// requiredProtectedRelationStates entry, compare owner/kind/RLS/
	// triggers/index_defs/policies/identity ONLY -- the seven-plus-one
	// D47 columns, not the live indisvalid/indisready facts D65 adds.
	for _, want := range requiredProtectedRelationStates {
		var ownerOK, kindOK, rlsOK, forceRLSOK, triggersOK, indexesOK, policiesOK, identityOK bool
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
				r.policy_oids = ARRAY[]::oid[],
				r.identity = $1
			FROM sec7_protected_relation r
			WHERE (pg_identify_object('pg_class'::regclass, r.objid, 0)).identity = $1
		`, want.identity, want.relowner, want.relkind, want.relrowsecurity, want.relforcerowsecurity, want.triggerNames(), want.indexNames()).
			Scan(&ownerOK, &kindOK, &rlsOK, &forceRLSOK, &triggersOK, &indexesOK, &policiesOK, &identityOK)
		if err != nil {
			t.Fatalf("preD65ProvisioningState: %v", err)
		}
		if !ownerOK || !kindOK || !rlsOK || !forceRLSOK || !triggersOK || !indexesOK || !policiesOK || !identityOK {
			return ProvisioningState{Reason: "recorded state mismatch for " + want.identity}
		}
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

// preD65TriggerFunctionSQL is sec7_protect_ddl_objects() exactly as
// shipped by this addendum, with only the D65 index-validity IF block
// removed -- D63's evidence-ordered loop and D64's exception-guarded
// binding read are both left in place, since neither is what this test
// isolates. Installed on a disposable clone only, never on the primary
// database.
const preD65TriggerFunctionSQL = `
CREATE OR REPLACE FUNCTION sec7_protect_ddl_objects() RETURNS event_trigger LANGUAGE plpgsql
SECURITY DEFINER SET search_path = pg_catalog, public AS $BODY$
DECLARE
  obj record;
  rel record;
  cur_owner oid;
  cur_kind "char";
  cur_rls boolean;
  cur_force_rls boolean;
  cur_triggers oid[];
  cur_index_defs text[];
  cur_policies oid[];
  live_oid oid;
  rec_sysid bigint;
  rec_dboid oid;
  rec_dbname text;
  live_sysid bigint;
  live_dboid oid;
  live_dbname text;
  binding_readable boolean;
  binding_row_count integer;
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
    FOR rel IN SELECT * FROM sec7_protected_relation r2
      ORDER BY (EXISTS (SELECT 1 FROM pg_class c2 WHERE c2.oid = r2.objid)), r2.identity LOOP
      IF NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = rel.objid) THEN
        binding_readable := to_regclass('sec7_instance_binding') IS NOT NULL;
        IF binding_readable THEN
          BEGIN
            SELECT count(*) INTO binding_row_count FROM sec7_instance_binding;
            IF binding_row_count > 0 THEN
              SELECT b.system_identifier, b.database_oid, b.database_name
                INTO rec_sysid, rec_dboid, rec_dbname
                FROM sec7_instance_binding b LIMIT 1;
            END IF;
          EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION 'ADR-0007 Addendum 7 D64: protected relation "%" (registry objid %) no longer exists; the instance binding is present but could not be read, so whether this database is a copy cannot be determined -- investigate the sec7_instance_binding relation before re-provisioning', rel.identity, rel.objid;
          END;
        ELSE
          binding_row_count := 0;
        END IF;

        IF NOT binding_readable OR binding_row_count = 0 THEN
          RAISE EXCEPTION 'ADR-0007 Addendum 6 D54: protected relation "%" (registry objid %) no longer exists; the instance binding is absent or empty, so whether this database is a copy cannot be determined. If this is a fresh, never-provisioned database run scripts/ci/provision_test_roles.sh grant-ddl-ownership; otherwise investigate before doing so -- see docs/operations/sec7-database-copies.md', rel.identity, rel.objid;
        END IF;

        SELECT system_identifier INTO live_sysid FROM pg_control_system();
        SELECT d.oid, d.datname INTO live_dboid, live_dbname FROM pg_database d WHERE d.datname = current_database();

        IF rec_sysid IS DISTINCT FROM live_sysid OR rec_dboid IS DISTINCT FROM live_dboid THEN
          RAISE EXCEPTION 'ADR-0007 Addendum 5 D46: protected relation "%" (registry objid %) no longer exists. This database is a copy or restore of another (registry recorded instance %/% %; live instance %/% %). The SEC-7 registries hold raw OIDs and do not survive pg_dump/pg_restore. Recovery (ADR-0007 Addendum 6 D56): ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE; then scripts/ci/provision_test_roles.sh grant-ddl-ownership -- see docs/operations/sec7-database-copies.md', rel.identity, rel.objid, rec_sysid, rec_dboid, rec_dbname, live_sysid, live_dboid, live_dbname;
        END IF;

        SELECT c.oid INTO live_oid
          FROM pg_class c
         WHERE (pg_identify_object('pg_class'::regclass, c.oid, 0)).identity = rel.identity;

        IF live_oid IS NULL THEN
          RAISE EXCEPTION 'ADR-0007 Addendum 5 D46: protected relation "%" (registry objid %) no longer exists and no relation of that name is present', rel.identity, rel.objid;
        END IF;

        RAISE EXCEPTION 'ADR-0007 Addendum 5 D46: protected relation "%" (registry objid %) no longer exists; "%" is present with objid % -- the relation was dropped and recreated in place. Re-run grant-ddl-ownership.', rel.identity, rel.objid, rel.identity, live_oid;
      END IF;
      SELECT c.relowner, c.relkind, c.relrowsecurity, c.relforcerowsecurity
        INTO cur_owner, cur_kind, cur_rls, cur_force_rls
        FROM pg_class c WHERE c.oid = rel.objid;
      IF cur_owner IS DISTINCT FROM rel.relowner THEN
        RAISE EXCEPTION 'ADR-0007 Addendum 4 D40: protected relation "%" (objid %): its owner changed', rel.identity, rel.objid;
      END IF;
      IF cur_kind IS DISTINCT FROM rel.relkind THEN
        RAISE EXCEPTION 'ADR-0007 Addendum 4 D40: protected relation "%" (objid %): its relkind changed', rel.identity, rel.objid;
      END IF;
      IF cur_rls IS DISTINCT FROM rel.relrowsecurity OR cur_force_rls IS DISTINCT FROM rel.relforcerowsecurity THEN
        RAISE EXCEPTION 'ADR-0007 Addendum 4 D40: protected relation "%" (objid %): its row-level-security flags changed', rel.identity, rel.objid;
      END IF;
      IF EXISTS (SELECT 1 FROM pg_rewrite r WHERE r.ev_class = rel.objid) THEN
        RAISE EXCEPTION 'ADR-0007 Addendum 4 D40: protected relation "%" (objid %): a rewrite RULE exists on it', rel.identity, rel.objid;
      END IF;
      IF EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhparent = rel.objid OR i.inhrelid = rel.objid) THEN
        RAISE EXCEPTION 'ADR-0007 Addendum 4 D40: protected relation "%" (objid %): an inheritance child is attached (or it has itself been attached as a child)', rel.identity, rel.objid;
      END IF;
      SELECT COALESCE(array_agg(t.oid ORDER BY t.oid), ARRAY[]::oid[]) INTO cur_triggers
        FROM pg_trigger t WHERE t.tgrelid = rel.objid AND NOT t.tgisinternal;
      IF cur_triggers IS DISTINCT FROM rel.trigger_oids THEN
        RAISE EXCEPTION 'ADR-0007 Addendum 4 D40: protected relation "%" (objid %): its trigger set changed', rel.identity, rel.objid;
      END IF;
      SELECT COALESCE(array_agg(pg_get_indexdef(ix.indexrelid) ORDER BY pg_get_indexdef(ix.indexrelid)), ARRAY[]::text[]) INTO cur_index_defs
        FROM pg_index ix WHERE ix.indrelid = rel.objid;
      IF cur_index_defs IS DISTINCT FROM rel.index_defs THEN
        RAISE EXCEPTION 'ADR-0007 Addendum 6 D50: protected relation "%" (objid %): its index set changed', rel.identity, rel.objid;
      END IF;
      SELECT COALESCE(array_agg(p.oid ORDER BY p.oid), ARRAY[]::oid[]) INTO cur_policies
        FROM pg_policy p WHERE p.polrelid = rel.objid;
      IF cur_policies IS DISTINCT FROM rel.policy_oids THEN
        RAISE EXCEPTION 'ADR-0007 Addendum 4 D40: protected relation "%" (objid %): its RLS policy set changed', rel.identity, rel.objid;
      END IF;
      IF EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid = rel.objid AND NOT t.tgisinternal AND t.tgenabled <> 'O') THEN
        RAISE EXCEPTION 'ADR-0007 Addendum 4 D40: protected relation "%" (objid %): one of its triggers is not ENABLE (tgenabled <> ''O'')', rel.identity, rel.objid;
      END IF;
      -- ADR-0007 Addendum 7 D65's own IF block deliberately omitted here.
    END LOOP;
  END IF;
END;
$BODY$;
`

func installPreD65TriggerFunction(t *testing.T, ctx context.Context, superuser *pgx.Conn) {
	t.Helper()
	withD34TriggersDisabled(t, ctx, superuser, func() {
		if _, err := superuser.Exec(ctx, preD65TriggerFunctionSQL); err != nil {
			t.Fatalf("install pre-D65 sec7_protect_ddl_objects(): %v", err)
		}
	})
}

// d65InvalidatePrimaryKey reproduces CAP #6 §7.10's exact UPDATE: the
// anchor's primary key is invalidated and un-readied directly via
// catalog DML (invisible to the DDL event triggers, which fire on DDL
// statements, not on DML against pg_index).
func d65InvalidatePrimaryKey(t *testing.T, ctx context.Context, superuser *pgx.Conn) {
	t.Helper()
	if _, err := superuser.Exec(ctx, `UPDATE pg_index SET indisvalid=false, indisready=false WHERE indexrelid = 'screening_ledger_anchor_pkey'::regclass`); err != nil {
		t.Fatalf("invalidate screening_ledger_anchor_pkey: %v", err)
	}
}

func TestD65IndexValidityIsAssertedAndConcurrentRebuildStillSucceeds(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	t.Run("pre-D65 mechanism misses it on both sides", func(t *testing.T) {
		clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
		superuser, err := pgx.Connect(ctx, clone.superuserDSN)
		if err != nil {
			t.Fatalf("connect as bootstrap superuser: %v", err)
		}
		defer superuser.Close(context.Background())

		installPreD65TriggerFunction(t, ctx, superuser)
		d65InvalidatePrimaryKey(t, ctx, superuser)

		// Go-side: the pre-D65 reconstruction still reads Provisioned=true.
		cloneMigratorDSN := withDatabase(t, migratorDSN, clone.dbName)
		sink, err := NewPostgresSink(ctx, cloneMigratorDSN, 10*time.Second)
		if err != nil {
			t.Fatalf("NewPostgresSink: %v", err)
		}
		defer sink.Close(context.Background())
		pre := preD65ProvisioningState(t, ctx, sink)
		if !pre.Provisioned {
			t.Fatalf("ADR-0007 Addendum 7 D65: the pre-D65 reconstruction should still read Provisioned=true with the primary key invalidated -- that is the gap this addendum closes (Reason=%q)", pre.Reason)
		}

		// Trigger-side: an unrelated DDL statement still succeeds.
		assertHealthy(t, ctx, clone.superuserDSN, "zz_d65_pre_healthy_probe")

		// The forged duplicate itself: the anchor's writer can now
		// insert a second row at the same (ledger_id, sequence).
		anchorConn, err := pgx.Connect(ctx, clone.ledgerDDLDSN)
		if err != nil {
			t.Fatalf("connect as owl_ledger_ddl: %v", err)
		}
		defer anchorConn.Close(context.Background())
		if _, err := anchorConn.Exec(ctx, `
			INSERT INTO screening_ledger_anchor (ledger_id, sequence, event_sha256, audit_sha256, audit_sequence, policy_sha256, anchored_at, anchor_mac)
			VALUES
			  ('zz-d65-ledger', 1, repeat('a',64), repeat('a',64), 0, repeat('a',64), now(), repeat('a',64)),
			  ('zz-d65-ledger', 1, repeat('b',64), repeat('b',64), 0, repeat('b',64), now(), repeat('b',64))
		`); err != nil {
			t.Fatalf("ADR-0007 Addendum 7 D65: expected the forged duplicate to be insertable with the primary key invalidated, got: %v", err)
		}
		var dupCount int
		if err := superuser.QueryRow(ctx, `SELECT count(*) FROM screening_ledger_anchor WHERE ledger_id='zz-d65-ledger' AND sequence=1`).Scan(&dupCount); err != nil {
			t.Fatalf("count forged duplicate rows: %v", err)
		}
		if dupCount != 2 {
			t.Fatalf("expected 2 forged duplicate rows at (zz-d65-ledger, 1), got %d", dupCount)
		}
	})

	t.Run("shipped mechanism catches it on both sides", func(t *testing.T) {
		clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
		superuser, err := pgx.Connect(ctx, clone.superuserDSN)
		if err != nil {
			t.Fatalf("connect as bootstrap superuser: %v", err)
		}
		defer superuser.Close(context.Background())

		withD34TriggersDisabled(t, ctx, superuser, func() {
			d65InvalidatePrimaryKey(t, ctx, superuser)
		})

		// Trigger-side: an unrelated DDL statement is now refused.
		_, ddlErr := superuser.Exec(ctx, `CREATE TABLE zz_d65_probe (id int)`)
		if ddlErr == nil {
			t.Fatal("ADR-0007 Addendum 7 D65: unrelated DDL succeeded with the anchor's primary key invalidated")
		}
		if !strings.Contains(ddlErr.Error(), "D65") || !strings.Contains(ddlErr.Error(), "screening_ledger_anchor") {
			t.Fatalf("expected the D65 diagnostic naming the anchor relation, got: %v", ddlErr)
		}

		// Go-side: CheckProvisioningState now names the same fact.
		cloneMigratorDSN := withDatabase(t, migratorDSN, clone.dbName)
		sink, err := NewPostgresSink(ctx, cloneMigratorDSN, 10*time.Second)
		if err != nil {
			t.Fatalf("NewPostgresSink: %v", err)
		}
		defer sink.Close(context.Background())
		state, err := sink.CheckProvisioningState(ctx)
		if err != nil {
			t.Fatalf("CheckProvisioningState: %v", err)
		}
		if state.Provisioned {
			t.Fatal("ADR-0007 Addendum 7 D65: CheckProvisioningState reported Provisioned=true with the anchor's primary key invalidated")
		}
		if !strings.Contains(state.Reason, "D65") {
			t.Fatalf("expected a reason citing D65, got: %q", state.Reason)
		}
	})

	// D50's own preservation: every REINDEX ... CONCURRENTLY form still
	// completes and leaves the database healthy -- the branch must not
	// fire transiently during a legitimate rebuild, or it would
	// re-introduce J-A.
	t.Run("REINDEX CONCURRENTLY forms stay healthy", func(t *testing.T) {
		forms := []struct {
			name string
			sql  string
		}{
			{"REINDEX_INDEX_CONCURRENTLY_anchor_pkey", `REINDEX INDEX CONCURRENTLY screening_ledger_anchor_pkey`},
			{"REINDEX_TABLE_CONCURRENTLY_anchor", `REINDEX TABLE CONCURRENTLY screening_ledger_anchor`},
			{"REINDEX_TABLE_CONCURRENTLY_tombstone", `REINDEX TABLE CONCURRENTLY screening_ledger_retention_tombstone`},
			{"REINDEX_SCHEMA_CONCURRENTLY_public", `REINDEX SCHEMA CONCURRENTLY public`},
			{"REINDEX_DATABASE_CONCURRENTLY", `REINDEX DATABASE CONCURRENTLY ` + "CURRENT_DATABASE_PLACEHOLDER"},
		}
		for _, f := range forms {
			t.Run(f.name, func(t *testing.T) {
				clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
				superuser, err := pgx.Connect(ctx, clone.superuserDSN)
				if err != nil {
					t.Fatalf("connect as bootstrap superuser: %v", err)
				}
				defer superuser.Close(context.Background())

				sql := f.sql
				if strings.Contains(sql, "CURRENT_DATABASE_PLACEHOLDER") {
					sql = `REINDEX DATABASE CONCURRENTLY ` + pgx.Identifier{clone.dbName}.Sanitize()
				}
				if _, err := superuser.Exec(ctx, sql); err != nil {
					t.Fatalf("%s: %v (D65 must not fire transiently during a legitimate CONCURRENTLY rebuild)", f.name, err)
				}
				assertHealthy(t, ctx, clone.superuserDSN, "zz_d65_reindex_healthy_probe")
			})
		}
	})

	// The unit-level fact that refutes the filter design: an
	// indisvalid=false, indisready=true index (a cancelled
	// REINDEX ... CONCURRENTLY's own leftover shape) still rejects a
	// duplicate at the DML layer, on an ordinary lab table isolated from
	// every SEC-7 control.
	t.Run("indisvalid false indisready true still enforces uniqueness", func(t *testing.T) {
		clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
		superuser, err := pgx.Connect(ctx, clone.superuserDSN)
		if err != nil {
			t.Fatalf("connect as bootstrap superuser: %v", err)
		}
		defer superuser.Close(context.Background())

		if _, err := superuser.Exec(ctx, `CREATE TABLE zz_d65_lab (id int)`); err != nil {
			t.Fatalf("create lab table: %v", err)
		}
		if _, err := superuser.Exec(ctx, `CREATE UNIQUE INDEX zz_d65_lab_ix ON zz_d65_lab (id)`); err != nil {
			t.Fatalf("create unique index: %v", err)
		}
		if _, err := superuser.Exec(ctx, `INSERT INTO zz_d65_lab VALUES (1)`); err != nil {
			t.Fatalf("seed row: %v", err)
		}
		if _, err := superuser.Exec(ctx, `UPDATE pg_index SET indisvalid=false WHERE indexrelid = 'zz_d65_lab_ix'::regclass`); err != nil {
			t.Fatalf("set indisvalid=false: %v", err)
		}
		_, dupErr := superuser.Exec(ctx, `INSERT INTO zz_d65_lab VALUES (1)`)
		if dupErr == nil {
			t.Fatal("ADR-0007 Addendum 7 D65: an indisvalid=false, indisready=true unique index failed to reject a duplicate -- the fact that refutes the validity-filter design")
		}
		t.Logf("confirmed: indisvalid=false, indisready=true still rejects a duplicate: %v", dupErr)
	})
}
