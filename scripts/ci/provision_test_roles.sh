#!/usr/bin/env bash
# Provisions the non-superuser Postgres roles this repository's ADRs
# require for CI: owl_migrator (DDL/backfill, used by Migrate and
# db/migrations/, ADR-0001 SEC-1 §3 "Roles and DSNs"), owl_app (the
# identity every sink DSN uses, never BYPASSRLS, subject to FORCE ROW
# LEVEL SECURITY, same section), owl_ledger_anchor (the SEC-7 D3
# anchor-writing identity, ADR-0007 §5.3 -- distinct from owl_migrator,
# the screening-ledger writer, by construction), and owl_ledger_ddl
# (ADR-0007 Addendum 1 D17/F6 -- the anchor table's OWNER, so that
# owl_ledger_anchor, the role that actually writes at runtime, cannot
# ALTER or DROP the table's own protections; nothing connects as
# owl_ledger_ddl outside this script and the migration that transfers
# ownership to it).
#
# No role is created by a migration ("No migration contains CREATE ROLE
# or GRANT", docs/adr/0001-tenant-isolation.md:208), so this lives in CI
# provisioning instead. ADR-0007 did not originally reconcile
# owl_ledger_anchor's ownership-transfer/membership-drop sequence with
# that rule -- see the correction note added to ADR-0007 §5.3. This
# script connects as the bootstrap superuser INFRA-3 already provisions
# (PGSUPERUSER), which is the only identity in this pipeline allowed to
# be a superuser.
set -euo pipefail

usage() {
  echo "usage: $0 {create-roles|grant-app-privileges|grant-ddl-ownership|create-stale-anchor-database}" >&2
  exit 1
}
[[ $# -eq 1 ]] || usage

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

: "${PGHOST:=localhost}"
: "${PGPORT:=5432}"
: "${PGDATABASE:=owl_ci}"
: "${PGSUPERUSER:=owl_ci}"
: "${PGSUPERPASSWORD:=owl_ci}"
: "${OWL_MIGRATOR_PASSWORD:=owl_migrator}"
: "${OWL_APP_PASSWORD:=owl_app}"
: "${OWL_LEDGER_ANCHOR_PASSWORD:=owl_ledger_anchor}"
: "${OWL_LEDGER_DDL_PASSWORD:=owl_ledger_ddl}"

export PGPASSWORD="$PGSUPERPASSWORD"
psql_super() {
  psql -h "$PGHOST" -p "$PGPORT" -U "$PGSUPERUSER" -d "$PGDATABASE" -X -q -v ON_ERROR_STOP=1 "$@"
}

create_role() {
  local role="$1" password="$2"
  local exists
  exists="$(psql_super -tAc "SELECT 1 FROM pg_roles WHERE rolname = '${role}'")"
  if [[ "$exists" == "1" ]]; then
    psql_super -c "ALTER ROLE ${role} WITH LOGIN PASSWORD '${password}' NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS;"
  else
    psql_super -c "CREATE ROLE ${role} WITH LOGIN PASSWORD '${password}' NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS;"
  fi
}

case "$1" in
create-roles)
  create_role owl_migrator "$OWL_MIGRATOR_PASSWORD"
  create_role owl_app "$OWL_APP_PASSWORD"
  create_role owl_ledger_anchor "$OWL_LEDGER_ANCHOR_PASSWORD"
  create_role owl_ledger_ddl "$OWL_LEDGER_DDL_PASSWORD"
  # owl_migrator runs every statement in db/migrations/ (CREATE TABLE,
  # CREATE TRIGGER, CREATE POLICY, ALTER TABLE ... FORCE ROW LEVEL
  # SECURITY), which needs CREATE on the target schema. Postgres 15+ no
  # longer grants that to PUBLIC by default.
  psql_super -c "GRANT ALL ON SCHEMA public TO owl_migrator;"
  psql_super -c "GRANT USAGE ON SCHEMA public TO owl_app;"
  # owl_ledger_anchor and owl_ledger_ddl get no schema-level grant here --
  # neither creates relations directly (owl_ledger_ddl only ever receives
  # ownership of an already-created table below; nothing connects as it
  # at runtime, ADR-0007 Addendum 1 D17). Their privileges on
  # screening_ledger_anchor specifically are conferred by
  # grant-ddl-ownership below, after the migration that creates the
  # table has run.
  echo "PASS: owl_migrator, owl_app, owl_ledger_anchor, and owl_ledger_ddl provisioned (NOSUPERUSER NOBYPASSRLS)"
  ;;
grant-app-privileges)
  # Runs after db/migrations/ has created the tenant-scoped relations
  # (owned by owl_migrator, since it ran the CREATE TABLE statements).
  # owl_app gets DML only, never ownership. FORCE ROW LEVEL SECURITY
  # exists specifically to close the table-owner RLS bypass; a granted,
  # non-owning role like owl_app is already fully subject to policy
  # without depending on that mechanism, which keeps the migrator/app
  # privilege boundary unambiguous.
  #
  # Reads db/tenant_scoped_tables.txt -- the single source of truth
  # (ADR §3 point 1) -- directly, instead of re-enumerating relations
  # here, per the "never enumerate targets by inference" trap.
  TABLES_FILE="$ROOT/db/tenant_scoped_tables.txt"
  [[ -f "$TABLES_FILE" ]] || {
    echo "FAIL: missing $TABLES_FILE" >&2
    exit 1
  }
  count=0
  while IFS= read -r raw; do
    line="${raw%%#*}"
    line="$(echo -n "$line" | tr -d '[:space:]')"
    [[ -z "$line" ]] && continue
    psql_super -c "GRANT SELECT, INSERT, UPDATE, DELETE ON ${line} TO owl_app;"
    count=$((count + 1))
  done <"$TABLES_FILE"
  [[ "$count" -gt 0 ]] || {
    echo "FAIL: no tables read from $TABLES_FILE" >&2
    exit 1
  }
  # security_control_suspension (db/migrations/014_tenant_isolation.sql)
  # is not tenant-scoped, so it is deliberately outside the loop above --
  # but SQL invariant 5 (test/sql/security_invariants.sql, "no open
  # security_control_suspension row") runs as owl_app via
  # OWL_TEST_DATABASE_URL, and needs to read it. SELECT only: writing a
  # suspension row is db/rollback/014_tenant_isolation_down.sql's job, run
  # as owl_migrator, never as owl_app.
  psql_super -c "GRANT SELECT ON security_control_suspension TO owl_app;"
  echo "PASS: granted owl_app DML on $count tenant-scoped relation(s), SELECT on security_control_suspension"
  ;;
grant-ddl-ownership)
  # Renamed from grant-anchor-ownership (ADR-0007 Addendum 2 D27: "the
  # provisioning step... is renamed... to reflect that it now covers two
  # relations rather than one") -- screening_ledger_anchor (D17/F6) and,
  # below, screening_ledger_retention_tombstone (D27/F-D).
  #
  # ADR-0007 Addendum 1 D17/F6: screening_ledger_anchor must not be
  # owned by the role that writes to it at runtime. The original design
  # made owl_ledger_anchor (the writer) also the owner, which meant the
  # writer could ALTER TABLE ... DISABLE TRIGGER or DROP the table's own
  # protections at will -- F6 found this makes the anchor prove nothing
  # beyond the chain MAC it exists to stand outside of. The fix adds a
  # third role, owl_ledger_ddl, that owns the table and connects as
  # nothing at runtime; owl_ledger_anchor becomes INSERT-only, not owner;
  # owl_migrator (the screening-ledger CLI's DDL identity) stays
  # SELECT-only, as before. Run once, after db/migrations/015_screening_
  # ledger_anchor.sql has created the table (owl_migrator owns it at that
  # point, having run the CREATE TABLE) and 017_screening_ledger_anchor_
  # policy_binding.sql has added the policy_sha256/audit_sequence columns.
  #
  # owl_migrator briefly holds membership in owl_ledger_ddl so the
  # subsequent REVOKE is a real membership drop, not a vacuous one, and
  # to mirror ADR-0007's specification of this as a deliberate,
  # structurally one-time action rather than a policy convention: without
  # a fresh superuser session, nothing in this schema can put owl_migrator
  # back in a position to own screening_ledger_anchor.
  table_exists="$(psql_super -tAc "SELECT 1 FROM pg_class WHERE relname = 'screening_ledger_anchor'")"
  [[ "$table_exists" == "1" ]] || {
    echo "FAIL: screening_ledger_anchor does not exist; run db/migrations/015_screening_ledger_anchor.sql first" >&2
    exit 1
  }
  # Guarded on current ownership, not run unconditionally: once D26's
  # event trigger exists (below), it blocks every ALTER TABLE against
  # this relation by design -- including a superuser's, which is the
  # whole point -- so a second invocation of this subcommand (a retried
  # CI step, an operator re-running provisioning) must not attempt this
  # ALTER TABLE again once ownership has already moved. Same "guard on
  # current state" form D21 established, applied here to a script rather
  # than to Migrate().
  anchor_owner_before="$(psql_super -tAc "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE relname = 'screening_ledger_anchor'")"
  if [[ "$anchor_owner_before" != "owl_ledger_ddl" ]]; then
    psql_super -c "GRANT owl_ledger_ddl TO owl_migrator;"
    psql_super -c "ALTER TABLE screening_ledger_anchor OWNER TO owl_ledger_ddl;"
  fi
  # REVOKE runs unconditionally, even when the GRANT/ALTER above were
  # skipped as already-done: REVOKE on a membership that does not exist
  # is a harmless no-op (a WARNING, not an error, confirmed against a
  # live server), and this is what makes a partially-completed prior run
  # (GRANT+ALTER succeeded, REVOKE not yet reached) self-heal on retry
  # instead of leaving owl_migrator's membership dangling.
  psql_super -c "REVOKE owl_ledger_ddl FROM owl_migrator;"
  # owl_ledger_anchor (the runtime writer) gets INSERT only -- never
  # ownership, never SELECT/UPDATE/DELETE, never DDL. This is the
  # privilege set ADR-0007 §5.3 point 2 and anchor.go's doc comment
  # always claimed for it; D17 is what makes the claim true.
  psql_super -c "GRANT INSERT ON screening_ledger_anchor TO owl_ledger_anchor;"
  # SEC-7 Stage 3 (D3's remaining "Verify() becomes anchor-aware" half,
  # ADR-0007 §5.3 point 4): the screening-ledger CLI already connects as
  # owl_migrator for DDL purposes (PostgresSink's doc comment,
  # postgres.go:23-34); granting SELECT on the anchor table completes its
  # privilege set for verification without introducing owl_app or a new
  # runtime role into a path neither currently touches. owl_app is
  # deliberately left with nothing on this table: it is not tenant-scoped,
  # and giving it access here would be the first crack in the seam SEC-1
  # spent two days making precise. owl_migrator gets SELECT only --
  # ownership stays with owl_ledger_ddl, so this grant cannot be used to
  # alter or drop the table's own protections.
  psql_super -c "GRANT SELECT ON screening_ledger_anchor TO owl_migrator;"
  # Prove all postconditions rather than assuming the statements above
  # did what they say -- the same standard CLAUDE.md's schema-guard rule
  # applies to any control that could look installed and do nothing. This
  # now also proves what F6 found the script previously could NOT
  # express: that owl_ledger_anchor -- the runtime writer -- cannot
  # UPDATE or DELETE and is not the table's owner.
  owner="$(psql_super -tAc "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE relname = 'screening_ledger_anchor'")"
  [[ "$owner" == "owl_ledger_ddl" ]] || {
    echo "FAIL: screening_ledger_anchor owner is '$owner', expected owl_ledger_ddl" >&2
    exit 1
  }
  still_member="$(psql_super -tAc "SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles mm ON mm.oid = m.member WHERE r.rolname = 'owl_ledger_ddl' AND mm.rolname = 'owl_migrator'")"
  [[ -z "$still_member" ]] || {
    echo "FAIL: owl_migrator is still a member of owl_ledger_ddl after REVOKE" >&2
    exit 1
  }
  can_select="$(psql_super -tAc "SELECT has_table_privilege('owl_migrator', 'screening_ledger_anchor', 'SELECT')")"
  [[ "$can_select" == "t" ]] || {
    echo "FAIL: owl_migrator lacks SELECT on screening_ledger_anchor" >&2
    exit 1
  }
  can_insert_migrator="$(psql_super -tAc "SELECT has_table_privilege('owl_migrator', 'screening_ledger_anchor', 'INSERT')")"
  [[ "$can_insert_migrator" == "f" ]] || {
    echo "FAIL: owl_migrator has INSERT on screening_ledger_anchor; it must be read-only there" >&2
    exit 1
  }
  can_insert_anchor="$(psql_super -tAc "SELECT has_table_privilege('owl_ledger_anchor', 'screening_ledger_anchor', 'INSERT')")"
  [[ "$can_insert_anchor" == "t" ]] || {
    echo "FAIL: owl_ledger_anchor lacks INSERT on screening_ledger_anchor" >&2
    exit 1
  }
  anchor_can_select="$(psql_super -tAc "SELECT has_table_privilege('owl_ledger_anchor', 'screening_ledger_anchor', 'SELECT')")"
  [[ "$anchor_can_select" == "f" ]] || {
    echo "FAIL: owl_ledger_anchor has SELECT on screening_ledger_anchor; it must be INSERT-only" >&2
    exit 1
  }
  anchor_can_update="$(psql_super -tAc "SELECT has_table_privilege('owl_ledger_anchor', 'screening_ledger_anchor', 'UPDATE')")"
  [[ "$anchor_can_update" == "f" ]] || {
    echo "FAIL: owl_ledger_anchor has UPDATE on screening_ledger_anchor; it must be INSERT-only (F6)" >&2
    exit 1
  }
  anchor_can_delete="$(psql_super -tAc "SELECT has_table_privilege('owl_ledger_anchor', 'screening_ledger_anchor', 'DELETE')")"
  [[ "$anchor_can_delete" == "f" ]] || {
    echo "FAIL: owl_ledger_anchor has DELETE on screening_ledger_anchor; it must be INSERT-only (F6)" >&2
    exit 1
  }
  anchor_is_owner="$(psql_super -tAc "SELECT 1 FROM pg_class WHERE relname = 'screening_ledger_anchor' AND relowner = 'owl_ledger_anchor'::regrole")"
  [[ -z "$anchor_is_owner" ]] || {
    echo "FAIL: owl_ledger_anchor owns screening_ledger_anchor; ownership must belong to owl_ledger_ddl (F6)" >&2
    exit 1
  }
  echo "PASS: screening_ledger_anchor owned by owl_ledger_ddl; owl_ledger_anchor is INSERT-only and not owner; owl_migrator's DDL membership dropped and it has SELECT-only"

  # ADR-0007 Addendum 2 D27 (F-D, MEDIUM): screening_ledger_retention_
  # tombstone and both screening_ledger_purge_snapshots overloads
  # (db/migrations/019_screening_ledger_purge_definer.sql) move to
  # owl_ledger_ddl -- the role D17 already introduced, no fifth role. This
  # closes the tombstone-forgery gap the CAP demonstrated: owl_migrator
  # owned this table and held unrestricted INSERT, so it could record a
  # tombstone for a snapshot never actually purged. Run once, after 019
  # has run (owl_migrator owns both functions and the table at that
  # point, having created them).
  table_exists="$(psql_super -tAc "SELECT 1 FROM pg_class WHERE relname = 'screening_ledger_retention_tombstone'")"
  [[ "$table_exists" == "1" ]] || {
    echo "FAIL: screening_ledger_retention_tombstone does not exist; run db/migrations/008g_screening_ledger.sql first" >&2
    exit 1
  }
  # Same guard as the anchor table above, same reason: once D26's event
  # trigger below exists, it blocks every ALTER TABLE against this
  # relation too, for anyone including a superuser.
  tombstone_owner_before="$(psql_super -tAc "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE relname = 'screening_ledger_retention_tombstone'")"
  if [[ "$tombstone_owner_before" != "owl_ledger_ddl" ]]; then
    psql_super -c "ALTER TABLE screening_ledger_retention_tombstone OWNER TO owl_ledger_ddl;"
  fi
  psql_super -c "ALTER FUNCTION screening_ledger_purge_snapshots(timestamptz,text,text) OWNER TO owl_ledger_ddl;"
  psql_super -c "ALTER FUNCTION screening_ledger_purge_snapshots(text[],timestamptz,text,text) OWNER TO owl_ledger_ddl;"
  # The definer functions run as owl_ledger_ddl regardless of caller
  # (SECURITY DEFINER), so their INSERT into screening_ledger_retention_
  # tombstone needs nothing further (owl_ledger_ddl now owns that table),
  # but their UPDATE of screening_ledger_snapshot -- still owned by
  # owl_migrator, unaffected by this step -- needs an explicit grant, or
  # the function body itself would fail with insufficient privilege the
  # first time either form actually runs.
  psql_super -c "GRANT SELECT, UPDATE ON screening_ledger_snapshot TO owl_ledger_ddl;"
  # owl_migrator keeps SELECT on the tombstone table -- IsPurgeRecorded
  # (postgres.go, ADR-0007 D13/F8) reads it as owl_migrator to check
  # whether a snapshot's purge is independently recorded. It does NOT get
  # INSERT/UPDATE/DELETE/TRUNCATE back, and it is no longer the owner, so
  # this is a read-only grant, exactly parallel to owl_migrator's
  # SELECT-only privilege on screening_ledger_anchor above.
  psql_super -c "GRANT SELECT ON screening_ledger_retention_tombstone TO owl_migrator;"
  # owl_migrator loses INSERT/UPDATE/DELETE and ownership on the
  # tombstone table (the CAP's exact forgery path) and gains only EXECUTE
  # on both functions, plus the SELECT it already needs for
  # IsPurgeRecorded (postgres.go). REVOKE EXECUTE FROM PUBLIC first:
  # Postgres grants EXECUTE on a new function to PUBLIC by default, which
  # would otherwise leave every role -- not just owl_migrator -- able to
  # invoke a SECURITY DEFINER function without this script's explicit
  # decision to grant it.
  psql_super -c "REVOKE EXECUTE ON FUNCTION screening_ledger_purge_snapshots(timestamptz,text,text) FROM PUBLIC;"
  psql_super -c "REVOKE EXECUTE ON FUNCTION screening_ledger_purge_snapshots(text[],timestamptz,text,text) FROM PUBLIC;"
  psql_super -c "GRANT EXECUTE ON FUNCTION screening_ledger_purge_snapshots(timestamptz,text,text) TO owl_migrator;"
  psql_super -c "GRANT EXECUTE ON FUNCTION screening_ledger_purge_snapshots(text[],timestamptz,text,text) TO owl_migrator;"
  tombstone_owner="$(psql_super -tAc "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE relname = 'screening_ledger_retention_tombstone'")"
  [[ "$tombstone_owner" == "owl_ledger_ddl" ]] || {
    echo "FAIL: screening_ledger_retention_tombstone owner is '$tombstone_owner', expected owl_ledger_ddl" >&2
    exit 1
  }
  tombstone_can_insert="$(psql_super -tAc "SELECT has_table_privilege('owl_migrator', 'screening_ledger_retention_tombstone', 'INSERT')")"
  [[ "$tombstone_can_insert" == "f" ]] || {
    echo "FAIL: owl_migrator has INSERT on screening_ledger_retention_tombstone; the CAP's forgery path is still open (D27)" >&2
    exit 1
  }
  func1_definer="$(psql_super -tAc "SELECT prosecdef FROM pg_proc WHERE proname='screening_ledger_purge_snapshots' AND pg_get_function_identity_arguments(oid)='p_before timestamp with time zone, p_operator text, p_reason text'")"
  [[ "$func1_definer" == "t" ]] || {
    echo "FAIL: screening_ledger_purge_snapshots(timestamptz,text,text) is not SECURITY DEFINER (prosecdef)" >&2
    exit 1
  }
  func2_definer="$(psql_super -tAc "SELECT prosecdef FROM pg_proc WHERE proname='screening_ledger_purge_snapshots' AND pg_get_function_identity_arguments(oid)='p_snapshot_sha256 text[], p_before timestamp with time zone, p_operator text, p_reason text'")"
  [[ "$func2_definer" == "t" ]] || {
    echo "FAIL: screening_ledger_purge_snapshots(text[],timestamptz,text,text) is not SECURITY DEFINER (prosecdef)" >&2
    exit 1
  }
  echo "PASS: screening_ledger_retention_tombstone and both screening_ledger_purge_snapshots overloads owned by owl_ledger_ddl (SECURITY DEFINER); owl_migrator lost table DML, gained EXECUTE only"

  # ADR-0007 Addendum 2 D26 (F-F, HIGH -- the highest-risk item in this
  # addendum): CAP §9 framed the residual as possibly unclosable, on the
  # premise that a table owner can always drop that table's triggers.
  # True about ownership, incomplete about PostgreSQL: event triggers are
  # not owner-scoped. CREATE EVENT TRIGGER requires superuser; the
  # resulting trigger fires for every non-superuser role including the
  # protected table's own owner; no non-superuser can disable it. Every
  # role in this cluster is NOSUPERUSER (create_role above), including
  # owl_ledger_ddl -- so this is the first control in this schema a
  # migration cannot install, and it must be provisioned here, by the
  # bootstrap superuser, after the anchor and tombstone tables exist and
  # after ownership of both has transferred (all true at this point in
  # this case).
  #
  # This design does not get to assert D26 works (its own stated
  # standard). It is discharged only by
  # internal/screeningledger/ddl_event_trigger_pgx_test.go reproducing
  # CAP §7.3's exact five-form attack sequence against a real Postgres,
  # every attempt blocked, SQLSTATE captured rather than inferred.
  psql_super -c "
    CREATE OR REPLACE FUNCTION sec7_protect_ddl_objects() RETURNS event_trigger LANGUAGE plpgsql AS \$\$
    DECLARE
      obj record;
      -- D26's own text names screening_ledger_retention_tombstone and
      -- its own two triggers here explicitly, not the
      -- screening_ledger_purge_snapshots functions, which stay within
      -- owl_ledger_ddl's own authority to alter -- the same role D27
      -- moves trust to, not a residual this event trigger claims to
      -- close.
      protected_tables text[] := ARRAY['public.screening_ledger_anchor', 'public.screening_ledger_retention_tombstone'];
      protected_trigger_identities text[] := ARRAY[
        'screening_ledger_anchor_immutable on public.screening_ledger_anchor',
        'screening_ledger_anchor_no_truncate on public.screening_ledger_anchor',
        'screening_ledger_retention_tombstone_immutable on public.screening_ledger_retention_tombstone',
        'screening_ledger_retention_tombstone_no_truncate on public.screening_ledger_retention_tombstone'
      ];
    BEGIN
      IF TG_EVENT = 'sql_drop' THEN
        FOR obj IN SELECT * FROM pg_event_trigger_dropped_objects() LOOP
          IF (obj.object_type = 'table' AND obj.object_identity = ANY(protected_tables))
             OR (obj.object_type = 'trigger' AND obj.object_identity = ANY(protected_trigger_identities)) THEN
            RAISE EXCEPTION 'ADR-0007 Addendum 2 D26: % is protected by a superuser-only DDL event trigger and cannot be dropped', obj.object_identity;
          END IF;
        END LOOP;
      ELSIF TG_EVENT = 'ddl_command_end' THEN
        FOR obj IN SELECT * FROM pg_event_trigger_ddl_commands() LOOP
          IF obj.object_type = 'table' AND obj.object_identity = ANY(protected_tables) THEN
            RAISE EXCEPTION 'ADR-0007 Addendum 2 D26: % is protected by a superuser-only DDL event trigger; ALTER TABLE is not permitted', obj.object_identity;
          END IF;
        END LOOP;
      END IF;
    END;
    \$\$;
  "
  psql_super -c "DROP EVENT TRIGGER IF EXISTS sec7_protect_ddl_objects_on_drop;"
  psql_super -c "DROP EVENT TRIGGER IF EXISTS sec7_protect_ddl_objects_on_alter;"
  # Scoped by WHEN TAG to the specific DROP forms and to ALTER TABLE only
  # -- narrower than "every DDL statement in the database" -- and by
  # object identity inside the function body to exactly the anchor table
  # and its two guard triggers, per D26's "narrowly scoped by object
  # identity" requirement. Created only now, after db/migrations/ and
  # grant-ddl-ownership above have both already run, so 017's own
  # ALTER TABLE / DROP TRIGGER IF EXISTS statements and this step's own
  # ALTER TABLE OWNER TO above are unaffected.
  psql_super -c "CREATE EVENT TRIGGER sec7_protect_ddl_objects_on_drop ON sql_drop WHEN TAG IN ('DROP TABLE', 'DROP TRIGGER') EXECUTE FUNCTION sec7_protect_ddl_objects();"
  psql_super -c "CREATE EVENT TRIGGER sec7_protect_ddl_objects_on_alter ON ddl_command_end WHEN TAG IN ('ALTER TABLE') EXECUTE FUNCTION sec7_protect_ddl_objects();"
  # ENABLE ALWAYS so this also fires under session_replication_role =
  # 'replica' -- that GUC is SUSET and already unreachable to these
  # non-superuser roles, but this removes the question rather than
  # leaving it to be re-derived (D26's own stated reasoning).
  psql_super -c "ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop ENABLE ALWAYS;"
  psql_super -c "ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter ENABLE ALWAYS;"
  event_trigger_count="$(psql_super -tAc "SELECT count(*) FROM pg_event_trigger WHERE evtname IN ('sec7_protect_ddl_objects_on_drop','sec7_protect_ddl_objects_on_alter') AND evtenabled = 'A'")"
  [[ "$event_trigger_count" == "2" ]] || {
    echo "FAIL: expected both D26 event triggers to exist and be ENABLE ALWAYS ('A'), found $event_trigger_count" >&2
    exit 1
  }
  echo "PASS: D26 DDL event triggers installed and ENABLE ALWAYS, protecting screening_ledger_anchor, screening_ledger_retention_tombstone, and their guard triggers from DROP/ALTER TABLE by any non-superuser role, owner included"
  ;;
create-stale-anchor-database)
  # ADR-0007 Addendum 2 D21/D22 (F-E, CRITICAL): the committed regression
  # for "Migrate() reports success on a database migrated through 015 but
  # not 017, leaving the anchor table mutable" needs a real Postgres in
  # exactly that state -- CAP §7.6's own method. It cannot be reproduced
  # against owl_ci (the primary CI database): db/migrations/ always runs
  # there in full, and after grant-ddl-ownership above, owl_migrator no
  # longer owns screening_ledger_anchor and cannot manipulate its schema
  # to simulate staleness -- nor should a shared database other tests
  # depend on be put into a deliberately incomplete state.
  #
  # A second, disposable database, owned by owl_migrator from creation (so
  # db/migrations/ up to and including 015/016 can be applied against it
  # exactly as normal, and screening_ledger_anchor stays owl_migrator-owned
  # there -- grant-ddl-ownership is never run against this database),
  # is the minimal isolation that lets the real Migrate() and LatestAnchor
  # code paths run against genuinely stale schema, with no risk to the
  # primary database other pgx suites in this package depend on
  # concurrently (Go test packages run in parallel by default; this
  # database is never touched by any other suite).
  psql_super -c "DROP DATABASE IF EXISTS owl_ci_sec7_stale;"
  psql_super -c "CREATE DATABASE owl_ci_sec7_stale OWNER owl_migrator;"
  echo "PASS: owl_ci_sec7_stale created, owned by owl_migrator (ADR-0007 Addendum 2 D21/D22 stale-schema fixture)"
  ;;
*)
  usage
  ;;
esac
