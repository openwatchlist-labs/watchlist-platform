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
  echo "usage: $0 {create-roles|grant-app-privileges|grant-ddl-ownership|create-stale-anchor-database|create-unprovisioned-database|create-schemasql-only-database}" >&2
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
  # ADR-0007 Addendum 3 D35 (G-E): this step used to briefly GRANT
  # owl_ledger_ddl TO owl_migrator before ALTER TABLE ... OWNER TO, then
  # REVOKE it -- a window CAP #2 §7.9 showed is cluster-wide (Postgres
  # role membership is not per-database) and survives any failure between
  # the GRANT and the REVOKE (an ALTER TABLE error, a SIGINT, a cancelled
  # CI step), leaving owl_migrator privileged on every OTHER database in
  # the cluster too, including ones the failed run never touched. The
  # membership was never necessary: ALTER TABLE ... OWNER TO requires the
  # executing role to be able to SET ROLE to the new owner only when that
  # role is NOT a superuser, and this script always connects as the
  # bootstrap superuser (psql_super, INFRA-3's PGSUPERUSER) -- confirmed
  # by execution during this addendum's design pass. D35's decision is to
  # remove the GRANT/REVOKE pair entirely rather than narrow the window:
  # "do not close the hole, remove the thing that opens it." A
  # non-membership precondition runs first (immediately below), not last,
  # so a dangling membership left by an older script version, an
  # interrupted run, or a manual grant is refused rather than silently
  # inherited -- the existing postcondition later in this step stays
  # where it is; this is an addition, checking the same property on both
  # edges.
  already_member="$(psql_super -tAc "SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles mm ON mm.oid = m.member WHERE r.rolname = 'owl_ledger_ddl' AND mm.rolname = 'owl_migrator'")"
  [[ -z "$already_member" ]] || {
    echo "FAIL: owl_migrator is already a member of owl_ledger_ddl before this step ran (ADR-0007 Addendum 3 D35/G-E) -- an older script version, an interrupted run, or a manual grant left this membership; a superuser must REVOKE owl_ledger_ddl FROM owl_migrator before re-running this step" >&2
    exit 1
  }
  table_exists="$(psql_super -tAc "SELECT 1 FROM pg_class WHERE relname = 'screening_ledger_anchor'")"
  [[ "$table_exists" == "1" ]] || {
    echo "FAIL: screening_ledger_anchor does not exist; run db/migrations/015_screening_ledger_anchor.sql first" >&2
    exit 1
  }
  # Guarded on current ownership, not run unconditionally: once D26/D34's
  # event trigger exists (below), it blocks every ALTER TABLE against
  # this relation by design -- including a superuser's, which is the
  # whole point -- so a second invocation of this subcommand (a retried
  # CI step, an operator re-running provisioning) must not attempt this
  # ALTER TABLE again once ownership has already moved. Same "guard on
  # current state" form D21 established, applied here to a script rather
  # than to Migrate(). D35: no GRANT/REVOKE of role membership surrounds
  # this -- see above.
  anchor_owner_before="$(psql_super -tAc "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE relname = 'screening_ledger_anchor'")"
  if [[ "$anchor_owner_before" != "owl_ledger_ddl" ]]; then
    psql_super -c "ALTER TABLE screening_ledger_anchor OWNER TO owl_ledger_ddl;"
  fi
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
  # ADR-0007 Addendum 3 D34 registers both overloads below as protected
  # objects, so -- exactly like the two ALTER TABLE OWNER TO statements
  # above -- these must be guarded on current ownership rather than run
  # unconditionally: ALTER FUNCTION ... OWNER TO fires ddl_command_end
  # with a real objid even when the new owner equals the current one (a
  # true no-op is not exempt), confirmed by execution during this
  # addendum's design pass, so an unconditional re-run would trip D34's
  # own event trigger on the second and every subsequent invocation of
  # this script.
  func1_owner_before="$(psql_super -tAc "SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE proname='screening_ledger_purge_snapshots' AND pg_get_function_identity_arguments(oid)='p_before timestamp with time zone, p_operator text, p_reason text'")"
  if [[ "$func1_owner_before" != "owl_ledger_ddl" ]]; then
    psql_super -c "ALTER FUNCTION screening_ledger_purge_snapshots(timestamptz,text,text) OWNER TO owl_ledger_ddl;"
  fi
  func2_owner_before="$(psql_super -tAc "SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE proname='screening_ledger_purge_snapshots' AND pg_get_function_identity_arguments(oid)='p_snapshot_sha256 text[], p_before timestamp with time zone, p_operator text, p_reason text'")"
  if [[ "$func2_owner_before" != "owl_ledger_ddl" ]]; then
    psql_super -c "ALTER FUNCTION screening_ledger_purge_snapshots(text[],timestamptz,text,text) OWNER TO owl_ledger_ddl;"
  fi
  # The definer functions run as owl_ledger_ddl regardless of caller
  # (SECURITY DEFINER), so their INSERT into screening_ledger_retention_
  # tombstone needs nothing further (owl_ledger_ddl now owns that table),
  # but their UPDATE of screening_ledger_snapshot -- still owned by
  # owl_migrator, unaffected by this step -- needs an explicit grant, or
  # the function body itself would fail with insufficient privilege the
  # first time either form actually runs.
  psql_super -c "GRANT SELECT, UPDATE ON screening_ledger_snapshot TO owl_ledger_ddl;"
  # ADR-0007 Addendum 3 D32: both overloads' predicate now reads
  # screening_ledger_event.expires_at (joined through
  # request_snapshot_sha256/response_snapshot_sha256) instead of trusting
  # screening_ledger_snapshot.expires_at alone -- owl_ledger_ddl needs
  # SELECT on that table too, or the definer function itself fails with
  # insufficient privilege the first time either form actually runs.
  psql_super -c "GRANT SELECT ON screening_ledger_event TO owl_ledger_ddl;"
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
  # ADR-0007 Addendum 3 D33: ownership of both overloads is now asserted
  # here too, not only reported -- the provisioning completion condition
  # D33 names, checked at the point that installs it rather than left to
  # Migrate()'s deliberately ownership-blind schema check alone.
  func1_owner="$(psql_super -tAc "SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE proname='screening_ledger_purge_snapshots' AND pg_get_function_identity_arguments(oid)='p_before timestamp with time zone, p_operator text, p_reason text'")"
  [[ "$func1_owner" == "owl_ledger_ddl" ]] || {
    echo "FAIL: screening_ledger_purge_snapshots(timestamptz,text,text) owner is '$func1_owner', expected owl_ledger_ddl" >&2
    exit 1
  }
  func2_owner="$(psql_super -tAc "SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE proname='screening_ledger_purge_snapshots' AND pg_get_function_identity_arguments(oid)='p_snapshot_sha256 text[], p_before timestamp with time zone, p_operator text, p_reason text'")"
  [[ "$func2_owner" == "owl_ledger_ddl" ]] || {
    echo "FAIL: screening_ledger_purge_snapshots(text[],timestamptz,text,text) owner is '$func2_owner', expected owl_ledger_ddl" >&2
    exit 1
  }
  echo "PASS: screening_ledger_retention_tombstone and both screening_ledger_purge_snapshots overloads owned by owl_ledger_ddl (SECURITY DEFINER); owl_migrator lost table DML, gained EXECUTE only"

  # ADR-0007 Addendum 3 D34 (G-B, G-D, G-G): D26's event trigger scoped
  # itself twice -- WHEN TAG on the trigger, object_identity string
  # comparison in the function body -- and CAP #2 walked past both scopings:
  # DROP OWNED BY carries command tag "DROP OWNED", outside the sql_drop
  # trigger's WHEN TAG list, so it destroyed both protected tables with no
  # DDL the trigger watched at all (G-B); CREATE OR REPLACE FUNCTION
  # carries tag "CREATE FUNCTION", which neither trigger watches, letting
  # owl_migrator -- which still owns the shared guard functions every
  # row-immutability trigger on all eight protected tables calls -- neuter
  # them outright (G-D); and ALTER TABLE ... RENAME TO changes
  # object_identity but not the object's OID, so the identity-string
  # comparison missed it (G-G). D31's replacement principle, verified by
  # execution during this addendum's design pass rather than assumed: scope
  # by the protected object's OID (stable across RENAME TO and SET SCHEMA,
  # unlike object_identity) and remove the WHEN TAG filters entirely, so
  # the trigger sees every DDL statement rather than a chosen few.
  #
  # A regclass/regprocedure cast INSIDE the trigger cannot resolve a
  # dropped object -- by the time sql_drop fires, the catalog entry is
  # already gone (confirmed by execution: "ERROR: relation ... does not
  # exist" from exactly this cast, run inside a sql_drop function body
  # during this addendum's design pass). The protected set therefore has
  # to be a REAL RELATION, its rows resolved to OIDs once, here, while the
  # objects still exist -- not re-resolved by name inside the trigger.
  #
  # sec7_protected_object is itself in its own protected set (last row
  # below), so the registry cannot be dropped without tripping the sql_drop
  # trigger either (R15: a registry is a new trust object, and a stale one
  # -- an OID that no longer resolves to the object it names -- fails
  # open; D33's requiredProvisioningState is what is required to close
  # that, by asserting every fact this step installs, not by this registry
  # alone).
  psql_super -c "CREATE TABLE IF NOT EXISTS sec7_protected_object (objid oid PRIMARY KEY, note text NOT NULL);"
  # ADR-0007 Addendum 4 D40/D41 bootstrapping: on a database this step
  # already ran on before this addendum, sec7_protected_object is
  # already a protected object (last row of its own previous
  # population), so the ALTER TABLE ADD COLUMN below -- and every
  # statement in this step that touches either registry or the two
  # protected tables -- would trip D34's own event trigger before this
  # step ever reaches the point where it (re)installs that trigger.
  # Dropped here, at the top, rather than only immediately before
  # CREATE EVENT TRIGGER as originally structured: this step already ran
  # with protection down for its whole remaining duration on every prior
  # execution (the triggers are always created LAST, after every table/
  # function/registry statement above them), so widening that existing
  # window to cover the registry changes above is not a new exposure,
  # only a longer version of the one this idempotent, superuser-only
  # script has always had. A no-op on a true first run, where neither
  # trigger exists yet.
  psql_super -c "DROP EVENT TRIGGER IF EXISTS sec7_protect_ddl_objects_on_drop;"
  psql_super -c "DROP EVENT TRIGGER IF EXISTS sec7_protect_ddl_objects_on_alter;"
  # ADR-0007 Addendum 4 D41: classid records which system catalog each
  # row's OID belongs to, so the row's claim becomes a machine-comparable
  # identity (pg_identify_object(classid, objid, 0)) rather than a prose
  # note that is never compared to anything -- R15's stated closure
  # ("resolves to the object it claims") was never actually checked
  # before this. ADD COLUMN IF NOT EXISTS: idempotent against a database
  # this step already ran on before this addendum.
  psql_super -c "ALTER TABLE sec7_protected_object ADD COLUMN IF NOT EXISTS classid oid;"
  psql_super -c "REVOKE ALL ON sec7_protected_object FROM PUBLIC;"
  psql_super -c "GRANT SELECT ON sec7_protected_object TO owl_migrator;"
  # ADR-0007 Addendum 4 D40: sec7_protected_relation, a second
  # superuser-owned registry, one row per protected RELATION (as opposed
  # to sec7_protected_object's one row per protected OBJECT of any kind)
  # -- recording the facts sec7_protect_ddl_objects()'s second phase
  # re-asserts after every DDL statement: owner, kind, both RLS flags,
  # and the non-internal trigger/index/policy OID sets. Created before
  # sec7_protected_object is (re)populated below, since this table's own
  # OID is itself one of sec7_protected_object's rows.
  psql_super -c "
    CREATE TABLE IF NOT EXISTS sec7_protected_relation (
      objid oid PRIMARY KEY,
      relowner oid NOT NULL,
      relkind \"char\" NOT NULL,
      relrowsecurity boolean NOT NULL,
      relforcerowsecurity boolean NOT NULL,
      trigger_oids oid[] NOT NULL,
      index_oids oid[] NOT NULL,
      policy_oids oid[] NOT NULL
    );
  "
  psql_super -c "REVOKE ALL ON sec7_protected_relation FROM PUBLIC;"
  psql_super -c "GRANT SELECT ON sec7_protected_relation TO owl_migrator;"
  # DML, not DDL -- unaffected by the event triggers below regardless of
  # their own installation state, so re-populating on every invocation of
  # this step is safe and keeps both registries from drifting if this
  # script is ever edited to protect a different object/relation set.
  psql_super -c "DELETE FROM sec7_protected_relation;"
  psql_super -c "
    INSERT INTO sec7_protected_relation (objid, relowner, relkind, relrowsecurity, relforcerowsecurity, trigger_oids, index_oids, policy_oids)
    SELECT c.oid, c.relowner, c.relkind, c.relrowsecurity, c.relforcerowsecurity,
      COALESCE((SELECT array_agg(t.oid ORDER BY t.oid) FROM pg_trigger t WHERE t.tgrelid = c.oid AND NOT t.tgisinternal), ARRAY[]::oid[]),
      COALESCE((SELECT array_agg(ix.indexrelid ORDER BY ix.indexrelid) FROM pg_index ix WHERE ix.indrelid = c.oid), ARRAY[]::oid[]),
      COALESCE((SELECT array_agg(p.oid ORDER BY p.oid) FROM pg_policy p WHERE p.polrelid = c.oid), ARRAY[]::oid[])
    FROM pg_class c
    WHERE c.oid IN ('screening_ledger_anchor'::regclass::oid, 'screening_ledger_retention_tombstone'::regclass::oid);
  "
  protected_relation_row_count="$(psql_super -tAc "SELECT count(*) FROM sec7_protected_relation")"
  [[ "$protected_relation_row_count" == "2" ]] || {
    echo "FAIL: expected 2 rows in sec7_protected_relation, found $protected_relation_row_count" >&2
    exit 1
  }
  psql_super -c "DELETE FROM sec7_protected_object;"
  psql_super -c "
    INSERT INTO sec7_protected_object (objid, classid, note) VALUES
      ('screening_ledger_anchor'::regclass::oid, 'pg_class'::regclass::oid, 'table: screening_ledger_anchor'),
      ('screening_ledger_retention_tombstone'::regclass::oid, 'pg_class'::regclass::oid, 'table: screening_ledger_retention_tombstone'),
      ((SELECT oid FROM pg_trigger WHERE tgname='screening_ledger_anchor_immutable' AND tgrelid='screening_ledger_anchor'::regclass), 'pg_trigger'::regclass::oid, 'trigger: screening_ledger_anchor_immutable'),
      ((SELECT oid FROM pg_trigger WHERE tgname='screening_ledger_anchor_no_truncate' AND tgrelid='screening_ledger_anchor'::regclass), 'pg_trigger'::regclass::oid, 'trigger: screening_ledger_anchor_no_truncate'),
      ((SELECT oid FROM pg_trigger WHERE tgname='screening_ledger_retention_tombstone_immutable' AND tgrelid='screening_ledger_retention_tombstone'::regclass), 'pg_trigger'::regclass::oid, 'trigger: screening_ledger_retention_tombstone_immutable'),
      ((SELECT oid FROM pg_trigger WHERE tgname='screening_ledger_retention_tombstone_no_truncate' AND tgrelid='screening_ledger_retention_tombstone'::regclass), 'pg_trigger'::regclass::oid, 'trigger: screening_ledger_retention_tombstone_no_truncate'),
      ('screening_ledger_reject_mutation()'::regprocedure::oid, 'pg_proc'::regclass::oid, 'function: screening_ledger_reject_mutation (G-D: the shared row-immutability guard every one of the eight protected tables'' trigger calls)'),
      ('owl_reject_truncate()'::regprocedure::oid, 'pg_proc'::regclass::oid, 'function: owl_reject_truncate (G-D: the shared TRUNCATE guard every one of the eight protected tables'' trigger calls)'),
      ('screening_ledger_purge_snapshots(timestamptz,text,text)'::regprocedure::oid, 'pg_proc'::regclass::oid, 'function: screening_ledger_purge_snapshots(timestamptz,text,text) (D27''s retention control -- D34 extends protection to it since G-B showed the owner can destroy it wholesale via DROP OWNED BY)'),
      ('screening_ledger_purge_snapshots(text[],timestamptz,text,text)'::regprocedure::oid, 'pg_proc'::regclass::oid, 'function: screening_ledger_purge_snapshots(text[],timestamptz,text,text)'),
      ('sec7_protected_object'::regclass::oid, 'pg_class'::regclass::oid, 'table: sec7_protected_object (the registry itself)'),
      ('sec7_protected_relation'::regclass::oid, 'pg_class'::regclass::oid, 'table: sec7_protected_relation (ADR-0007 Addendum 4 D40''s second registry)')
    ;
  "
  psql_super -c "ALTER TABLE sec7_protected_object ALTER COLUMN classid SET NOT NULL;"
  registry_row_count="$(psql_super -tAc "SELECT count(*) FROM sec7_protected_object")"
  [[ "$registry_row_count" == "12" ]] || {
    echo "FAIL: expected 12 rows in sec7_protected_object, found $registry_row_count" >&2
    exit 1
  }
  # sec7_protect_ddl_objects() becomes SECURITY DEFINER -- load-bearing,
  # not hygiene, confirmed by execution: an INVOKER-rights version (the
  # default) failed an UNRELATED CREATE TABLE with "permission denied for
  # table sec7_protected_object" during this addendum's design pass,
  # because the function's own SELECT on the registry then ran as the
  # invoking (non-superuser) role, which this step never grants read
  # access to the registry. That is D26's own "database-wide blast
  # radius" risk realized -- every DDL statement in the database would
  # have started failing, and it would have shipped. SET search_path
  # matters for the same reason D27's definer functions need it: an
  # unqualified reference to sec7_protected_object inside a definer body
  # would otherwise resolve against the CALLER's search_path.
  psql_super -c "
    CREATE OR REPLACE FUNCTION sec7_protect_ddl_objects() RETURNS event_trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, public AS \$\$
    DECLARE
      obj record;
      rel record;
      cur_owner oid;
      cur_kind \"char\";
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
        -- ADR-0007 Addendum 4 D40: the objid membership check above
        -- answers 'was the reported object itself in the protected
        -- set?' -- which is the wrong question for CREATE RULE (reports
        -- the rule, not the table), inheritance attachment (reports the
        -- child, not the parent), CREATE TRIGGER/INDEX/POLICY (reports
        -- the new trigger/index/policy, not the table they attach to),
        -- and every future object type that attaches to a protected
        -- relation while reporting something else. This second phase
        -- asks a different question, of every protected relation, on
        -- every ddl_command_end firing regardless of what it reported:
        -- does this relation still match the state recorded for it at
        -- provisioning time? ddl_command_end fires for DROP commands
        -- too (confirmed by execution), so this also covers drop-shaped
        -- attacks on a relation's attachments (e.g. DROP of an
        -- unrelated object that happens to leave a dangling rule) that
        -- the sql_drop phase's objid check would miss for any object
        -- not individually registered.
        FOR rel IN SELECT * FROM sec7_protected_relation LOOP
          IF NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = rel.objid) THEN
            RAISE EXCEPTION 'ADR-0007 Addendum 4 D40: protected relation (objid %) no longer exists', rel.objid;
          END IF;
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
    \$\$;
  "
  # No WHEN TAG clause on either trigger -- D31's principle applied: the
  # protected set is closed, small, and resolved by OID above; the set of
  # DDL statement forms is open and enumerating it is what failed twice
  # (G-B, G-D). Confirmed by execution that an unfiltered sql_drop trigger
  # DOES see DROP OWNED BY's cascaded drops, with real OIDs and object_type
  # per dropped object, and that GRANT/REVOKE report objid=NULL (so they
  # are never accidentally caught by the objid membership check above,
  # regardless of unfiltering) -- both confirmed during this addendum's
  # design pass. Created only now, after db/migrations/ and every ALTER
  # TABLE/ALTER FUNCTION OWNER TO above have already run, so none of this
  # step's own DDL is caught by its own trigger.
  psql_super -c "CREATE EVENT TRIGGER sec7_protect_ddl_objects_on_drop ON sql_drop EXECUTE FUNCTION sec7_protect_ddl_objects();"
  psql_super -c "CREATE EVENT TRIGGER sec7_protect_ddl_objects_on_alter ON ddl_command_end EXECUTE FUNCTION sec7_protect_ddl_objects();"
  # ENABLE ALWAYS so this also fires under session_replication_role =
  # 'replica' -- that GUC is SUSET and already unreachable to these
  # non-superuser roles, but this removes the question rather than
  # leaving it to be re-derived (D26's own stated reasoning, unchanged).
  psql_super -c "ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop ENABLE ALWAYS;"
  psql_super -c "ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter ENABLE ALWAYS;"
  event_trigger_count="$(psql_super -tAc "SELECT count(*) FROM pg_event_trigger WHERE evtname IN ('sec7_protect_ddl_objects_on_drop','sec7_protect_ddl_objects_on_alter') AND evtenabled = 'A'")"
  [[ "$event_trigger_count" == "2" ]] || {
    echo "FAIL: expected both D34 event triggers to exist and be ENABLE ALWAYS ('A'), found $event_trigger_count" >&2
    exit 1
  }
  protect_fn_definer="$(psql_super -tAc "SELECT prosecdef FROM pg_proc WHERE proname='sec7_protect_ddl_objects'")"
  [[ "$protect_fn_definer" == "t" ]] || {
    echo "FAIL: sec7_protect_ddl_objects() is not SECURITY DEFINER -- an invoker-rights version breaks every unrelated DDL statement in the database (ADR-0007 Addendum 3 D34)" >&2
    exit 1
  }
  echo "PASS: D34 object-scoped (OID-keyed, unfiltered) DDL event triggers installed and ENABLE ALWAYS, protecting screening_ledger_anchor, screening_ledger_retention_tombstone, their guard triggers, the shared row-immutability/TRUNCATE guard functions, both screening_ledger_purge_snapshots overloads, and both registries from any DDL statement by any non-superuser role, owner included; D40's second phase (sec7_protected_relation, 2 rows) re-asserts owner/kind/RLS-flags/rules/inheritance/trigger-index-policy-OID-sets after every DDL statement"
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
create-unprovisioned-database)
  # ADR-0007 Addendum 3 D33/D37 (G-A): CAP #2 §7.5's owl_p4 state --
  # db/migrations/ applied in FULL, but grant-ddl-ownership never run --
  # is a distinct degraded state from create-stale-anchor-database above
  # (which is a MISSING migration; this is a missing PROVISIONING step,
  # with no migration absent at all). It cannot be reproduced against
  # owl_ci for the same reason the stale-schema database cannot: this
  # step above already ran there. A third, disposable database, owned by
  # owl_migrator from creation so every migration can run in full against
  # it and ownership of the protected tables stays with owl_migrator
  # (grant-ddl-ownership is never run against this database, by
  # construction), is what lets Migrate()'s and VerifyAnchored's real
  # code paths run against a genuinely unprovisioned-but-fully-migrated
  # schema.
  psql_super -c "DROP DATABASE IF EXISTS owl_ci_sec7_unprovisioned;"
  psql_super -c "CREATE DATABASE owl_ci_sec7_unprovisioned OWNER owl_migrator;"
  echo "PASS: owl_ci_sec7_unprovisioned created, owned by owl_migrator (ADR-0007 Addendum 3 D33/G-A unprovisioned-schema fixture)"
  ;;
create-schemasql-only-database)
  # SEC-2 followup (Sprint 0 register reconciliation): the gate blind spot
  # this fixture closes is that scripts/ci/check_sql_invariants.sh's
  # generic TRUNCATE-guard invariant only ever ran against owl_ci, a
  # database db/migrations/ (including 012_truncate_guards.sql) has
  # always applied to in full before this database's rows are ever
  # queried -- so it could never have caught a package's own SchemaSQL
  # const (Migrate(), called with zero dependency on db/migrations/ ever
  # having run -- the same REL-9-adjacent shape ADR-0007 D3/D15 already
  # found once in screeningledger's own SchemaSQL) independently lagging
  # behind 012's table list, which is exactly what happened to
  # internal/alertcase and internal/assistancerag.
  #
  # A fourth disposable database, owned by owl_migrator from creation and
  # with NO migration ever applied to it -- unlike
  # create-stale-anchor-database (some migrations applied) and
  # create-unprovisioned-database (every migration applied) above, this
  # one has none -- is what lets internal/schemasqlgate's suite call each
  # package's Migrate()/SchemaSQL directly and observe the database that
  # bootstrap path alone actually produces.
  psql_super -c "DROP DATABASE IF EXISTS owl_ci_schemasql_only;"
  psql_super -c "CREATE DATABASE owl_ci_schemasql_only OWNER owl_migrator;"
  echo "PASS: owl_ci_schemasql_only created, owned by owl_migrator, no migrations applied (SEC-2 followup SchemaSQL-only-bootstrap fixture)"
  ;;
*)
  usage
  ;;
esac
