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
  echo "usage: $0 {create-roles|grant-app-privileges|grant-anchor-ownership}" >&2
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
  # grant-anchor-ownership below, after the migration that creates the
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
grant-anchor-ownership)
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
  psql_super -c "GRANT owl_ledger_ddl TO owl_migrator;"
  psql_super -c "ALTER TABLE screening_ledger_anchor OWNER TO owl_ledger_ddl;"
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
  ;;
*)
  usage
  ;;
esac
