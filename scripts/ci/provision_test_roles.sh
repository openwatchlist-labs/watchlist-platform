#!/usr/bin/env bash
# Provisions the two non-superuser Postgres roles ADR-0001 SEC-1 §3
# "Roles and DSNs" requires for CI: owl_migrator (DDL/backfill, used by
# Migrate and db/migrations/) and owl_app (the identity every sink DSN
# uses, never BYPASSRLS, subject to FORCE ROW LEVEL SECURITY).
#
# Neither role is created by a migration ("No migration contains CREATE
# ROLE or GRANT"), so this lives in CI provisioning instead. It connects
# as the bootstrap superuser INFRA-3 already provisions (PGSUPERUSER),
# which is the only identity in this pipeline allowed to be a superuser.
set -euo pipefail

usage() {
  echo "usage: $0 {create-roles|grant-app-privileges}" >&2
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
  # owl_migrator runs every statement in db/migrations/ (CREATE TABLE,
  # CREATE TRIGGER, CREATE POLICY, ALTER TABLE ... FORCE ROW LEVEL
  # SECURITY), which needs CREATE on the target schema. Postgres 15+ no
  # longer grants that to PUBLIC by default.
  psql_super -c "GRANT ALL ON SCHEMA public TO owl_migrator;"
  psql_super -c "GRANT USAGE ON SCHEMA public TO owl_app;"
  echo "PASS: owl_migrator and owl_app provisioned (NOSUPERUSER NOBYPASSRLS)"
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
  echo "PASS: granted owl_app DML on $count tenant-scoped relation(s)"
  ;;
*)
  usage
  ;;
esac
