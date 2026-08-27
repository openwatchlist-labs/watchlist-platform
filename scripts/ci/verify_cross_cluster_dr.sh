#!/usr/bin/env bash
# ADR-0007 Addendum 7 D66/D67 test 7: executes the corrected
# cross-cluster DR procedure end to end against a genuinely SECOND,
# disposable PostgreSQL 17 cluster -- not the docker-service primary
# every other CI step in this repository uses -- proving D66's decision
# (the four owl_* roles created on the target cluster BEFORE the
# restore, create-roles directed at an un-restored database, every
# snippet carrying real connection parameters) actually completes with
# zero errors, per docs/operations/sec7-database-copies.md's "Before you
# clone production into staging" section. CAP #6 found the document's
# previously-shipped procedure could not be completed as written (81
# role-does-not-exist errors on an unprepared target cluster); this
# script is the "tested, not described" proof D67 requires, run on a
# second real cluster rather than falling back to the weaker
# roles-before-restore-only scripted check D67's own withdrawal
# condition would otherwise permit.
#
# Requires PG_BIN_DIR to point at a PostgreSQL 17 server installation
# (initdb, pg_ctl, postgres, psql) distinct from the primary database
# this repository's other CI steps use -- .github/workflows/ci.yml and
# release-qualification.yml install postgresql-17 (the server package,
# not merely postgresql-client-17) for exactly this purpose.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

: "${PG_BIN_DIR:=/usr/lib/postgresql/17/bin}"
: "${PRIMARY_PGHOST:=localhost}"
: "${PRIMARY_PGPORT:=5432}"
: "${PRIMARY_PGSUPERUSER:=owl_ci}"
: "${PRIMARY_PGSUPERPASSWORD:=owl_ci}"
: "${PRIMARY_PGDATABASE:=owl_ci}"

for bin in initdb pg_ctl postgres psql pg_isready; do
  [[ -x "$PG_BIN_DIR/$bin" ]] || {
    echo "FAIL: $PG_BIN_DIR/$bin not found or not executable -- PG_BIN_DIR must point at a PostgreSQL 17 SERVER installation (postgresql-17, not only postgresql-client-17)" >&2
    exit 1
  }
done

DR_PORT="${DR_PORT:-55499}"
DR_DATA_DIR="$(mktemp -d)"
DR_SOCK_DIR="$(mktemp -d)"
DR_LOG="$(mktemp)"
DR_ERR_TMP="$(mktemp)"

cleanup() {
  "$PG_BIN_DIR/pg_ctl" -D "$DR_DATA_DIR" -m fast stop >/dev/null 2>&1 || true
  rm -rf "$DR_DATA_DIR" "$DR_SOCK_DIR"
  rm -f "$DR_ERR_TMP"
}
trap cleanup EXIT

echo "== D66: initializing a second, disposable PostgreSQL 17 cluster on port $DR_PORT =="
"$PG_BIN_DIR/initdb" -D "$DR_DATA_DIR" -U "$PRIMARY_PGSUPERUSER" --auth=trust -E UTF8 >/dev/null
"$PG_BIN_DIR/pg_ctl" -D "$DR_DATA_DIR" -l "$DR_LOG" -o "-p $DR_PORT -k $DR_SOCK_DIR" start
ready=0
for _ in $(seq 1 30); do
  if "$PG_BIN_DIR/pg_isready" -h "$DR_SOCK_DIR" -p "$DR_PORT" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.5
done
[[ "$ready" == "1" ]] || {
  echo "FAIL: the second cluster did not become ready within 15s; log:" >&2
  cat "$DR_LOG" >&2
  exit 1
}
PGPASSWORD= "$PG_BIN_DIR/psql" -h "$DR_SOCK_DIR" -p "$DR_PORT" -U "$PRIMARY_PGSUPERUSER" -d postgres \
  -c "ALTER USER $PRIMARY_PGSUPERUSER WITH PASSWORD '$PRIMARY_PGSUPERPASSWORD';" >/dev/null
PGPASSWORD="$PRIMARY_PGSUPERPASSWORD" "$PG_BIN_DIR/psql" -h localhost -p "$DR_PORT" -U "$PRIMARY_PGSUPERUSER" -d postgres \
  -c "CREATE DATABASE owl_dr2;" >/dev/null

echo "== D66 step 1: create-roles on the TARGET cluster, PGDATABASE=postgres, BEFORE the restore =="
PGHOST=localhost PGPORT="$DR_PORT" PGDATABASE=postgres \
  PGSUPERUSER="$PRIMARY_PGSUPERUSER" PGSUPERPASSWORD="$PRIMARY_PGSUPERPASSWORD" \
  OWL_MIGRATOR_PASSWORD=owl_migrator OWL_APP_PASSWORD=owl_app \
  OWL_LEDGER_ANCHOR_PASSWORD=owl_ledger_anchor OWL_LEDGER_DDL_PASSWORD=owl_ledger_ddl \
  ./scripts/ci/provision_test_roles.sh create-roles

echo "== D66 step 2: pg_dump the primary | psql into the target cluster (0 errors expected) =="
PGPASSWORD="$PRIMARY_PGSUPERPASSWORD" pg_dump -h "$PRIMARY_PGHOST" -p "$PRIMARY_PGPORT" -U "$PRIMARY_PGSUPERUSER" -d "$PRIMARY_PGDATABASE" \
  | PGPASSWORD="$PRIMARY_PGSUPERPASSWORD" "$PG_BIN_DIR/psql" -h localhost -p "$DR_PORT" -U "$PRIMARY_PGSUPERUSER" -d owl_dr2 -v ON_ERROR_STOP=1 >/dev/null

echo "== D66: confirming the restore is genuinely bricked (Addendum 5 D46) =="
if PGPASSWORD="$PRIMARY_PGSUPERPASSWORD" "$PG_BIN_DIR/psql" -h localhost -p "$DR_PORT" -U "$PRIMARY_PGSUPERUSER" -d owl_dr2 \
  -c "CREATE TABLE zz_d66_probe(id int)" >/dev/null 2>"$DR_ERR_TMP"; then
  echo "FAIL: an unrelated CREATE TABLE succeeded against the freshly restored database -- expected the D46 refusal" >&2
  exit 1
fi
grep -q "Addendum 5 D46" "$DR_ERR_TMP" || {
  echo "FAIL: expected the D46 copy/restore refusal, got:" >&2
  cat "$DR_ERR_TMP" >&2
  exit 1
}

echo "== D66 steps 3-4: disable the event trigger, run grant-ddl-ownership on the restored database =="
PGPASSWORD="$PRIMARY_PGSUPERPASSWORD" "$PG_BIN_DIR/psql" -h localhost -p "$DR_PORT" -U "$PRIMARY_PGSUPERUSER" -d owl_dr2 \
  -c "ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE;" >/dev/null
PGHOST=localhost PGPORT="$DR_PORT" PGDATABASE=owl_dr2 \
  PGSUPERUSER="$PRIMARY_PGSUPERUSER" PGSUPERPASSWORD="$PRIMARY_PGSUPERPASSWORD" \
  ./scripts/ci/provision_test_roles.sh grant-ddl-ownership

echo "== D66 step 5: confirming enforcement is genuinely live on the DR copy =="
enabled_count="$(PGPASSWORD="$PRIMARY_PGSUPERPASSWORD" "$PG_BIN_DIR/psql" -h localhost -p "$DR_PORT" -U "$PRIMARY_PGSUPERUSER" -d owl_dr2 -tAc \
  "SELECT count(*) FROM pg_event_trigger WHERE evtenabled = 'A'")"
[[ "$enabled_count" == "2" ]] || {
  echo "FAIL: expected both event triggers ENABLE ALWAYS after recovery, found $enabled_count" >&2
  exit 1
}

PGPASSWORD=owl_migrator "$PG_BIN_DIR/psql" -h localhost -p "$DR_PORT" -U owl_migrator -d owl_dr2 \
  -c "CREATE TABLE zz_d66_migrator_probe(id int); DROP TABLE zz_d66_migrator_probe;" >/dev/null

if PGPASSWORD=owl_ledger_ddl "$PG_BIN_DIR/psql" -h localhost -p "$DR_PORT" -U owl_ledger_ddl -d owl_dr2 \
  -c "DROP TRIGGER screening_ledger_anchor_immutable ON screening_ledger_anchor;" >/dev/null 2>"$DR_ERR_TMP"; then
  echo "FAIL: DROP TRIGGER succeeded against the recovered DR copy -- D34 should still block it" >&2
  exit 1
fi
grep -q "Addendum 3 D34" "$DR_ERR_TMP" || {
  echo "FAIL: expected the D34 refusal, got:" >&2
  cat "$DR_ERR_TMP" >&2
  exit 1
}

if PGPASSWORD=owl_ledger_ddl "$PG_BIN_DIR/psql" -h localhost -p "$DR_PORT" -U owl_ledger_ddl -d owl_dr2 \
  -c "REINDEX INDEX CONCURRENTLY screening_ledger_anchor_pkey;" >/dev/null 2>"$DR_ERR_TMP"; then
  echo "FAIL: REINDEX INDEX CONCURRENTLY succeeded as owl_ledger_ddl against the recovered DR copy -- Addendum 6 D51's revoke should survive the restore" >&2
  exit 1
fi
grep -q "permission denied" "$DR_ERR_TMP" || {
  echo "FAIL: expected a permission-denied refusal (Addendum 6 D51's revoke), got:" >&2
  cat "$DR_ERR_TMP" >&2
  exit 1
}

echo "PASS: ADR-0007 Addendum 7 D66 -- corrected cross-cluster DR procedure completed with zero errors on a genuinely second PostgreSQL cluster, enforcement genuinely live on the recovered copy"
