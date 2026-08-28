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

# ADR-0007 Addendum 8 D74 L-G: pg_dump joins the same PG_BIN_DIR
# preflight check as the other binaries, rather than being taken from
# PATH -- this repository has already been bitten once by exactly this
# class of gap (ci.yml:213-219's own comment: pg_dump refuses to run
# against a server newer than itself, and the runner's default client
# does not reliably match; Addendum 5's create-restored-database fixture
# needed a pinned matching client installed for the same reason). This
# script's own pg_dump call (D66 step 2, below) is now $PG_BIN_DIR-
# prefixed too, so both halves of the gap are closed together.
for bin in initdb pg_ctl postgres psql pg_isready pg_dump; do
  [[ -x "$PG_BIN_DIR/$bin" ]] || {
    echo "FAIL: $PG_BIN_DIR/$bin not found or not executable -- PG_BIN_DIR must point at a PostgreSQL 17 SERVER installation (postgresql-17, not only postgresql-client-17)" >&2
    exit 1
  }
done

DR_PORT="${DR_PORT:-55499}"
# ADR-0007 Addendum 8 D74 L-E: a FIXED, recorded path (not mktemp -d's
# unpredictable name) so a later invocation can find and reap a cluster
# a SIGKILLed prior run left behind -- SIGKILL cannot be trapped, so
# "add a signal handler" is not an available fix; a reaper that runs at
# the START of the NEXT invocation is. DR_SOCK_DIR/DR_LOG/DR_ERR_TMP stay
# mktemp-generated: nothing about D74's finding requires them to be
# rediscoverable, and a fixed path for those would only add a second
# stale-file class to manage.
DR_DATA_DIR="${DR_DATA_DIR:-/tmp/owl-sec7-cross-cluster-dr-data}"
DR_SOCK_DIR="$(mktemp -d)"
DR_LOG="$(mktemp)"
DR_ERR_TMP="$(mktemp)"

cleanup() {
  "$PG_BIN_DIR/pg_ctl" -D "$DR_DATA_DIR" -m fast stop >/dev/null 2>&1 || true
  rm -rf "$DR_DATA_DIR" "$DR_SOCK_DIR"
  # ADR-0007 Addendum 8 D74 L-F: DR_LOG held the postmaster log, which
  # includes D46's diagnostic naming the primary's system_identifier and
  # database OID verbatim -- the failure path above (D66's own
  # "confirming the second cluster became ready" check) still prints it
  # to stderr first when that path is taken, so the diagnostic value is
  # kept; only the durable copy on disk is dropped here, same as
  # DR_ERR_TMP already was.
  rm -f "$DR_LOG" "$DR_ERR_TMP"
}
trap cleanup EXIT

# ADR-0007 Addendum 8 D74 L-E (the other half): SIGKILL cannot be
# trapped, so a run killed with SIGKILL leaves DR_DATA_DIR's postmaster
# running with no chance for THIS run's own `trap cleanup EXIT` to ever
# fire. The reaper -- postmaster.pid-based, per pg_ctl's own convention
# -- runs here, before initdb, bounding the leak by the interval between
# runs rather than leaving it unbounded. It is not a trap and does not
# pretend to be one; docs/operations/sec7-database-copies.md's manual
# `pg_ctl -D <dir> -m immediate stop` step covers the case where no
# further run of this script ever happens.
if [[ -f "$DR_DATA_DIR/postmaster.pid" ]]; then
  echo "== D74 L-E: reaping a cluster a previous (likely SIGKILLed) run left running at $DR_DATA_DIR =="
  "$PG_BIN_DIR/pg_ctl" -D "$DR_DATA_DIR" -m immediate stop >/dev/null 2>&1 || true
fi
rm -rf "$DR_DATA_DIR"

echo "== D66: initializing a second, disposable PostgreSQL 17 cluster on port $DR_PORT =="
# ADR-0007 Addendum 8 D74 L-E: --auth=trust let any local user connect
# as the bootstrap superuser, with no password, to a full logical copy
# of the primary's SEC-7 database, for the whole run.
# --auth=scram-sha-256 --pwfile requires a password from the first
# connection onward, which is what makes the ALTER USER ... WITH
# PASSWORD below (L-H) meaningful rather than decorative: --pwfile seeds
# a throwaway bootstrap password (initdb requires SOME password under
# scram-sha-256; it is never the final credential), and ALTER USER is
# what actually establishes $PRIMARY_PGSUPERPASSWORD as the real one.
DR_BOOTSTRAP_PWFILE="$(mktemp)"
DR_BOOTSTRAP_PASSWORD="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)"
printf '%s\n' "$DR_BOOTSTRAP_PASSWORD" >"$DR_BOOTSTRAP_PWFILE"
"$PG_BIN_DIR/initdb" -D "$DR_DATA_DIR" -U "$PRIMARY_PGSUPERUSER" --auth=scram-sha-256 --pwfile="$DR_BOOTSTRAP_PWFILE" -E UTF8 >/dev/null
rm -f "$DR_BOOTSTRAP_PWFILE"
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
# ADR-0007 Addendum 8 D74 L-H: the identifier and the password are both
# quoted by Postgres's own format(), %I and %L respectively, rather than
# built by shell interpolation into the SQL text -- rated LOW because
# both values are workflow-controlled today, fixed because L-E's change
# above makes this the statement that actually sets the credential
# rather than a decorative one against --auth=trust.
# :'var' substitution is a psql script-parser feature, not honored
# inside a -c argument -- fed on stdin instead, where it is.
PGPASSWORD="$DR_BOOTSTRAP_PASSWORD" "$PG_BIN_DIR/psql" -h "$DR_SOCK_DIR" -p "$DR_PORT" -U "$PRIMARY_PGSUPERUSER" -d postgres \
  -X -q -v ON_ERROR_STOP=1 -v role="$PRIMARY_PGSUPERUSER" -v pass="$PRIMARY_PGSUPERPASSWORD" >/dev/null <<'SQL'
SELECT format('ALTER USER %I WITH PASSWORD %L', :'role', :'pass') \gexec
SQL
PGPASSWORD="$PRIMARY_PGSUPERPASSWORD" "$PG_BIN_DIR/psql" -h localhost -p "$DR_PORT" -U "$PRIMARY_PGSUPERUSER" -d postgres \
  -c "CREATE DATABASE owl_dr2;" >/dev/null

echo "== D66 step 1: create-roles on the TARGET cluster, PGDATABASE=postgres, BEFORE the restore =="
PGHOST=localhost PGPORT="$DR_PORT" PGDATABASE=postgres \
  PGSUPERUSER="$PRIMARY_PGSUPERUSER" PGSUPERPASSWORD="$PRIMARY_PGSUPERPASSWORD" \
  OWL_MIGRATOR_PASSWORD=owl_migrator OWL_APP_PASSWORD=owl_app \
  OWL_LEDGER_ANCHOR_PASSWORD=owl_ledger_anchor OWL_LEDGER_DDL_PASSWORD=owl_ledger_ddl \
  ./scripts/ci/provision_test_roles.sh create-roles

echo "== D66 step 2: pg_dump the primary | psql into the target cluster (0 errors expected) =="
# ADR-0007 Addendum 8 D74 L-G: $PG_BIN_DIR-prefixed, like every other
# binary this script uses, rather than taken from PATH -- pg_dump must
# match the PRIMARY's server version (it refuses to run against a newer
# server), which is exactly what PG_BIN_DIR's own preflight check above
# now covers for this binary too.
PGPASSWORD="$PRIMARY_PGSUPERPASSWORD" "$PG_BIN_DIR/pg_dump" -h "$PRIMARY_PGHOST" -p "$PRIMARY_PGPORT" -U "$PRIMARY_PGSUPERUSER" -d "$PRIMARY_PGDATABASE" \
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

# ADR-0007 Addendum 8 D74 L-D: "enforcement genuinely live on the
# recovered copy" was, before this addendum, a claim this script's own
# assertions never actually made -- every one above is an Addendum 3/5/6
# property (D34, D46, D51), and grepping this file for
# D60|D61|D62|D65|MAINTAIN|CheckProvisioningState|screening-ledger
# status|provisioned returned nothing. Made real here rather than
# narrowing the sentence, because L-A(i) is precisely a state a DR copy
# carries across (a GRANT MAINTAIN survives pg_dump in the relation's
# ACL) and D61's matrix is exactly the kind of thing a restore's own
# GRANT statements can get wrong -- a round whose HIGH findings are
# about privileges should not ship a DR proof that checks no privilege.
# `screening-ledger migrate` (not `status`: it needs no signed policy
# file, only a DSN, and reports the identical provisioned/
# provisioning_reason pair CheckProvisioningState computes -- the same
# D33/D60/D61/D69-D73 chain `status` would read) run against the
# recovered copy, as owl_migrator, asserting Provisioned=true.
echo "== D74 L-D: asserting CheckProvisioningState (D33/D60/D61/D69-D73) reports Provisioned=true on the recovered copy =="
DR_BINARY="$(mktemp -d)/screening-ledger"
(cd "$ROOT" && go build -o "$DR_BINARY" ./cmd/screening-ledger)
export DR_MIGRATOR_DSN="postgresql://owl_migrator:owl_migrator@localhost:${DR_PORT}/owl_dr2"
migrate_output="$("$DR_BINARY" migrate --postgres-dsn-env DR_MIGRATOR_DSN)"
echo "$migrate_output"
case "$migrate_output" in
*'"provisioned":true'*) ;;
*)
  echo "FAIL: ADR-0007 Addendum 8 D74 L-D: screening-ledger migrate reported Provisioned=false (or an unrecognized shape) against the recovered DR copy -- enforcement is not genuinely live" >&2
  exit 1
  ;;
esac

echo "PASS: ADR-0007 Addendum 7 D66 / Addendum 8 D74 -- corrected cross-cluster DR procedure completed with zero errors on a genuinely second PostgreSQL cluster, enforcement genuinely live on the recovered copy (D33/D60/D61/D69-D73 all asserted true, not merely D34/D46/D51)"
