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
# ADR-0007 Addendum 9 D83 M-J: no default. owl_ci is published in this
# repository; a value that could be mistaken for a deployment default
# must not exist at all -- both workflow files (ci.yml, release-
# qualification.yml) already set this explicitly to the primary CI
# database's actual credential, so removing the fallback changes nothing
# for either CI run and only removes an unset variable's silent fallback
# to a guessable, published string on a local invocation.
: "${PRIMARY_PGSUPERPASSWORD:?PRIMARY_PGSUPERPASSWORD must be set explicitly (ADR-0007 Addendum 9 D83 M-J): no default is provided, matching the primary CI database actual bootstrap credential rather than a guessable published string}"
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
# ADR-0007 Addendum 9 D83 (M-F, M-I, M-K): D74's fixed, recorded
# DR_DATA_DIR is WITHDRAWN, per D74's own pre-declared withdrawal
# condition ("if the reaper is found to interfere with concurrent CI
# jobs sharing a runner, it is withdrawn and the manual cleanup step
# ships alone") -- CAP #8 section 7.7 executed exactly that
# interference: two runs three seconds apart sharing the fixed path, one
# run's reaper killing the OTHER run's live, healthy cluster and
# rm -rf'ing its data directory. The predicate (postmaster.pid's mere
# PRESENCE) never distinguished a dead run's leak from a live
# concurrent one -- D21's condemned "presence implies X" shape, one
# domain over. Adopting a variant of the withdrawn mechanism (even a
# liveness-checking one) in the same round that withdrew it is not done
# here; R37 records that option for a later addendum if the leak this
# withdrawal reopens proves painful in practice.
#
# What replaces it: a unique per-invocation scratch root, so two
# concurrent runs have nothing to collide over, and M-K's failure mode
# (the ~60s pg_ctl stall against a wrong cluster, and rm -rf against a
# world-writable predictable path) disappears with the fixed path that
# caused it. This also closes M-I as a CLASS rather than patching a
# third instance: D74 already added DR_LOG/DR_ERR_TMP to cleanup()'s
# hand-maintained enumeration and, in the same commit, added
# DR_BINARY -- a new mktemp -- to :222 and did not add it there, the
# exact defect Addendum 1 diagnosed for this whole arc (fixing an
# instance rather than the class). One mktemp -d scratch root is
# created once; every temp path this script uses lives inside it;
# cleanup() removes the one root, so a new mktemp added later has
# nowhere else to put a file and cannot be forgotten.
SCRATCH_ROOT="$(mktemp -d)"
DR_DATA_DIR="$SCRATCH_ROOT/data"
DR_SOCK_DIR="$SCRATCH_ROOT/sock"
DR_LOG="$SCRATCH_ROOT/log"
DR_ERR_TMP="$SCRATCH_ROOT/err"
mkdir -p "$DR_SOCK_DIR"

# D83's replacement for D74 L-E's reaper: since there is no rediscoverable
# fixed path left to reap, a SIGKILLed run's cluster leaks until an
# operator acts -- printing this run's own root is what makes that
# actionable (D84 adds the corresponding manual-cleanup step to
# docs/operations/sec7-database-copies.md). CI is bounded by the
# ephemeral runner regardless (D74's own finding, unchanged).
echo "== D83: this run's scratch root is $SCRATCH_ROOT -- if this run is SIGKILLed, clean up manually with: $PG_BIN_DIR/pg_ctl -D $DR_DATA_DIR -m immediate stop; rm -rf $SCRATCH_ROOT =="

cleanup() {
  "$PG_BIN_DIR/pg_ctl" -D "$DR_DATA_DIR" -m fast stop >/dev/null 2>&1 || true
  # ADR-0007 Addendum 8 D74 L-F: DR_LOG held the postmaster log, which
  # includes D46's diagnostic naming the primary's system_identifier and
  # database OID verbatim -- the failure path above (D66's own
  # "confirming the second cluster became ready" check) still prints it
  # to stderr first when that path is taken, so the diagnostic value is
  # kept; only the durable copy on disk is dropped here.
  rm -rf "$SCRATCH_ROOT"
}
trap cleanup EXIT

echo "== D66: initializing a second, disposable PostgreSQL 17 cluster on port $DR_PORT =="
# ADR-0007 Addendum 8 D74 L-E: --auth=trust let any local user connect
# as the bootstrap superuser, with no password, to a full logical copy
# of the primary's SEC-7 database, for the whole run.
# --auth=scram-sha-256 --pwfile requires a password from the first
# connection onward, which is what makes the ALTER USER ... WITH
# PASSWORD below (L-H) meaningful rather than decorative: --pwfile seeds
# a throwaway bootstrap password (initdb requires SOME password under
# scram-sha-256; it is never the final credential).
#
# ADR-0007 Addendum 9 D83 M-J: the DR cluster's own PERSISTENT password
# (what ALTER USER actually sets it to) is a fresh, per-run generated
# secret -- DR_PERSISTENT_PASSWORD -- not $PRIMARY_PGSUPERPASSWORD.
# Before this, ALTER USER copied the primary's real credential onto the
# disposable DR cluster, so any local user who reads this repository's
# published PRIMARY_PGSUPERPASSWORD default (the defect the := removal
# above closes) reached a full logical copy of the primary's SEC-7
# database as its bootstrap superuser for the life of the run. The
# pattern already exists in this file for DR_BOOTSTRAP_PASSWORD, thirty
# lines below the original defect, and was simply never applied to the
# one credential that outlives initdb. A per-run generated secret cannot
# be copied because there is nothing to copy. The primary-cluster
# credential itself ($PRIMARY_PGSUPERPASSWORD, used only to authenticate
# TO the primary below) is unchanged -- this is the credential the DR
# script creates, not the credential CI provisions.
DR_BOOTSTRAP_PWFILE="$SCRATCH_ROOT/bootstrap-pwfile"
DR_BOOTSTRAP_PASSWORD="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)"
DR_PERSISTENT_PASSWORD="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)"
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
  -X -q -v ON_ERROR_STOP=1 -v role="$PRIMARY_PGSUPERUSER" -v pass="$DR_PERSISTENT_PASSWORD" >/dev/null <<'SQL'
SELECT format('ALTER USER %I WITH PASSWORD %L', :'role', :'pass') \gexec
SQL
PGPASSWORD="$DR_PERSISTENT_PASSWORD" "$PG_BIN_DIR/psql" -h localhost -p "$DR_PORT" -U "$PRIMARY_PGSUPERUSER" -d postgres \
  -c "CREATE DATABASE owl_dr2;" >/dev/null

echo "== D66 step 1: create-roles on the TARGET cluster, PGDATABASE=postgres, BEFORE the restore =="
PGHOST=localhost PGPORT="$DR_PORT" PGDATABASE=postgres \
  PGSUPERUSER="$PRIMARY_PGSUPERUSER" PGSUPERPASSWORD="$DR_PERSISTENT_PASSWORD" \
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
  | PGPASSWORD="$DR_PERSISTENT_PASSWORD" "$PG_BIN_DIR/psql" -h localhost -p "$DR_PORT" -U "$PRIMARY_PGSUPERUSER" -d owl_dr2 -v ON_ERROR_STOP=1 >/dev/null

echo "== D66: confirming the restore is genuinely bricked (Addendum 5 D46) =="
if PGPASSWORD="$DR_PERSISTENT_PASSWORD" "$PG_BIN_DIR/psql" -h localhost -p "$DR_PORT" -U "$PRIMARY_PGSUPERUSER" -d owl_dr2 \
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
PGPASSWORD="$DR_PERSISTENT_PASSWORD" "$PG_BIN_DIR/psql" -h localhost -p "$DR_PORT" -U "$PRIMARY_PGSUPERUSER" -d owl_dr2 \
  -c "ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE;" >/dev/null
PGHOST=localhost PGPORT="$DR_PORT" PGDATABASE=owl_dr2 \
  PGSUPERUSER="$PRIMARY_PGSUPERUSER" PGSUPERPASSWORD="$DR_PERSISTENT_PASSWORD" \
  ./scripts/ci/provision_test_roles.sh grant-ddl-ownership

echo "== D66 step 5: confirming enforcement is genuinely live on the DR copy =="
enabled_count="$(PGPASSWORD="$DR_PERSISTENT_PASSWORD" "$PG_BIN_DIR/psql" -h localhost -p "$DR_PORT" -U "$PRIMARY_PGSUPERUSER" -d owl_dr2 -tAc \
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
DR_BINARY="$SCRATCH_ROOT/screening-ledger"
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
