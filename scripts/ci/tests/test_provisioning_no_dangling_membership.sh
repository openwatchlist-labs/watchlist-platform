#!/usr/bin/env bash
# ADR-0007 Addendum 3 D35/D37 (G-E): "the test whose absence let G-E
# ship" -- CAP #2 §7.9 found that grant-ddl-ownership's old
# GRANT owl_ledger_ddl TO owl_migrator / ALTER TABLE / REVOKE sequence
# left a cluster-wide dangling membership if anything failed between the
# GRANT and the REVOKE, granting owl_migrator privileges on every
# database in the cluster, including ones a failed run never touched.
# D35's fix removes the GRANT/REVOKE pair entirely (a superuser needs no
# role membership to run ALTER TABLE ... OWNER TO, confirmed by execution
# during the design pass) and adds a precondition that refuses to proceed
# if a dangling membership already exists from any other source.
#
# This test proves both directions against a real, already-provisioned
# database, without ever risking real state: (1) the static claim -- no
# GRANT of role membership to owl_migrator exists anywhere in the script
# text any more; (2) the live claim -- a dangling membership, however it
# got there, is refused rather than silently inherited; and (3) that a
# normal, successful run leaves no membership behind, which is now true
# by construction rather than by care.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="$ROOT/scripts/ci/provision_test_roles.sh"

: "${PGHOST:=localhost}"
: "${PGPORT:=5432}"
: "${PGDATABASE:=owl_ci}"
: "${PGSUPERUSER:=owl_ci}"
: "${PGSUPERPASSWORD:=owl_ci}"
export PGPASSWORD="$PGSUPERPASSWORD"

psql_super() {
  psql -h "$PGHOST" -p "$PGPORT" -U "$PGSUPERUSER" -d "$PGDATABASE" -X -q -v ON_ERROR_STOP=1 "$@"
}

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

is_member() {
  psql_super -tAc "SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles mm ON mm.oid = m.member WHERE r.rolname = 'owl_ledger_ddl' AND mm.rolname = 'owl_migrator'"
}

# --- Case 1: the mechanism is gone, not merely narrowed -------------------
if grep -qE "GRANT[[:space:]]+owl_ledger_ddl[[:space:]]+TO[[:space:]]+owl_migrator" "$SCRIPT"; then
  fail "case 1: provision_test_roles.sh still grants owl_ledger_ddl membership to owl_migrator -- the window D35 removes is still present in the script text"
fi
echo "PASS: case 1 (no GRANT of owl_ledger_ddl membership to owl_migrator anywhere in provision_test_roles.sh)"

# --- Case 2: a dangling membership from any other source is refused ------
# Requires a fully provisioned database (grant-ddl-ownership already run,
# so this case does not depend on run order against the primary suite).
already_member="$(is_member)"
[[ -z "$already_member" ]] || fail "case 2 precondition: owl_migrator is already a member of owl_ledger_ddl before this test ran -- run grant-ddl-ownership's own postconditions first"

PGPASSWORD="$PGSUPERPASSWORD" psql_super -c "GRANT owl_ledger_ddl TO owl_migrator;" >/dev/null
trap 'PGPASSWORD="$PGSUPERPASSWORD" psql -h "$PGHOST" -p "$PGPORT" -U "$PGSUPERUSER" -d "$PGDATABASE" -X -q -c "REVOKE owl_ledger_ddl FROM owl_migrator;" >/dev/null 2>&1 || true' EXIT

set +e
out="$(env PGSUPERUSER="$PGSUPERUSER" PGSUPERPASSWORD="$PGSUPERPASSWORD" PGHOST="$PGHOST" PGPORT="$PGPORT" PGDATABASE="$PGDATABASE" "$SCRIPT" grant-ddl-ownership 2>&1)"
code=$?
set -e
[[ "$code" -ne 0 ]] || fail "case 2: grant-ddl-ownership succeeded despite a pre-existing owl_migrator->owl_ledger_ddl membership; the D35 precondition did not fire. Output:\n$out"
[[ "$out" == *"already a member of owl_ledger_ddl"* ]] || fail "case 2: expected the D35 precondition's specific message, got:\n$out"
echo "PASS: case 2 (a dangling membership from any source is refused, not silently inherited)"

PGPASSWORD="$PGSUPERPASSWORD" psql -h "$PGHOST" -p "$PGPORT" -U "$PGSUPERUSER" -d "$PGDATABASE" -X -q -c "REVOKE owl_ledger_ddl FROM owl_migrator;" >/dev/null
trap - EXIT

# --- Case 3: a normal, successful run leaves no membership behind --------
env PGSUPERUSER="$PGSUPERUSER" PGSUPERPASSWORD="$PGSUPERPASSWORD" PGHOST="$PGHOST" PGPORT="$PGPORT" PGDATABASE="$PGDATABASE" "$SCRIPT" grant-ddl-ownership >/dev/null
still_member="$(is_member)"
[[ -z "$still_member" ]] || fail "case 3: owl_migrator is a member of owl_ledger_ddl after a successful grant-ddl-ownership run -- the window is supposed to not exist at all"
echo "PASS: case 3 (a successful run leaves pg_auth_members with no owl_migrator->owl_ledger_ddl edge)"

echo "PASS: all provisioning-membership tests (ADR-0007 Addendum 3 D35/G-E)"
