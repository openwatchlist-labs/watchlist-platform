#!/usr/bin/env bash
# ADR-0007 Addendum 22 D174/D179 test 7: grant-ddl-ownership's MAINTAIN
# REVOKE and its two-limb postcondition now range over all four
# protected relations (sec7_protected_relations), not the anchor and
# tombstone alone. This proves the installer half against a real,
# already-provisioned database:
#
# 1. MAINTAIN granted to a THIRD role (not the relation's declared
#    owner, not PUBLIC) survives the script's own REVOKE statement
#    (`REVOKE MAINTAIN ON TABLE <relation> FROM <owner>, PUBLIC` never
#    names a third role) and is caught by the postcondition instead --
#    exercised on each of the four protected relations in turn, so a
#    fifth relation added later without its own row in
#    sec7_protected_relations would be silently uncovered by this test
#    too (the same population-coincidence risk D174 itself closes).
# 2. A clean database's run exits 0 with exactly three PASS lines --
#    unregressed from the pre-Addendum-22 shape (D179's own literal
#    requirement): the MAINTAIN loop's success is folded into the D34
#    PASS line rather than adding a fourth.
# 3. The revoke is idempotent across re-runs (no error, same PASS count,
#    on a state the previous case's cleanup already restored).
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

run_install() {
  env PGSUPERUSER="$PGSUPERUSER" PGSUPERPASSWORD="$PGSUPERPASSWORD" PGHOST="$PGHOST" PGPORT="$PGPORT" PGDATABASE="$PGDATABASE" "$SCRIPT" grant-ddl-ownership
}

# Same four-relation population D174 declares in provision_test_roles.sh
# (sec7_protected_relations) and postgres.go (requiredProtectedRelationStates)
# -- duplicated here as table:owner pairs for the same cross-language/
# cross-script reason (R23/R35) every other declaration in this test
# suite duplicates rather than imports.
relations=(
  "screening_ledger_anchor:owl_ledger_ddl"
  "screening_ledger_retention_tombstone:owl_ledger_ddl"
  "screening_ledger_event:owl_migrator"
  "screening_ledger_snapshot:owl_migrator"
)

# --- Case 1: a third-role MAINTAIN grant is refused on each relation ------
for pair in "${relations[@]}"; do
  table="${pair%%:*}"
  psql_super -c "CREATE ROLE cap22_installer_third NOSUPERUSER NOLOGIN;" >/dev/null
  psql_super -c "GRANT MAINTAIN ON TABLE ${table} TO cap22_installer_third;" >/dev/null

  set +e
  out="$(run_install 2>&1)"
  code=$?
  set -e

  # Clean up before asserting, so a failed assertion below does not
  # leave a dangling role and grant for the next iteration or the next
  # test in this suite.
  psql_super -c "REVOKE MAINTAIN ON TABLE ${table} FROM cap22_installer_third;" >/dev/null
  psql_super -c "DROP ROLE cap22_installer_third;" >/dev/null

  [[ "$code" -ne 0 ]] || fail "case 1 (${table}): grant-ddl-ownership succeeded despite MAINTAIN held by a third role (cap22_installer_third) -- the postcondition's holder-side limb did not catch it. Output:\n$out"
  [[ "$out" == *"MAINTAIN on ${table} is held by"*"cap22_installer_third"* ]] || fail "case 1 (${table}): expected a failure naming ${table} and cap22_installer_third, got:\n$out"
done
echo "PASS: case 1 (a third-role MAINTAIN grant on each of the four protected relations is refused by name, ADR-0007 Addendum 22 D174)"

# --- Case 2: a clean run exits 0 with exactly three PASS lines ------------
out="$(run_install)"
pass_count="$(printf '%s\n' "$out" | grep -c '^PASS:')"
[[ "$pass_count" -eq 3 ]] || fail "case 2: expected exactly 3 PASS lines on a clean run, got $pass_count:\n$out"
echo "PASS: case 2 (a clean database's grant-ddl-ownership run exits 0 with exactly three PASS lines, unregressed by Addendum 22)"

# --- Case 3: the revoke is idempotent across re-runs -----------------------
run_install >/dev/null
out2="$(run_install)"
pass_count2="$(printf '%s\n' "$out2" | grep -c '^PASS:')"
[[ "$pass_count2" -eq 3 ]] || fail "case 3: a second consecutive clean run did not exit 0 with three PASS lines, got $pass_count2:\n$out2"
echo "PASS: case 3 (the MAINTAIN revoke is idempotent across repeated grant-ddl-ownership runs)"

echo "PASS: all provisioning-MAINTAIN-population tests (ADR-0007 Addendum 22 D174/D179 test 7)"
