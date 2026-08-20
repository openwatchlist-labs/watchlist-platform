#!/usr/bin/env bash
# Fast, no-database tests for scripts/ci/check_db_gates.sh (ADR-0007
# Addendum 1, D18). Exercises exit-code and banner behavior directly, with
# no real Postgres and no dependency on the rest of run-ci.sh, so it runs
# in milliseconds and can gate every PR.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GATE_SCRIPT="$ROOT/scripts/ci/check_db_gates.sh"

ALL_GATES=(
  OWL_TEST_DATABASE_URL
  OWL_MIGRATOR_DATABASE_URL
  OWL_LEDGER_ANCHOR_DATABASE_URL
  OWL_LEDGER_DDL_DATABASE_URL
  OWL_MIGRATOR_STALE_DATABASE_URL
)

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

# clean_env runs check_db_gates.sh with none of the OWL_*_DATABASE_URL or
# OWL_ALLOW_UNPROVEN_DB_GATES variables inherited from this process, plus
# whatever overrides are passed as NAME=value arguments.
run_gate() {
  env -u OWL_TEST_DATABASE_URL \
      -u OWL_MIGRATOR_DATABASE_URL \
      -u OWL_LEDGER_ANCHOR_DATABASE_URL \
      -u OWL_LEDGER_DDL_DATABASE_URL \
      -u OWL_MIGRATOR_STALE_DATABASE_URL \
      -u OWL_ALLOW_UNPROVEN_DB_GATES \
      "$@" "$GATE_SCRIPT"
}

# --- Case 1: all five gates unset, no opt-out -> fails closed -------------
set +e
out="$(run_gate 2>&1)"
code=$?
set -e
[[ "$code" -ne 0 ]] || fail "case 1: expected non-zero exit with no DSNs and no opt-out, got 0. Output:\n$out"
for gate in "${ALL_GATES[@]}"; do
  [[ "$out" == *"FAIL: $gate is not set"* ]] || fail "case 1: expected a FAIL line naming $gate. Output:\n$out"
done
echo "PASS: case 1 (all gates missing, no opt-out -> exit non-zero, all five named)"

# --- Case 2: all five gates unset, with opt-out -> fail-open, exit 0 ------
set +e
out="$(run_gate OWL_ALLOW_UNPROVEN_DB_GATES=1 2>&1)"
code=$?
set -e
[[ "$code" -eq 0 ]] || fail "case 2: expected exit 0 under OWL_ALLOW_UNPROVEN_DB_GATES=1, got $code. Output:\n$out"
[[ "$out" == *"FAIL-OPEN"* ]] || fail "case 2: expected a FAIL-OPEN banner. Output:\n$out"
[[ "$out" == *"DOES NOT CONSTITUTE A SECURITY GATE"* ]] || fail "case 2: expected the run to be marked as not constituting a security gate. Output:\n$out"
for gate in "${ALL_GATES[@]}"; do
  [[ "$out" == *"SKIP (fail-open, unproven): $gate not set"* ]] || fail "case 2: expected a fail-open SKIP line naming $gate. Output:\n$out"
done
echo "PASS: case 2 (all gates missing, opt-out set -> exit 0, fail-open banner, all five named)"

# --- Case 3: all four gates set (bogus but non-empty DSNs) -> passes ------
set +e
out="$(run_gate \
  OWL_TEST_DATABASE_URL=postgresql://bogus/db \
  OWL_MIGRATOR_DATABASE_URL=postgresql://bogus/db \
  OWL_LEDGER_ANCHOR_DATABASE_URL=postgresql://bogus/db \
  OWL_LEDGER_DDL_DATABASE_URL=postgresql://bogus/db \
  OWL_MIGRATOR_STALE_DATABASE_URL=postgresql://bogus/db \
  2>&1)"
code=$?
set -e
[[ "$code" -eq 0 ]] || fail "case 3: expected exit 0 with all five gates set, got $code. Output:\n$out"
[[ "$out" != *"FAIL"* ]] || fail "case 3: expected no FAIL output with all five gates set. Output:\n$out"
[[ "$out" != *"FAIL-OPEN"* ]] || fail "case 3: expected no fail-open banner with all five gates set. Output:\n$out"
for gate in "${ALL_GATES[@]}"; do
  [[ "$out" == *"PASS: $gate is set"* ]] || fail "case 3: expected a PASS line naming $gate. Output:\n$out"
done
echo "PASS: case 3 (all gates set -> exit 0, no fail-open banner, all five named)"

# --- Case 4: partial set (only OWL_TEST_DATABASE_URL), no opt-out --------
# The anchor-related gates are not the only ones that must fail closed --
# a run with only OWL_TEST_DATABASE_URL set (e.g. SQL invariants alone)
# must still fail if the SEC-7 anchor gates are absent.
set +e
out="$(run_gate OWL_TEST_DATABASE_URL=postgresql://bogus/db 2>&1)"
code=$?
set -e
[[ "$code" -ne 0 ]] || fail "case 4: expected non-zero exit with only OWL_TEST_DATABASE_URL set, got 0. Output:\n$out"
[[ "$out" == *"PASS: OWL_TEST_DATABASE_URL is set"* ]] || fail "case 4: expected OWL_TEST_DATABASE_URL to be reported as set. Output:\n$out"
[[ "$out" == *"FAIL: OWL_LEDGER_ANCHOR_DATABASE_URL is not set"* ]] || fail "case 4: expected OWL_LEDGER_ANCHOR_DATABASE_URL to fail closed even though OWL_TEST_DATABASE_URL was set. Output:\n$out"
echo "PASS: case 4 (partial gates set, no opt-out -> exit non-zero on the missing ones specifically)"

echo "PASS: all check_db_gates.sh tests"
