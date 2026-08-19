#!/usr/bin/env bash
# ADR-0007 Addendum 1, D18 (F4): database security gates fail closed.
#
# Each variable below gates real-Postgres tests or checks that otherwise
# self-skip and still exit 0 -- Go's t.Skip, or (before this script existed)
# run-ci.sh's own SKIP-falls-through-to-PASS path. That is the "silent
# absence" bug shape CLAUDE.md rule 5 calls out: a control that looks
# installed and does nothing. A run that did not prove these controls must
# say so and fail, not pass quietly.
#
#   OWL_TEST_DATABASE_URL          - SQL invariants (check_sql_invariants.sh,
#                                     run by run-ci.sh); readiness pgx suite
#                                     (internal/productionops/readiness_postgres_test.go);
#                                     SEC-1 two-tenant pgx suite
#                                     (internal/integrationtest/tenant_isolation_test.go)
#   OWL_MIGRATOR_DATABASE_URL      - screening-ledger pgx suite
#                                     (internal/screeningledger/postgres_pgx_test.go);
#                                     SEC-1 two-tenant fixture seeding
#                                     (internal/integrationtest/tenant_isolation_test.go)
#   OWL_LEDGER_ANCHOR_DATABASE_URL - SEC-7 anchor role-separation suite
#                                     (internal/screeningledger/anchor_pgx_test.go)
#   OWL_LEDGER_DDL_DATABASE_URL    - SEC-7 anchor role-separation suite
#                                     (internal/screeningledger/anchor_pgx_test.go)
#
# This is the complete set: every `os.Getenv("OWL_*_DATABASE_URL")` in the
# tree gates through one of these four, confirmed by grepping the tree
# rather than assumed from ADR-0007 D18's text, which names only the two
# anchor-related ones.
#
# An operator who genuinely has no database available sets
# OWL_ALLOW_UNPROVEN_DB_GATES=1. Everything else in run-ci.sh still runs;
# this script still exits 0; but it prints a named, visible fail-open
# banner and the run does not constitute a security gate.
#
# Deliberately does not grep .github/workflows/ci.yml for these variables
# (D18's explicit non-goal): that would replace one unenforced coupling
# with a more brittle one. The property this proves is that a verification
# run which did not prove the gates says so and fails, wherever it runs --
# not that one CI config file stays correct forever.
set -euo pipefail

DB_GATES=(
  OWL_TEST_DATABASE_URL
  OWL_MIGRATOR_DATABASE_URL
  OWL_LEDGER_ANCHOR_DATABASE_URL
  OWL_LEDGER_DDL_DATABASE_URL
)

missing=()
for gate in "${DB_GATES[@]}"; do
  if [[ -z "${!gate:-}" ]]; then
    missing+=("$gate")
  else
    printf 'PASS: %s is set\n' "$gate"
  fi
done

if [[ "${#missing[@]}" -eq 0 ]]; then
  exit 0
fi

if [[ "${OWL_ALLOW_UNPROVEN_DB_GATES:-0}" == "1" ]]; then
  printf '\n'
  printf '################################################################################\n'
  printf '# FAIL-OPEN: database security gates not provisioned\n'
  printf '# OWL_ALLOW_UNPROVEN_DB_GATES=1 is set -- continuing without them.\n'
  printf '# THIS RUN DOES NOT CONSTITUTE A SECURITY GATE.\n'
  printf '################################################################################\n'
  for gate in "${missing[@]}"; do
    printf 'SKIP (fail-open, unproven): %s not set\n' "$gate"
  done
  printf '\n'
  exit 0
fi

for gate in "${missing[@]}"; do
  printf 'FAIL: %s is not set. Set it, or set OWL_ALLOW_UNPROVEN_DB_GATES=1 to continue without proving this gate (prints a fail-open banner; the run will not constitute a security gate).\n' "$gate" >&2
done
exit 1
