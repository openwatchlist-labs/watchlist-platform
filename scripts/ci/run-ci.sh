#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [[ "${CLEAN_RESTART_BOOTSTRAP_VERIFY:-0}" == "1" ]]; then
  ./scripts/ci/verify-clean-restart.sh --bootstrap
else
  ./scripts/ci/verify-clean-restart.sh
fi

./scripts/ci/verify-homelab-r2-4-publication.sh
python3 ./scripts/ci/verify-legacy-lineage.py
PYTHONDONTWRITEBYTECODE=1 python3 ./scripts/ci/tests/test_legacy_lineage.py
python3 ./scripts/ci/check_tenant_binding.py
PYTHONDONTWRITEBYTECODE=1 python3 ./scripts/ci/tests/test_tenant_binding.py
python3 ./scripts/ci/check_permission_table.py
PYTHONDONTWRITEBYTECODE=1 python3 ./scripts/ci/tests/test_permission_table.py
python3 ./scripts/ci/check_screening_variants.py

# ADR-0007 Addendum 1, D18: fail closed on the database security gates
# before spending time on go/cargo, rather than letting `go test` below
# silently absorb the SEC-7/SEC-1 pgx suites' self-skip. See
# scripts/ci/check_db_gates.sh for the full rationale and the gate list.
./scripts/ci/check_db_gates.sh
# ADR-0007 Addendum 2 D30 (F-G): the gate script above has its own
# regression test, which nothing was invoking -- placed here, next to the
# gate it guards, rather than with run-ci.sh's other test_*.py siblings,
# so the test and the script it tests read together.
./scripts/ci/tests/test_check_db_gates.sh
# ADR-0007 Addendum 3 D35/D37 (G-E): the same rationale as D30's line
# above -- riding along per CLAUDE.md Boundaries as a one-line invocation
# of an already-committed test that adds no gate and changes no
# pass/fail semantics for any environment that was passing before. Gated
# on OWL_LEDGER_DDL_DATABASE_URL, a proxy for "this cluster is fully
# provisioned" -- the test itself connects with PGHOST/PGPORT/PGDATABASE/
# PGSUPERUSER/PGSUPERPASSWORD, the same variables provision_test_roles.sh
# itself reads, not a DSN.
if [[ -n "${OWL_LEDGER_DDL_DATABASE_URL:-}" ]]; then
  ./scripts/ci/tests/test_provisioning_no_dangling_membership.sh
else
  printf 'SKIP: provisioning no-dangling-membership test (OWL_LEDGER_DDL_DATABASE_URL not set; see fail-open banner above)\n'
fi

if [[ -f go.mod ]]; then
  command -v go >/dev/null 2>&1 || { echo 'FAIL: Go is required' >&2; exit 1; }
  go mod verify
  go_files="$(git ls-files '*.go')"
  if [[ -n "$go_files" ]]; then
    unformatted="$(printf '%s\n' "$go_files" | xargs gofmt -l)"
    if [[ -n "$unformatted" ]]; then
      printf 'FAIL: gofmt required:\n%s\n' "$unformatted" >&2
      exit 1
    fi
  fi
  go vet ./...
  go run golang.org/x/vuln/cmd/govulncheck@latest ./...
  go run honnef.co/go/tools/cmd/staticcheck@latest ./...
  go test -race -count=1 ./...
fi
if [[ -f Cargo.toml ]]; then
  command -v cargo >/dev/null 2>&1 || { echo 'FAIL: Cargo is required' >&2; exit 1; }
  command -v rustc >/dev/null 2>&1 || { echo 'FAIL: rustc is required' >&2; exit 1; }
  command -v rustfmt >/dev/null 2>&1 || { echo 'FAIL: rustfmt is required' >&2; exit 1; }
  python3 ./scripts/ci/check_rustfmt.py \
    --baseline .clean-restart/inherited-rustfmt-baseline.txt \
    --plan .clean-restart/import-plan.json \
    --manifest .clean-restart/import-manifest.json \
    --root "$ROOT"
  cargo check --locked --workspace --all-targets
  cargo test --locked --workspace --all-targets
  if [[ "${CI_STRICT_CLIPPY:-0}" == "1" ]]; then
    cargo clippy --locked --workspace --all-targets -- -D warnings
  fi
else
  cargo_manifests="$(git ls-files '*/Cargo.toml')"
  if [[ -n "$cargo_manifests" ]]; then
    command -v cargo >/dev/null 2>&1 || { echo 'FAIL: Cargo is required' >&2; exit 1; }
    while IFS= read -r manifest; do
      [[ -n "$manifest" ]] || continue
      cargo check --locked --manifest-path "$manifest" --all-targets
      cargo test --locked --manifest-path "$manifest" --all-targets
      if [[ "${CI_STRICT_CLIPPY:-0}" == "1" ]]; then
        cargo clippy --locked --manifest-path "$manifest" --all-targets -- -D warnings
      fi
    done <<< "$cargo_manifests"
  fi
fi
if [[ -n "${OWL_TEST_DATABASE_URL:-}" ]]; then
  ./scripts/ci/check_sql_invariants.sh
else
  printf 'SKIP: SQL security invariants (OWL_TEST_DATABASE_URL not set; see fail-open banner above)\n'
fi

# Mirrors check_db_gates.sh's gate list so the final line names the
# fail-open condition too, in case a reader only skims the tail of the log.
db_gates_unproven=0
for gate in OWL_TEST_DATABASE_URL OWL_MIGRATOR_DATABASE_URL OWL_LEDGER_ANCHOR_DATABASE_URL OWL_LEDGER_DDL_DATABASE_URL OWL_MIGRATOR_STALE_DATABASE_URL OWL_BOOTSTRAP_SUPERUSER_DATABASE_URL OWL_MIGRATOR_UNPROVISIONED_DATABASE_URL OWL_SCHEMASQL_ONLY_DATABASE_URL; do
  [[ -n "${!gate:-}" ]] || db_gates_unproven=1
done
if [[ "$db_gates_unproven" -eq 1 ]]; then
  printf 'PASS: OpenWatchlist clean-restart CI -- FAIL-OPEN: database security gates unproven, NOT A SECURITY GATE (see banner above)\n'
else
  printf 'PASS: OpenWatchlist clean-restart CI\n'
fi
