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
  printf 'SKIP: SQL security invariants (OWL_TEST_DATABASE_URL not set)\n'
fi

printf 'PASS: OpenWatchlist clean-restart CI\n'
