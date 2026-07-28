#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

BOOTSTRAP=0
if [[ "${1:-}" == "--bootstrap" ]]; then
  BOOTSTRAP=1
  shift
fi
[[ $# -eq 0 ]] || { echo "FAIL: unknown verify argument: $1" >&2; exit 2; }

# Keep the durable and bootstrap invocations explicit. macOS ships Bash 3.2,
# where expanding an empty array under `set -u` raises "unbound variable".
if [[ "$BOOTSTRAP" -eq 1 ]]; then
  python3 ./scripts/ci/legacy_exclusion_gate.py --verify-bootstrap-bytes
else
  python3 ./scripts/ci/legacy_exclusion_gate.py
fi

for required in \
  .clean-restart/import-manifest.json \
  .clean-restart/import-policy.json \
  .clean-restart/import-plan.json \
  .clean-restart/import-plan.tsv \
  .clean-restart/imported-files.sha256 \
  .clean-restart/baseline-files.sha256 \
  .clean-restart/inherited-whitespace-baseline.txt \
  .clean-restart/inherited-rustfmt-baseline.txt \
  rust-toolchain.toml \
  .github/workflows/ci.yml \
  docs/governance/clean-restart-r1.md; do
  test -f "$required" || { printf 'FAIL: missing %s\n' "$required" >&2; exit 1; }
done

if [[ "$BOOTSTRAP" -eq 1 ]]; then
  python3 ./scripts/ci/check_whitespace.py \
    --baseline .clean-restart/inherited-whitespace-baseline.txt \
    --plan .clean-restart/import-plan.json \
    --manifest .clean-restart/import-manifest.json \
    --root "$ROOT" \
    --require-inherited-bytes
else
  python3 ./scripts/ci/check_whitespace.py \
    --baseline .clean-restart/inherited-whitespace-baseline.txt \
    --plan .clean-restart/import-plan.json \
    --manifest .clean-restart/import-manifest.json \
    --root "$ROOT"
fi

if [[ "$BOOTSTRAP" -eq 1 ]]; then
  python3 ./scripts/ci/check_rustfmt.py \
    --baseline .clean-restart/inherited-rustfmt-baseline.txt \
    --plan .clean-restart/import-plan.json \
    --manifest .clean-restart/import-manifest.json \
    --root "$ROOT" \
    --metadata-only \
    --require-inherited-bytes
else
  python3 ./scripts/ci/check_rustfmt.py \
    --baseline .clean-restart/inherited-rustfmt-baseline.txt \
    --plan .clean-restart/import-plan.json \
    --manifest .clean-restart/import-manifest.json \
    --root "$ROOT" \
    --metadata-only
fi

if [[ "$BOOTSTRAP" -eq 1 ]]; then
  printf 'PASS: clean-restart bootstrap provenance and repository controls\n'
else
  printf 'PASS: clean-restart durable provenance and repository controls\n'
fi
