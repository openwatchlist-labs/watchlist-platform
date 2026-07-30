#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
export PYTHONDONTWRITEBYTECODE=1

# Run lifecycle cases first and isolate each in its own interpreter. These tests
# intentionally create and terminate disposable process trees; starting from a
# clean process table avoids cleanup timing from unrelated tests on macOS/Linux.
for test_name in \
  tests.test_remote_lifecycle.RemoteLifecycleTests.test_opt1_realistic_rebinding_activate_smoke_and_rollback \
  tests.test_remote_lifecycle.RemoteLifecycleTests.test_opt2_activate_smoke_rollback \
  tests.test_remote_lifecycle.RemoteLifecycleTests.test_opt1_prequalification_published_check_failure_is_structured \
  tests.test_remote_lifecycle.RemoteLifecycleTests.test_opt1_prequalification_rejects_missing_required_runtime_seal \
  tests.test_remote_lifecycle.RemoteLifecycleTests.test_opt2_package_mismatch_is_structured_and_rolls_back \
  tests.test_remote_lifecycle.RemoteSafetyTests.test_capability_only_activation_is_rejected \
  tests.test_remote_lifecycle.RemoteSafetyTests.test_opt1_rollback_without_docker_is_fail_closed \
  tests.test_remote_lifecycle.RemoteSafetyTests.test_missing_opt2_archive_cleanup_is_idempotent \
  tests.test_remote_lifecycle.RemoteSafetyTests.test_unsafe_opt2_archive_is_rejected_and_runtime_removed; do
  python3 -m unittest -v "$test_name"
done

for module in \
  tests.test_evaluators \
  tests.test_evidence \
  tests.test_inputs \
  tests.test_policy \
  tests.test_publication \
  tests.test_source_lock; do
  python3 -m unittest -v "$module"
done

if find . \( -type d -name __pycache__ -o -name '*.pyc' \) -print | grep -q .;then
  echo 'ERROR: self-test created compiled Python artifacts' >&2
  exit 2
fi

echo 'PASS: offline exact-corpus, source-lock, sanitized policy, complete config rebinding, declared multi-config seal regeneration, realistic published-check, qualification-first transfer, activation, and rollback-safety tests'
