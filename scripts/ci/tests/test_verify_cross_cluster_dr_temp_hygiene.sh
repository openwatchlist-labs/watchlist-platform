#!/usr/bin/env bash
# ADR-0007 Addendum 9 D83/D85 test 7: scripts/ci/verify_cross_cluster_dr.sh's
# own assertions become tests, made real rather than claimed a third time
# (D75 test 5 made the same claim once, unmet; D74's own fix -- adding
# DR_LOG/DR_ERR_TMP to cleanup()'s hand-maintained enumeration -- missed
# DR_BINARY in the very same commit).
#
# 1. No `mktemp` call exists in the script outside the one scratch-root
#    allocation -- a grep-based unit check so a fourth instance cannot be
#    added silently the way the third (DR_BOOTSTRAP_PWFILE) was.
# 2. No PRIMARY_PGSUPERPASSWORD default (`:=`) remains in the script or
#    either workflow file.
# 3. A successful run leaves the system temp directory's file count
#    unchanged -- asserted by counting, not by inspection.
# 4. Two concurrent invocations (distinct DR_PORT, distinct scratch roots)
#    both succeed -- the withdrawn reaper's own failure condition (CAP #8
#    section 7.7: one run's reaper killed the other's live cluster)
#    asserted as a test rather than left to a ninth CAP.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="$ROOT/scripts/ci/verify_cross_cluster_dr.sh"

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

# --- Case 1: exactly one mktemp CALL (not comment mention) in the script --
mktemp_count="$(grep -v '^[[:space:]]*#' "$SCRIPT" | grep -c 'mktemp' || true)"
[[ "$mktemp_count" -eq 1 ]] || fail "case 1: expected exactly one non-comment 'mktemp' occurrence in $SCRIPT (the scratch-root allocation), found $mktemp_count -- a new temp path was added outside SCRATCH_ROOT, reproducing the M-I class defect"
echo "PASS: case 1 (exactly one mktemp call, the scratch-root allocation)"

# --- Case 2: no PRIMARY_PGSUPERPASSWORD default anywhere -------------------
if grep -q 'PRIMARY_PGSUPERPASSWORD:=' "$SCRIPT"; then
  fail "case 2: $SCRIPT still defaults PRIMARY_PGSUPERPASSWORD -- the published-string exposure D83 M-J closes is still present"
fi
for wf in "$ROOT/.github/workflows/ci.yml" "$ROOT/.github/workflows/release-qualification.yml"; do
  if grep -q 'PRIMARY_PGSUPERPASSWORD:=' "$wf"; then
    fail "case 2: $wf defaults PRIMARY_PGSUPERPASSWORD"
  fi
done
echo "PASS: case 2 (no PRIMARY_PGSUPERPASSWORD default in the script or either workflow)"

# --- Cases 3-4 require a live PostgreSQL 17 server installation ------------
: "${PG_BIN_DIR:=/usr/lib/postgresql/17/bin}"
if [[ ! -x "$PG_BIN_DIR/initdb" ]]; then
  echo "SKIP: cases 3-4 require PG_BIN_DIR to point at a PostgreSQL 17 SERVER installation (postgresql-17); not found at $PG_BIN_DIR"
  echo "PASS: static checks only (ADR-0007 Addendum 9 D83)"
  exit 0
fi

if [[ -z "${PRIMARY_PGSUPERPASSWORD:-}" ]]; then
  echo "SKIP: cases 3-4 require PRIMARY_PGSUPERPASSWORD (matching verify_cross_cluster_dr.sh's own D83 M-J requirement); not set"
  echo "PASS: static checks only (ADR-0007 Addendum 9 D83)"
  exit 0
fi
: "${PRIMARY_PGHOST:=localhost}"
: "${PRIMARY_PGPORT:=5432}"
: "${PRIMARY_PGSUPERUSER:=owl_ci}"
: "${PRIMARY_PGDATABASE:=owl_ci}"
export PG_BIN_DIR PRIMARY_PGHOST PRIMARY_PGPORT PRIMARY_PGSUPERUSER PRIMARY_PGSUPERPASSWORD PRIMARY_PGDATABASE

# ADR-0007 Addendum 10 D94 (N-G, LOW): ${TMPDIR:-/tmp} is where mktemp
# writes on the CI runner (Ubuntu, TMPDIR usually unset, /tmp a real
# directory) but is NOT where it writes on macOS, with or without TMPDIR
# set -- macOS mktemp -d always resolves through
# confstr(_CS_DARWIN_USER_TEMP_DIR) (a path under /var/folders/...),
# regardless of TMPDIR. Measured during this addendum's implementation
# pass: with TMPDIR unset on macOS, `find "${TMPDIR:-/tmp}" -maxdepth 1`
# lists exactly 1 entry (/tmp itself, a symlink `find` without -H does
# not follow) while `mktemp -d` writes into a directory holding thousands
# of entries -- so the shipped counter was a constant that could not
# register a leak. tmp_root() asks mktemp directly where it writes,
# rather than guessing from TMPDIR; -H follows a symlinked start path
# (the other half of the same defect, harmless on Ubuntu where /tmp is
# already a real directory and TMPDIR usually agrees with tmp_root()).
tmp_root() {
  local d r
  d="$(mktemp -d)"
  r="$(dirname "$d")"
  rmdir "$d"
  printf '%s' "$r"
}

tmp_file_count() {
  find -H "$(tmp_root)" -maxdepth 1 2>/dev/null | wc -l | tr -d ' '
}

# This test's OWN log files must not be counted as a leak: LOG_DIR is
# created once, before case 3's "before" measurement, so it is already
# one of the temp directory's top-level entries in BOTH the before and
# after snapshots -- writing case output files INSIDE it changes nothing
# at the top level being measured. Removed unconditionally on exit.
LOG_DIR="$(mktemp -d)"
trap 'rm -rf "$LOG_DIR"' EXIT

# --- Case 3: a successful run leaves the temp directory unchanged ---------
before="$(tmp_file_count)"
DR_PORT="${DR_PORT:-55499}" "$SCRIPT" >"$LOG_DIR/case3.log" 2>&1 || {
  cat "$LOG_DIR/case3.log" >&2
  fail "case 3: a plain run of $SCRIPT should succeed against a reachable primary"
}
after="$(tmp_file_count)"
[[ "$before" -eq "$after" ]] || fail "case 3: system temp directory file count changed from $before to $after across a successful run -- a temp file leaked"

# ADR-0007 Addendum 10 D94's own required assertion: the counter must be
# non-vacuous -- the root it measures must be the one the script's own
# "== D83: this run's scratch root is ..." line names, not merely a
# constant that happens not to have changed. A counter that cannot
# change (case 1's own historical bug) would pass the [[ "$before" -eq
# "$after" ]] check above vacuously; this fails the test if that ever
# recurs.
run_scratch_root="$(grep -o "scratch root is [^ ]*" "$LOG_DIR/case3.log" | head -1 | cut -d' ' -f3)"
[[ -n "$run_scratch_root" ]] || fail "case 3: could not find the '== D83: this run's scratch root is ...' line in the script's own output"
run_tmp_root="$(dirname "$run_scratch_root")"
measured_tmp_root="$(tmp_root)"
[[ "$run_tmp_root" == "$measured_tmp_root" ]] || fail "case 3: this test's own tmp_root() ($measured_tmp_root) does not match the directory the script's scratch root actually lived in ($run_tmp_root) -- the counter would be measuring the wrong directory"
echo "PASS: case 3 (a successful run leaves the system temp directory file count unchanged: $before; counter confirmed non-vacuous against $measured_tmp_root)"

# --- Case 4: two concurrent invocations both succeed ------------------------
DR_PORT=55501 "$SCRIPT" >"$LOG_DIR/case4a.log" 2>&1 &
pid_a=$!
DR_PORT=55502 "$SCRIPT" >"$LOG_DIR/case4b.log" 2>&1 &
pid_b=$!
wait "$pid_a"; code_a=$?
wait "$pid_b"; code_b=$?
[[ "$code_a" -eq 0 ]] || { cat "$LOG_DIR/case4a.log" >&2; fail "case 4: concurrent invocation A failed (exit $code_a) -- the withdrawn reaper's own failure condition (CAP #8 section 7.7) reproduced"; }
[[ "$code_b" -eq 0 ]] || { cat "$LOG_DIR/case4b.log" >&2; fail "case 4: concurrent invocation B failed (exit $code_b) -- the withdrawn reaper's own failure condition (CAP #8 section 7.7) reproduced"; }
echo "PASS: case 4 (two concurrent invocations, distinct DR_PORT, both succeeded -- no shared fixed path to collide over)"

echo "PASS: all DR-tooling temp-hygiene tests (ADR-0007 Addendum 9 D83)"
