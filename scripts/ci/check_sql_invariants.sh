#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

SQL_FILE="test/sql/security_invariants.sql"

if [[ -z "${OWL_TEST_DATABASE_URL:-}" ]]; then
  echo "FAIL: OWL_TEST_DATABASE_URL is not set" >&2
  exit 1
fi
command -v psql >/dev/null 2>&1 || { echo "FAIL: psql is required" >&2; exit 1; }
[[ -f "$SQL_FILE" ]] || { echo "FAIL: missing $SQL_FILE" >&2; exit 1; }

if ! psql "$OWL_TEST_DATABASE_URL" -X -q -v ON_ERROR_STOP=1 -c "SELECT 1;" >/dev/null; then
  echo "FAIL: cannot connect to OWL_TEST_DATABASE_URL" >&2
  exit 1
fi

# Parse test/sql/security_invariants.sql into (description, query) blocks.
# Each block is a `-- INVARIANT: <description>` comment line immediately
# followed by exactly one query, separated from other blocks by a blank
# line. Emits a simple line-oriented protocol the while-loop below reads.
parsed="$(awk '
  BEGIN { RS = ""; FS = "\n" }
  $1 ~ /^-- INVARIANT:/ {
    desc = $1
    sub(/^-- INVARIANT:[ \t]*/, "", desc)
    print "@@@INVARIANT@@@"
    print desc
    print "@@@SQL@@@"
    for (i = 2; i <= NF; i++) print $i
    print "@@@END@@@"
  }
' "$SQL_FILE")"

invariant_count=0
failed=0
state="none"
desc=""
sql=""

run_invariant() {
  local description="$1" query="$2"
  invariant_count=$((invariant_count + 1))
  local rows
  if ! rows="$(psql "$OWL_TEST_DATABASE_URL" -X -q -t -A -v ON_ERROR_STOP=1 -c "$query" 2>&1)"; then
    echo "FAIL: invariant query errored: $description" >&2
    echo "$rows" >&2
    failed=1
    return
  fi
  if [[ -n "$rows" ]]; then
    echo "FAIL: invariant violated: $description" >&2
    while IFS= read -r relation; do
      [[ -n "$relation" ]] && echo "  offending relation: $relation" >&2
    done <<<"$rows"
    failed=1
  else
    echo "PASS: $description"
  fi
}

while IFS= read -r line; do
  case "$line" in
  "@@@INVARIANT@@@")
    state="desc"
    desc=""
    sql=""
    ;;
  "@@@SQL@@@")
    state="sql"
    ;;
  "@@@END@@@")
    run_invariant "$desc" "$sql"
    state="none"
    ;;
  *)
    if [[ "$state" == "desc" ]]; then
      desc="$line"
    elif [[ "$state" == "sql" ]]; then
      sql+="$line"$'\n'
    fi
    ;;
  esac
done <<<"$parsed"

if [[ "$invariant_count" -eq 0 ]]; then
  echo "FAIL: no invariants parsed from $SQL_FILE" >&2
  exit 1
fi

if [[ "$failed" -ne 0 ]]; then
  echo "FAIL: $invariant_count SQL security invariant(s) checked, at least one violated" >&2
  exit 1
fi

echo "PASS: $invariant_count SQL security invariant(s) hold"
