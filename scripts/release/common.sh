#!/usr/bin/env bash
set -euo pipefail
release_fail(){ echo "FAIL: $*" >&2; exit 1; }
release_require(){ command -v "$1" >/dev/null 2>&1 || release_fail "required tool missing: $1"; }
release_require_empty(){ [ -n "$1" ] || release_fail "output path required"; [ ! -e "$1" ] || release_fail "output already exists: $1"; }
release_iso_utc(){ python3 - "$1" <<'PY_REL_TIME'
import datetime,sys
print(datetime.datetime.fromtimestamp(int(sys.argv[1]),datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
PY_REL_TIME
}
