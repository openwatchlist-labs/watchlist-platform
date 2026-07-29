#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ARCHIVE=""
MANIFEST=""
OUTPUT=""
usage() {
  cat <<'EOF'
Usage: qualify-linux-amd64-runtime.sh --archive PATH --manifest PATH --output DIRECTORY

Linux x86-64 only. Performs portable archive/ELF validation first, followed by
readelf, ldd, and executable smoke validation on Ubuntu/Linux AMD64.
EOF
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --archive) ARCHIVE=${2:-}; shift 2 ;;
    --manifest) MANIFEST=${2:-}; shift 2 ;;
    --output) OUTPUT=${2:-}; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "FAIL: unknown argument: $1" >&2; exit 1 ;;
  esac
done
for tool in python3 file readelf ldd shasum uname; do
  command -v "$tool" >/dev/null 2>&1 || { echo "FAIL: required Linux qualification tool missing: $tool" >&2; exit 1; }
done
[ "$(uname -s)" = "Linux" ] || { echo "FAIL: executable runtime qualification requires Linux" >&2; exit 1; }
case "$(uname -m)" in
  x86_64|amd64) ;;
  *) echo "FAIL: executable runtime qualification requires x86_64/amd64" >&2; exit 1 ;;
esac
[ -f "$ARCHIVE" ] && [ -f "$MANIFEST" ] && [ -n "$OUTPUT" ] || { echo "FAIL: archive, manifest, and output required" >&2; exit 1; }
[ ! -e "$OUTPUT" ] || { echo "FAIL: output already exists: $OUTPUT" >&2; exit 1; }
TMP=$(mktemp -d "${TMPDIR:-/tmp}/openwatchlist-runtime-qualification.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$OUTPUT"

python3 "$SCRIPT_DIR/validate-linux-amd64-runtime-portable.py" \
  --archive "$ARCHIVE" \
  --manifest "$MANIFEST" \
  --output "$OUTPUT/portable-validation.json" \
  >"$OUTPUT/portable-validation.log"

python3 - "$ARCHIVE" "$TMP/extracted" <<'PY_EXTRACT'
import os
import pathlib
import sys
import tarfile

archive = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
out.mkdir(mode=0o700)
with tarfile.open(archive, "r:gz") as tf:
    for member in tf.getmembers():
        pure = pathlib.PurePosixPath(member.name)
        if pure.is_absolute() or ".." in pure.parts or member.issym() or member.islnk():
            raise SystemExit(f"unsafe archive member: {member.name}")
        target = out.joinpath(*pure.parts)
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            target.chmod(member.mode & 0o777)
        elif member.isfile():
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tf.extractfile(member)
            if source is None:
                raise SystemExit(f"unreadable archive member: {member.name}")
            with target.open("wb") as handle:
                while True:
                    block = source.read(1024 * 1024)
                    if not block:
                        break
                    handle.write(block)
            target.chmod(member.mode & 0o777)
        else:
            raise SystemExit(f"unsupported archive member: {member.name}")
PY_EXTRACT

ROOT_NAME=$(find "$TMP/extracted" -mindepth 1 -maxdepth 1 -type d -print | head -n1)
[ -n "$ROOT_NAME" ] || { echo "FAIL: runtime archive root missing" >&2; exit 1; }
cp "$MANIFEST" "$OUTPUT/external-manifest.json"
cp "$ROOT_NAME/manifest.json" "$OUTPUT/embedded-manifest.json"
(cd "$ROOT_NAME" && shasum -a 256 -c SHA256SUMS) >"$OUTPUT/sha256-verification.log"
: >"$OUTPUT/elf.log"
: >"$OUTPUT/ldd.log"
for NAME in platform-api platform-ops container-healthcheck catalog-mmap; do
  BIN="$ROOT_NAME/bin/$NAME"
  [ -x "$BIN" ] || { echo "FAIL: missing executable $NAME" >&2; exit 1; }
  file "$BIN" | tee -a "$OUTPUT/elf.log" | grep -Eq 'ELF 64-bit.*x86-64' || { echo "FAIL: $NAME is not Linux AMD64 ELF" >&2; exit 1; }
  readelf -h "$BIN" >>"$OUTPUT/elf.log"
  readelf -h "$BIN" | grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64' || { echo "FAIL: $NAME ELF machine mismatch" >&2; exit 1; }
  set +e
  ldd "$BIN" >"$OUTPUT/ldd-$NAME.txt" 2>&1
  LRC=$?
  set -e
  cat "$OUTPUT/ldd-$NAME.txt" >>"$OUTPUT/ldd.log"
  if grep -q 'not found' "$OUTPUT/ldd-$NAME.txt"; then
    echo "FAIL: unresolved shared library for $NAME" >&2
    exit 1
  fi
  if [ "$LRC" -ne 0 ] && ! grep -Eq 'not a dynamic executable|statically linked' "$OUTPUT/ldd-$NAME.txt"; then
    echo "FAIL: ldd failed for $NAME" >&2
    exit 1
  fi
done
set +e
"$ROOT_NAME/bin/catalog-mmap" >"$OUTPUT/catalog-smoke.stdout" 2>"$OUTPUT/catalog-smoke.stderr"
RC=$?
set -e
[ "$RC" -eq 1 ] || { echo "FAIL: catalog-mmap no-argument smoke returned $RC, expected 1" >&2; exit 1; }
grep -q '^catalog-mmap: usage: catalog-mmap ' "$OUTPUT/catalog-smoke.stderr" || { echo "FAIL: catalog-mmap usage smoke mismatch" >&2; exit 1; }
python3 - "$OUTPUT/qualification.json" "$ARCHIVE" "$MANIFEST" "$OUTPUT/portable-validation.json" "$RC" <<'PY_SUMMARY'
import hashlib
import json
import pathlib
import sys

sha = lambda path: hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
portable = json.load(open(sys.argv[4], encoding="utf-8"))
assert portable["status"] == "PASS"
out = {
    "schema": "openwatchlist.linux-amd64-runtime-qualification.v2",
    "status": "PASS",
    "archive": {"name": pathlib.Path(sys.argv[2]).name, "sha256": sha(sys.argv[2])},
    "manifest_sha256": sha(sys.argv[3]),
    "portable_validation_sha256": sha(sys.argv[4]),
    "target": {"os": "linux", "arch": "amd64", "elf_machine": "x86-64"},
    "executable_count": 4,
    "portable_elf_header_validation_performed": True,
    "dynamic_linker_validation_performed": True,
    "binary_execution_performed": True,
    "catalog_mmap_smoke_exit": int(sys.argv[5]),
    "compiler_invocation_performed": False,
    "compiler_required_on_runtime_host": False,
    "runtime_started": False,
    "deployment_performed": False,
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY_SUMMARY
echo "PASS: Linux AMD64 runtime asset qualification"
cat "$OUTPUT/qualification.json"
