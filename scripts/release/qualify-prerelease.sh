#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd); . "$SCRIPT_DIR/common.sh"
VERSION=""; VCS_REF=""; SOURCE_DATE_EPOCH=""; OUT=""
while [ "$#" -gt 0 ]; do case "$1" in --version) VERSION=${2:-};shift 2;; --vcs-ref) VCS_REF=${2:-};shift 2;; --source-date-epoch) SOURCE_DATE_EPOCH=${2:-};shift 2;; --output) OUT=${2:-};shift 2;; *) release_fail "unknown argument: $1";; esac; done
release_require_empty "$OUT"
mkdir -p "$OUT"
[ -z "$(git status --short)" ] || release_fail "qualification requires a clean checkout"
[ "$(git rev-parse HEAD)" = "$VCS_REF" ] || release_fail "vcs-ref must equal checkout HEAD"
./scripts/ci/run-ci.sh >"$OUT/native-ci.log" 2>&1
./scripts/release/build-prerelease-assets.sh --version "$VERSION" --vcs-ref "$VCS_REF" --source-date-epoch "$SOURCE_DATE_EPOCH" --output "$OUT/run-a" >"$OUT/run-a.log" 2>&1
./scripts/release/build-prerelease-assets.sh --version "$VERSION" --vcs-ref "$VCS_REF" --source-date-epoch "$SOURCE_DATE_EPOCH" --output "$OUT/run-b" >"$OUT/run-b.log" 2>&1
python3 ./scripts/release/verify-reproducibility.py --left "$OUT/run-a" --right "$OUT/run-b" --output "$OUT/reproducibility.json" >"$OUT/reproducibility.txt" 2>&1
python3 - "$OUT/qualification-summary.json" "$VERSION" "$VCS_REF" "$SOURCE_DATE_EPOCH" "$OUT/reproducibility.json" <<'PY_QUAL_SUMMARY'
import json,sys,pathlib
result=json.load(open(sys.argv[5])); assert result['status']=='PASS'
out={'schema':'openwatchlist.public-prerelease-qualification.v2','status':'PASS','version':sys.argv[2],'vcs_ref':sys.argv[3],'source_date_epoch':int(sys.argv[4]),'native_ci_validated':True,'reproducible_build_validated':True,'qualification_runs':2,'artifact_file_count':result['file_count'],'publication_performed':False}
pathlib.Path(sys.argv[1]).write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
PY_QUAL_SUMMARY
echo "PASS: public prerelease qualification"
cat "$OUT/qualification-summary.json"
