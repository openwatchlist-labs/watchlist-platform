#!/usr/bin/env bash
set -uo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd);. "$SCRIPT_DIR/lib.sh"
STAGING="";OUT="";ARG_ERROR=""
while [ $# -gt 0 ];do
 case "$1" in
  --staging-evidence) if [ $# -lt 2 ]||[ -z "${2:-}" ];then ARG_ERROR='ERROR: --staging-evidence requires a value';shift;else STAGING=$2;shift 2;fi;;
  --output) if [ $# -lt 2 ]||[ -z "${2:-}" ];then ARG_ERROR='ERROR: --output requires a value';shift;else OUT=$2;shift 2;fi;;
  *) ARG_ERROR="ERROR: unknown argument: $1";shift;;
 esac
done
r183_bootstrap_output "$OUT"||exit $?
readiness_worker(){
 local arg_error=${1:-} P=$R183_POLICY name host payload
 r183_set_phase argument-validation;[ -z "$arg_error" ]||{ echo "$arg_error" >&2;return 2; };[ -n "$STAGING" ]||{ echo 'ERROR: staging evidence required' >&2;return 2; }
 r183_set_phase operational-policy-validation;r183_require_operational_policy
 r183_set_phase required-tool-validation;r183_require_tools
 r183_set_phase accepted-staging-evidence-validation
 STAGING=$(r183_realpath "$STAGING");r183_validate_checksums "$STAGING";r183_require_status "$STAGING/summary.json" "$(r183_json "$P" staging_status)"
 [ "$(r183_json "$STAGING/summary.json" schema)" = "$(r183_json "$P" staging_summary_schema)" ]||{ echo 'ERROR: staging summary schema mismatch' >&2;return 2; }
 [ "$(r183_json "$STAGING/summary.json" runtime_started)" = false ]||{ echo 'ERROR: staging evidence is not no-start' >&2;return 2; }
 echo '=== OpenWatchlist R2.4 r1.8.3.4 controlled activation readiness ===';echo "Staging evidence: $STAGING";echo "Evidence: $OUT";echo 'Mutation: none'
 r183_set_phase activation-input-validation
 python3 "$SCRIPT_DIR/validate_inputs.py" --policy "$P" --root "$R183_ROOT" --output "$OUT/input-validation.json" >"$OUT/logs/input-validation.log"
 r183_set_phase independent-commit-pinned-source-lock-verification
 python3 "$SCRIPT_DIR/verify_source_lock.py" --policy "$P" --root "$R183_ROOT" --output "$OUT/source-lock.json" >"$OUT/logs/source-lock.log"
 r183_set_phase deterministic-input-archive-build
 python3 "$SCRIPT_DIR/build_input_archives.py" --policy "$P" --root "$R183_ROOT" --output "$OUT/input-archives" >"$OUT/logs/input-archives.log"
 r183_set_phase four-host-staged-payload-and-capability-revalidation
 mkdir "$OUT/preflights"
 python3 - "$P" <<'PY' >"$OUT/hosts.tsv"
import base64,json,sys
p=json.load(open(sys.argv[1]))
for h in p['hosts']:
 q={**p,'host':h};print(h['name']+'\t'+h['ssh']+'\t'+base64.b64encode(json.dumps(q,separators=(',',':')).encode()).decode())
PY
 while IFS=$'\t' read -r name host payload;do
  python3 "$SCRIPT_DIR/bounded_ssh.py" --host "$host" --script "$SCRIPT_DIR/remote_preflight.py" --payload "$payload" --output "$OUT/logs/$name-preflight-ssh.json" --timeout "$(r183_json "$P" readiness_timeout_seconds)" >"$OUT/preflights/$name.json"
 done <"$OUT/hosts.tsv"
 r183_set_phase activation-readiness-evaluation
 python3 "$SCRIPT_DIR/evaluate_activation_readiness.py" --policy "$P" --staging-summary "$STAGING/summary.json" --input-validation "$OUT/input-validation.json" --source-lock "$OUT/source-lock.json" --archives "$OUT/input-archives/summary.json" --preflights "$OUT/preflights" --output "$OUT/summary.json"
 r183_require_status "$OUT/summary.json" "$(r183_json "$P" activation_readiness_status)"
 cp "$STAGING/summary.json" "$OUT/accepted-staging-summary.json"
 r183_complete;r183_checksum_tree "$OUT"
 echo 'PASS: staged rc.4 payloads, exact commit-pinned sources, governed corpus checksums, activation inputs, Opt1/G732 binding, Opt2 catalog binary, and P50 capabilities are ready';echo "Evidence: $OUT";echo 'STOP: review summary.json before activation.'
}
set +e;r183_guarded_run readiness_worker "$ARG_ERROR";rc=$?;set -e;exit "$rc"
