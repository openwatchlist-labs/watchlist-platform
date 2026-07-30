#!/usr/bin/env bash
set -uo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd);. "$SCRIPT_DIR/lib.sh"
READINESS="";STAGING="";OUT="";APPROVAL="";ARG_ERROR=""
while [ $# -gt 0 ];do
 case "$1" in
  --readiness-evidence) if [ $# -lt 2 ]||[ -z "${2:-}" ];then ARG_ERROR='ERROR: --readiness-evidence requires a value';shift;else READINESS=$2;shift 2;fi;;
  --staging-evidence) if [ $# -lt 2 ]||[ -z "${2:-}" ];then ARG_ERROR='ERROR: --staging-evidence requires a value';shift;else STAGING=$2;shift 2;fi;;
  --output) if [ $# -lt 2 ]||[ -z "${2:-}" ];then ARG_ERROR='ERROR: --output requires a value';shift;else OUT=$2;shift 2;fi;;
  --approval) if [ $# -lt 2 ]||[ -z "${2:-}" ];then ARG_ERROR='ERROR: --approval requires a value';shift;else APPROVAL=$2;shift 2;fi;;
  *) ARG_ERROR="ERROR: unknown argument: $1";shift;;
 esac
done
r183_bootstrap_output "$OUT"||exit $?
payload_for(){
 python3 - "$R183_POLICY" "$1" "$2" "$3" <<'PY'
import base64,json,sys
p=json.load(open(sys.argv[1]));name,action,remote=sys.argv[2:];h=next(x for x in p['hosts'] if x['name']==name);q={**p,'host':h,'action':action,'remote_archive':remote};print(base64.b64encode(json.dumps(q,separators=(',',':')).encode()).decode())
PY
}
ssh_for(){ python3 - "$R183_POLICY" "$1" <<'PY'
import json,sys
p=json.load(open(sys.argv[1]));print(next(x['ssh'] for x in p['hosts'] if x['name']==sys.argv[2]))
PY
}
invoke(){
 local action=$1 name=$2 dest=$3 timeout=$4 remote=${5:-/tmp/openwatchlist-r183-none.tar.gz} host payload
 host=$(ssh_for "$name");payload=$(payload_for "$name" "$action" "$remote")
 python3 "$SCRIPT_DIR/bounded_ssh.py" --host "$host" --script "$SCRIPT_DIR/remote_runtime_control.py" --payload "$payload" --output "$OUT/logs/$name-$action-$(basename "$dest").ssh.json" --timeout "$timeout" >"$dest"
}
auto_rollback(){
 local run_id=$1 failed_phase=$2 name remote rc rollback_ok=true cleanup_ok=true
 mkdir -p "$OUT/automatic-rollback"
 r183_update_journal remote_mutation_performed=true automatic_rollback_attempted=true automatic_rollback_performed=true activation_performed=false deployment_performed=false original_failure_phase="$failed_phase"
 r183_set_phase automatic-global-rollback
 for name in opt1 opt2;do
  remote="/tmp/openwatchlist-r183-$run_id-$name.tar.gz"
  set +e;invoke rollback "$name" "$OUT/automatic-rollback/$name-rollback.json" 300 "$remote";rc=$?;set -e
  printf '%s\n' "$rc" >"$OUT/automatic-rollback/$name-rollback.exit.txt"
  [ "$rc" -eq 0 ]||rollback_ok=false
 done
 for name in opt1 opt2;do
  remote="/tmp/openwatchlist-r183-$run_id-$name.tar.gz"
  set +e;invoke cleanup-archive "$name" "$OUT/automatic-rollback/$name-cleanup.json" 120 "$remote";rc=$?;set -e
  printf '%s\n' "$rc" >"$OUT/automatic-rollback/$name-cleanup.exit.txt"
  [ "$rc" -eq 0 ]||cleanup_ok=false
 done
 python3 "$SCRIPT_DIR/write_automatic_rollback_summary.py" --root "$OUT/automatic-rollback" --original-failure-phase "$failed_phase" --rollback-succeeded "$rollback_ok" --cleanup-succeeded "$cleanup_ok" >"$OUT/automatic-rollback/summary.stdout.json"
 r183_update_journal automatic_rollback_succeeded="$rollback_ok" automatic_archive_cleanup_succeeded="$cleanup_ok"
 r183_set_phase "$failed_phase"
 [ "$rollback_ok" = true ]&&[ "$cleanup_ok" = true ]
}
activation_worker(){
 local arg_error=${1:-} P=$R183_POLICY RUN_ID rc name remote src failed_phase
 r183_set_phase argument-validation;[ -z "$arg_error" ]||{ echo "$arg_error" >&2;return 2; };[ -n "$READINESS" ]&&[ -n "$STAGING" ]||{ echo 'ERROR: readiness and staging evidence required' >&2;return 2; }
 r183_set_phase operational-policy-validation;r183_require_operational_policy
 r183_set_phase required-tool-validation;r183_require_tools
 r183_set_phase activation-authorization;[ "$APPROVAL" = "$(r183_json "$P" activation_approval)" ]||{ echo 'ERROR: exact activation approval missing' >&2;return 2; }
 r183_set_phase evidence-validation
 READINESS=$(r183_realpath "$READINESS");STAGING=$(r183_realpath "$STAGING");r183_validate_checksums "$READINESS";r183_validate_checksums "$STAGING";r183_require_status "$READINESS/summary.json" "$(r183_json "$P" activation_readiness_status)";r183_require_status "$STAGING/summary.json" "$(r183_json "$P" staging_status)"
 python3 - "$P" "$READINESS/summary.json" "$STAGING/summary.json" <<'PY'
import hashlib,json,pathlib,sys
policy=json.load(open(sys.argv[1],encoding='utf-8'));readiness=json.load(open(sys.argv[2],encoding='utf-8'));staging_path=pathlib.Path(sys.argv[3]);staging=json.load(open(staging_path,encoding='utf-8'))
if readiness.get('schema')!='openwatchlist.r2-4-r1-8-3-4-activation-readiness.v1':raise SystemExit('r1.8.3.4 readiness schema required')
if readiness.get('source_lock',{}).get('status')!='PASS' or readiness.get('source_lock',{}).get('source_count')!=5:raise SystemExit('commit-pinned source lock not accepted')
if readiness.get('input_validation',{}).get('corpus_validation',{}).get('status')!='PASS':raise SystemExit('governed corpus validation not accepted')
if readiness.get('pre_mutation_opt1_qualification_required') is not True:raise SystemExit('Opt1 pre-mutation qualification contract absent')
if readiness.get('complete_temporary_root_rebinding_required') is not True:raise SystemExit('complete temporary-root rebinding contract absent')
if readiness.get('qualification_first_opt2_transfer_required') is not True:raise SystemExit('qualification-first Opt2 transfer contract absent')
if readiness.get('staging_evidence_sha256')!=hashlib.sha256(staging_path.read_bytes()).hexdigest():raise SystemExit('staging evidence binding mismatch')
fixture=next((x for x in readiness.get('input_validation',{}).get('inputs',[]) if x.get('name')=='corpus-snapshot.json'),{})
if fixture.get('size')!=policy['corpus']['source_snapshot_size'] or fixture.get('sha256')!=policy['corpus']['source_snapshot_sha256']:raise SystemExit('governed corpus source identity mismatch')
PY
 echo '=== OpenWatchlist R2.4 r1.8.3.4 source-locked activation, complete temporary-root configuration rebinding, qualification-first transfer, rollback qualification, and controlled reactivation ===';echo "Evidence: $OUT";echo 'Authorized mutation: Opt1/Opt2 exact rc.4 runtime roots and active link; Opt1 owned PostgreSQL container/volume and API process; /tmp activation-input archives'
 RUN_ID="r183-$(date -u +%Y%m%dT%H%M%SZ)-$$";mkdir "$OUT/fresh-preflight" "$OUT/capability-first" "$OUT/pre-mutation-qualification" "$OUT/activate-first" "$OUT/smoke-first" "$OUT/rollback-results" "$OUT/rollback-inspection" "$OUT/activate-final" "$OUT/smoke-final" "$OUT/capability-final"
 r183_set_phase fresh-preactivation-stage-and-capability-revalidation
 python3 - "$P" <<'PY' >"$OUT/preflight-hosts.tsv"
import base64,json,sys
p=json.load(open(sys.argv[1]))
for h in p['hosts']:
 q={**p,'host':h};print(h['name']+'\t'+h['ssh']+'\t'+base64.b64encode(json.dumps(q,separators=(',',':')).encode()).decode())
PY
 while IFS=$'\t' read -r name host payload;do python3 "$SCRIPT_DIR/bounded_ssh.py" --host "$host" --script "$SCRIPT_DIR/remote_preflight.py" --payload "$payload" --output "$OUT/logs/$name-fresh-preflight-ssh.json" --timeout "$(r183_json "$P" readiness_timeout_seconds)" >"$OUT/fresh-preflight/$name.json";done <"$OUT/preflight-hosts.tsv"
 python3 - "$READINESS/preflights" "$OUT/fresh-preflight" <<'PY'
import json,pathlib,sys
old={json.load(open(f))['host']:json.load(open(f)) for f in pathlib.Path(sys.argv[1]).glob('*.json')};new={json.load(open(f))['host']:json.load(open(f)) for f in pathlib.Path(sys.argv[2]).glob('*.json')}
if set(old)!=set(new):raise SystemExit('preflight host set drift')
for h in old:
 for k in ('stage_manifest_sha256','protected_containers_sha256'):
  if old[h].get(k)!=new[h].get(k):raise SystemExit(f'{h} {k} drift')
 if new[h].get('status')!='PASS':raise SystemExit(f'{h} fresh preflight failed')
PY
 transfer_archive(){
  local name=$1 remote src
  remote="/tmp/openwatchlist-r183-$RUN_ID-$name.tar.gz"
  src="$READINESS/input-archives/$name-activation-inputs.tar.gz"
  python3 "$SCRIPT_DIR/bounded_scp.py" --source "$src" --host "$(ssh_for "$name")" --remote "$remote" --output "$OUT/logs/$name-input-scp.json" --timeout 300
 }
 r183_set_phase opt1-activation-input-transfer-before-qualification
 r183_update_journal remote_mutation_performed=true
 set +e;transfer_archive opt1;rc=$?;set -e
 if [ "$rc" -ne 0 ];then failed_phase=$(r183_recorded_phase);auto_rollback "$RUN_ID" "$failed_phase"||true;echo 'ERROR: Opt1 activation input transfer failed; cleanup/rollback attempted' >&2;return "$rc";fi
 r183_update_journal opt1_archive_transferred=true opt2_archive_transferred=false
 activation_sequence(){
  r183_set_phase role-bounded-capability-verification-before-activation
  invoke capability g732 "$OUT/capability-first/g732.json" 120 || return $?;invoke capability Thinkpad-P50 "$OUT/capability-first/Thinkpad-P50.json" 120 || return $?
  r183_set_phase opt1-pre-mutation-configuration-qualification
  invoke qualify opt1 "$OUT/pre-mutation-qualification/opt1.json" 300 "/tmp/openwatchlist-r183-$RUN_ID-opt1.tar.gz" || return $?
  r183_update_journal pre_mutation_qualification_performed=true
  r183_set_phase opt2-activation-input-transfer-after-opt1-qualification
  transfer_archive opt2 || return $?
  r183_update_journal opt2_archive_transferred=true
  r183_set_phase first-controlled-activation
  invoke activate opt2 "$OUT/activate-first/opt2.json" 300 "/tmp/openwatchlist-r183-$RUN_ID-opt2.tar.gz" || return $?;invoke activate opt1 "$OUT/activate-first/opt1.json" "$(r183_json "$P" activation_timeout_seconds)" "/tmp/openwatchlist-r183-$RUN_ID-opt1.tar.gz" || return $?
  r183_set_phase first-smoke-qualification
  invoke smoke opt2 "$OUT/smoke-first/opt2.json" 120 "/tmp/openwatchlist-r183-$RUN_ID-opt2.tar.gz" || return $?;invoke smoke opt1 "$OUT/smoke-first/opt1.json" 180 "/tmp/openwatchlist-r183-$RUN_ID-opt1.tar.gz" || return $?
  r183_set_phase full-rollback-qualification
  invoke rollback opt1 "$OUT/rollback-results/opt1.json" 300 "/tmp/openwatchlist-r183-$RUN_ID-opt1.tar.gz" || return $?;invoke rollback opt2 "$OUT/rollback-results/opt2.json" 300 "/tmp/openwatchlist-r183-$RUN_ID-opt2.tar.gz" || return $?
  invoke inspect opt1 "$OUT/rollback-inspection/opt1.json" 120 "/tmp/openwatchlist-r183-$RUN_ID-opt1.tar.gz" || return $?;invoke inspect opt2 "$OUT/rollback-inspection/opt2.json" 120 "/tmp/openwatchlist-r183-$RUN_ID-opt2.tar.gz" || return $?
  r183_update_journal rollback_qualification_performed=true
  r183_set_phase controlled-reactivation
  invoke activate opt2 "$OUT/activate-final/opt2.json" 300 "/tmp/openwatchlist-r183-$RUN_ID-opt2.tar.gz" || return $?;invoke activate opt1 "$OUT/activate-final/opt1.json" "$(r183_json "$P" activation_timeout_seconds)" "/tmp/openwatchlist-r183-$RUN_ID-opt1.tar.gz" || return $?
  r183_set_phase final-smoke-and-capability-qualification
  invoke smoke opt2 "$OUT/smoke-final/opt2.json" 120 "/tmp/openwatchlist-r183-$RUN_ID-opt2.tar.gz" || return $?;invoke smoke opt1 "$OUT/smoke-final/opt1.json" 180 "/tmp/openwatchlist-r183-$RUN_ID-opt1.tar.gz" || return $?
  invoke capability g732 "$OUT/capability-final/g732.json" 120 || return $?;invoke capability Thinkpad-P50 "$OUT/capability-final/Thinkpad-P50.json" 120 || return $?
  return 0
 }
 set +e;activation_sequence;rc=$?;set -e
 if [ "$rc" -ne 0 ];then failed_phase=$(r183_recorded_phase);auto_rollback "$RUN_ID" "$failed_phase"||true;echo 'ERROR: controlled activation sequence failed; automatic rollback attempted' >&2;return "$rc";fi
 r183_set_phase deployment-evaluation
 set +e
 python3 "$SCRIPT_DIR/evaluate_deployment.py" --policy "$P" --pre-mutation-qualification "$OUT/pre-mutation-qualification/opt1.json" --first-smoke "$OUT/smoke-first" --rollback-inspection "$OUT/rollback-inspection" --final-smoke "$OUT/smoke-final" --capability-first "$OUT/capability-first" --capability-final "$OUT/capability-final" --preflight "$OUT/fresh-preflight" --output "$OUT/summary.json"
 rc=$?
 set -e
 if [ "$rc" -ne 0 ];then failed_phase=$(r183_recorded_phase);auto_rollback "$RUN_ID" "$failed_phase"||true;echo 'ERROR: deployment closure evaluation failed; automatic rollback attempted' >&2;return "$rc";fi
 r183_require_status "$OUT/summary.json" "$(r183_json "$P" final_status)"
 r183_set_phase remote-temporary-input-cleanup
 set +e
 rc=0
 for name in opt1 opt2;do remote="/tmp/openwatchlist-r183-$RUN_ID-$name.tar.gz";invoke cleanup-archive "$name" "$OUT/logs/$name-archive-cleanup.json" 120 "$remote" >/dev/null||{ rc=$?;break;};done
 set -e
 if [ "$rc" -ne 0 ];then failed_phase=$(r183_recorded_phase);auto_rollback "$RUN_ID" "$failed_phase"||true;echo 'ERROR: remote activation-input cleanup failed; automatic rollback attempted' >&2;return "$rc";fi
 r183_update_journal activation_performed=true deployment_performed=true
 r183_complete;r183_checksum_tree "$OUT"
 echo 'PASS: exact source-locked Opt1 inputs were prequalified before persistent mutation; Opt1 gateway/PostgreSQL and Opt2 catalog runtime were activated, smoke-tested, fully rolled back, protected state verified, and reactivated; G732/P50 remained capability-only';echo "Evidence: $OUT"
}
set +e;r183_guarded_run activation_worker "$ARG_ERROR";rc=$?;set -e;exit "$rc"
