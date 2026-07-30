#!/usr/bin/env bash
set -uo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd);. "$SCRIPT_DIR/lib.sh"
OUT="";APPROVAL="";ARG_ERROR=""
while [ $# -gt 0 ];do case "$1" in --output) if [ $# -lt 2 ]||[ -z "${2:-}" ];then ARG_ERROR='ERROR: --output requires a value';shift;else OUT=$2;shift 2;fi;;--approval) if [ $# -lt 2 ]||[ -z "${2:-}" ];then ARG_ERROR='ERROR: --approval requires a value';shift;else APPROVAL=$2;shift 2;fi;;*) ARG_ERROR="ERROR: unknown argument: $1";shift;;esac;done
r183_bootstrap_output "$OUT"||exit $?
payload_for(){ python3 - "$R183_POLICY" "$1" <<'PY'
import base64,json,sys
p=json.load(open(sys.argv[1]));name=sys.argv[2];h=next(x for x in p['hosts'] if x['name']==name);q={**p,'host':h,'action':'rollback','remote_archive':'/tmp/openwatchlist-r183-manual-rollback-unused.tar.gz'};print(base64.b64encode(json.dumps(q,separators=(',',':')).encode()).decode())
PY
}
ssh_for(){ python3 - "$R183_POLICY" "$1" <<'PY'
import json,sys
p=json.load(open(sys.argv[1]));print(next(x['ssh'] for x in p['hosts'] if x['name']==sys.argv[2]))
PY
}
rollback_worker(){
 local arg_error=${1:-} P=$R183_POLICY name payload
 r183_set_phase argument-validation;[ -z "$arg_error" ]||{ echo "$arg_error" >&2;return 2; }
 r183_set_phase operational-policy-validation;r183_require_operational_policy
 r183_set_phase required-tool-validation;r183_require_tools
 r183_set_phase rollback-authorization;[ "$APPROVAL" = "$(r183_json "$P" rollback_approval)" ]||{ echo 'ERROR: exact rollback approval missing' >&2;return 2; }
 echo '=== OpenWatchlist R2.4 r1.8.3.4 independently authorized rollback ===';echo "Evidence: $OUT";echo 'Authorized mutation: exact Opt1/Opt2 rc.4 owned runtime only; staged payloads remain'
 mkdir "$OUT/results"
 r183_set_phase controlled-runtime-rollback
 for name in opt1 opt2;do payload=$(payload_for "$name");python3 "$SCRIPT_DIR/bounded_ssh.py" --host "$(ssh_for "$name")" --script "$SCRIPT_DIR/remote_runtime_control.py" --payload "$payload" --output "$OUT/logs/$name-rollback-ssh.json" --timeout 300 >"$OUT/results/$name.json";done
 r183_update_journal remote_mutation_performed=true deployment_performed=false rollback_qualification_performed=true
 r183_set_phase rollback-evaluation
 python3 - "$OUT/results" "$OUT/summary.json" <<'PY'
import json,pathlib,sys
rows=[json.load(open(f)) for f in pathlib.Path(sys.argv[1]).glob('*.json')];bad=[x for x in rows if x.get('status')!='PASS' or x.get('runtime_active') is not False]
out={'schema':'openwatchlist.r2-4-r1-8-3-manual-rollback.v1','status':'PASS' if not bad and {x.get('host') for x in rows}=={'opt1','opt2'} else 'BLOCKED','runtime_active_hosts':[],'staged_payloads_preserved':True,'results':rows};pathlib.Path(sys.argv[2]).write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');raise SystemExit(0 if out['status']=='PASS' else 2)
PY
 r183_require_status "$OUT/summary.json" PASS;r183_complete;r183_checksum_tree "$OUT";echo "PASS: controlled rc.4 runtime rolled back; staged payloads preserved. Evidence: $OUT"
}
set +e;r183_guarded_run rollback_worker "$ARG_ERROR";rc=$?;set -e;exit "$rc"
