#!/usr/bin/env bash
set -euo pipefail
R183_SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
R183_ROOT=$(cd "$R183_SCRIPT_DIR/.." && pwd)
R183_POLICY=${R183_POLICY_OVERRIDE:-$R183_ROOT/config/policy.json}
R183_PHASE=initialization
R183_OUTPUT=""
R183_COMPLETED=false
r183_json(){ python3 - "$1" "$2" <<'PY'
import json,sys
x=json.load(open(sys.argv[1],encoding='utf-8'))
for p in sys.argv[2].split('.'):
 x=x[int(p)] if isinstance(x,list) else x[p]
if isinstance(x,(dict,list)):print(json.dumps(x,separators=(',',':')))
elif isinstance(x,bool):print(str(x).lower())
elif x is None:print('null')
else:print(x)
PY
}
r183_realpath(){ python3 - "$1" <<'PY'
import os,sys
print(os.path.realpath(os.path.expanduser(sys.argv[1])))
PY
}
r183_sha(){ shasum -a 256 "$1"|awk '{print $1}'; }
r183_checksum_tree(){ (cd "$1"&&find . -type f ! -name SHA256SUMS -print0|LC_ALL=C sort -z|xargs -0 shasum -a 256 >SHA256SUMS); }
r183_set_phase(){
 local phase=${1:-unknown};R183_PHASE=$phase;export R183_PHASE
 if [ -n "${R183_OUTPUT:-}" ]&&[ -d "$R183_OUTPUT" ];then
  python3 - "$R183_OUTPUT/phase.json.part" "$R183_OUTPUT/phase.json" "$phase" <<'PY'
import datetime,json,os,pathlib,sys
part,final,phase=sys.argv[1:]
x={'schema':'openwatchlist.r2-4-r1-8-3-4-phase.v1','phase':phase,'recorded_at':datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')}
pathlib.Path(part).write_text(json.dumps(x,sort_keys=True)+'\n');os.replace(part,final)
PY
 fi
}
r183_recorded_phase(){ if [ -f "${R183_OUTPUT:-}/phase.json" ];then r183_json "$R183_OUTPUT/phase.json" phase;else printf '%s\n' "${R183_PHASE:-unknown}";fi; }
r183_write_failure(){
 local rc=${1:-2} line=${2:-0} phase
 [ -d "${R183_OUTPUT:-}" ]||return 0
 phase=$(r183_recorded_phase 2>/dev/null||printf '%s\n' "${R183_PHASE:-unknown}")
 python3 - "$R183_OUTPUT/failure.json" "$phase" "$rc" "$line" "$R183_OUTPUT/mutation-journal.json" <<'PY'
import datetime,json,pathlib,sys
p,phase,rc,line,j=sys.argv[1:];m={}
try:m=json.load(open(j,encoding='utf-8'))
except Exception:pass
x={'schema':'openwatchlist.r2-4-r1-8-3-4-failure.v1','status':'FAILED_OR_BLOCKED','phase':phase,'exit_code':int(rc),'bash_line':int(line),'recorded_at':datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z'),**m}
pathlib.Path(p).write_text(json.dumps(x,indent=2,sort_keys=True)+'\n')
PY
 r183_checksum_tree "$R183_OUTPUT"||true
 echo "Evidence: $R183_OUTPUT" >&2
}
r183_bootstrap_output(){
 local requested=${1:-}
 [ -n "$requested" ]||{ echo 'ERROR: output required' >&2;return 2; }
 [ ! -e "$requested" ]||{ echo "ERROR: output exists: $requested" >&2;return 2; }
 mkdir -p "$requested/logs"
 R183_OUTPUT=$(r183_realpath "$requested");export R183_OUTPUT R183_PHASE
 printf '{"schema":"openwatchlist.r2-4-r1-8-3-4-startup.v1","status":"INITIALIZED","remote_mutation_performed":false,"activation_performed":false,"rollback_qualification_performed":false,"pre_mutation_qualification_performed":false,"deployment_performed":false}\n' >"$R183_OUTPUT/startup.json"
 printf '{"remote_mutation_performed":false,"activation_performed":false,"rollback_qualification_performed":false,"pre_mutation_qualification_performed":false,"deployment_performed":false,"automatic_rollback_attempted":false,"automatic_rollback_performed":false,"automatic_rollback_succeeded":false,"automatic_archive_cleanup_succeeded":false}\n' >"$R183_OUTPUT/mutation-journal.json"
 r183_set_phase initialization
}
r183_guarded_run(){
 local worker=${1:-};shift||true
 [ -n "$worker" ]||{ echo 'ERROR: guarded worker required' >&2;return 2; }
 set +e
 ( set -euo pipefail;"$worker" "$@" )
 local rc=$?
 if [ "$rc" -ne 0 ];then r183_write_failure "$rc" 0;return "$rc";fi
 return 0
}
r183_require_tools(){ local x;for x in gh python3 shasum ssh scp tar curl file;do command -v "$x" >/dev/null||{ echo "ERROR: required tool missing: $x" >&2;return 2;};done; }
r183_require_operational_policy(){
 local template
 [ -f "$R183_POLICY" ]||{ echo "ERROR: policy not found: $R183_POLICY" >&2;return 2;}
 template=$(r183_json "$R183_POLICY" public_template 2>/dev/null||printf '%s\n' true)
 [ "$template" = false ]||{ echo 'ERROR: committed public template is non-operational; set R183_POLICY_OVERRIDE to a private policy with public_template=false' >&2;return 2;}
}
r183_validate_checksums(){ [ -f "$1/SHA256SUMS" ]&&(cd "$1"&&shasum -a 256 -c SHA256SUMS >/dev/null)||{ echo "ERROR: evidence checksum failure: $1" >&2;return 2;}; }
r183_require_status(){ [ -f "$1" ]&&[ "$(r183_json "$1" status)" = "$2" ]||{ echo "ERROR: expected status $2 in $1" >&2;return 2;}; }
r183_complete(){ R183_COMPLETED=true;r183_set_phase completed; }
r183_update_journal(){ python3 - "$R183_OUTPUT/mutation-journal.json" "$@" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);x=json.load(open(p))
for arg in sys.argv[2:]:
 k,v=arg.split('=',1);x[k]=({'true':True,'false':False}.get(v,v))
p.write_text(json.dumps(x,sort_keys=True)+'\n')
PY
}
