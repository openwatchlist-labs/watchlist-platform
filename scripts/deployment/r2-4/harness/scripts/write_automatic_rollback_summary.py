#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,pathlib
ap=argparse.ArgumentParser()
ap.add_argument('--root',required=True)
ap.add_argument('--original-failure-phase',required=True)
ap.add_argument('--rollback-succeeded',choices=('true','false'),required=True)
ap.add_argument('--cleanup-succeeded',choices=('true','false'),required=True)
a=ap.parse_args()
root=pathlib.Path(a.root)
rollback_ok=a.rollback_succeeded=='true'
cleanup_ok=a.cleanup_succeeded=='true'
rows=[]
for host in ('opt1','opt2'):
 row={'host':host}
 for action in ('rollback','cleanup'):
  exit_path=root/f'{host}-{action}.exit.txt'
  result_path=root/f'{host}-{action}.json'
  row[action+'_returncode']=int(exit_path.read_text().strip()) if exit_path.is_file() else None
  if result_path.is_file():
   try:row[action+'_result']=json.loads(result_path.read_text())
   except Exception as exc:row[action+'_result_parse_error']=str(exc)
 rows.append(row)
out={'schema':'openwatchlist.r2-4-r1-8-3-4-automatic-rollback.v1','status':'PASS' if rollback_ok and cleanup_ok else 'FAILED_OR_BLOCKED','original_failure_phase':a.original_failure_phase,'rollback_succeeded':rollback_ok,'archive_cleanup_succeeded':cleanup_ok,'results':rows}
(root/'summary.json').write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
print(json.dumps(out,indent=2,sort_keys=True))
