#!/usr/bin/env python3
from __future__ import annotations
import argparse,base64,hashlib,json,pathlib,subprocess,sys,urllib.parse
ap=argparse.ArgumentParser();ap.add_argument('--policy',required=True);ap.add_argument('--root',required=True);ap.add_argument('--output',required=True);a=ap.parse_args()
p=json.load(open(a.policy,encoding='utf-8'));root=pathlib.Path(a.root);sources=json.load(open(root/'inputs/SOURCES.json',encoding='utf-8'));problems=[];rows=[]
if sources.get('repository')!=p['repository'] or sources.get('commit')!=p['main_commit']:problems.append('source-lock boundary mismatch')
for spec in sources.get('sources',[]):
 local=root/spec['local_path'];local_raw=local.read_bytes() if local.is_file() else b'';endpoint=f"repos/{p['repository']}/contents/{urllib.parse.quote(spec['source_path'],safe='/')}?ref={p['main_commit']}"
 cp=subprocess.run(['gh','api','-H','Accept: application/vnd.github+json','-H',f"X-GitHub-Api-Version: {p['api_version']}",endpoint],text=True,capture_output=True)
 remote=b'';metadata={}
 if cp.returncode:
  problems.append(f"source-lock API failure: {spec['name']}: {cp.stderr.strip()}")
 else:
  try:
   metadata=json.loads(cp.stdout)
   if metadata.get('type')!='file' or metadata.get('encoding')!='base64':raise ValueError('unexpected contents response')
   remote=base64.b64decode(''.join(str(metadata.get('content','')).split()),validate=True)
  except Exception as e:problems.append(f"source-lock response invalid: {spec['name']}: {e}")
 local_sha=hashlib.sha256(local_raw).hexdigest();remote_sha=hashlib.sha256(remote).hexdigest() if remote else None
 exact=(remote==local_raw and len(local_raw)==spec['size'] and local_sha==spec['sha256'])
 if not exact:problems.append(f"commit-pinned source-lock mismatch: {spec['name']}")
 rows.append({'name':spec['name'],'role':spec['role'],'source_path':spec['source_path'],'local_path':spec['local_path'],'git_blob_sha':metadata.get('sha'),'expected_size':spec['size'],'local_size':len(local_raw),'remote_size':len(remote),'expected_sha256':spec['sha256'],'local_sha256':local_sha,'remote_sha256':remote_sha,'byte_equal':remote==local_raw,'status':'PASS' if exact else 'BLOCKED'})
out={'schema':'openwatchlist.r2-4-r1-8-3-4-source-lock-verification.v1','status':'PASS' if not problems else 'BLOCKED','repository':p['repository'],'commit':p['main_commit'],'source_count':len(rows),'sources':rows,'remote_mutation_performed':False,'problems':problems}
pathlib.Path(a.output).write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');print(json.dumps(out,indent=2,sort_keys=True));raise SystemExit(0 if not problems else 2)
