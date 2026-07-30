#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,pathlib,subprocess,time,sys
ap=argparse.ArgumentParser();ap.add_argument('--source',required=True);ap.add_argument('--host',required=True);ap.add_argument('--remote',required=True);ap.add_argument('--output',required=True);ap.add_argument('--timeout',type=int,default=600);a=ap.parse_args();start=time.monotonic();out=pathlib.Path(a.output)
try:cp=subprocess.run(['scp','-q','-o','BatchMode=yes','-o','ConnectTimeout=15',a.source,f'{a.host}:{a.remote}'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=a.timeout)
except subprocess.TimeoutExpired as e:
 class CP:pass
 cp=CP();cp.returncode=124;cp.stdout=e.stdout or b'';cp.stderr=e.stderr or b''
out.with_suffix('.stdout').write_bytes(cp.stdout);out.with_suffix('.stderr').write_bytes(cp.stderr);rec={'schema':'openwatchlist.r2-4-r1-8-bounded-scp.v1','host':a.host,'remote':a.remote,'returncode':cp.returncode,'elapsed_seconds':round(time.monotonic()-start,3),'timed_out':cp.returncode==124};out.write_text(json.dumps(rec,indent=2,sort_keys=True)+'\n');raise SystemExit(cp.returncode)
