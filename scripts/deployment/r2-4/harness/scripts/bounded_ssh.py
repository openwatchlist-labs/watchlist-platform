#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,pathlib,subprocess,sys,time
ap=argparse.ArgumentParser();ap.add_argument('--host',required=True);ap.add_argument('--script',required=True);ap.add_argument('--payload',required=True);ap.add_argument('--output',required=True);ap.add_argument('--timeout',type=int,default=120);a=ap.parse_args()
start=time.monotonic();out=pathlib.Path(a.output);out.parent.mkdir(parents=True,exist_ok=True)
cmd=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=15','-o','ServerAliveInterval=10','-o','ServerAliveCountMax=2',a.host,'python3','-',a.payload]
try:cp=subprocess.run(cmd,input=pathlib.Path(a.script).read_bytes(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=a.timeout)
except subprocess.TimeoutExpired as e:
 class CP:pass
 cp=CP();cp.returncode=124;cp.stdout=e.stdout or b'';cp.stderr=e.stderr or b''
out.with_suffix('.stdout').write_bytes(cp.stdout);out.with_suffix('.stderr').write_bytes(cp.stderr)
rec={'schema':'openwatchlist.r2-4-r1-8-bounded-ssh.v1','host':a.host,'returncode':cp.returncode,'elapsed_seconds':round(time.monotonic()-start,3),'timeout_seconds':a.timeout,'timed_out':cp.returncode==124}
out.write_text(json.dumps(rec,indent=2,sort_keys=True)+'\n',encoding='utf-8');sys.stdout.buffer.write(cp.stdout);sys.stderr.buffer.write(cp.stderr);raise SystemExit(cp.returncode)
