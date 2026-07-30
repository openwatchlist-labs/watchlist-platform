#!/usr/bin/env python3
from __future__ import annotations
import argparse,gzip,hashlib,json,pathlib,tarfile
ap=argparse.ArgumentParser();ap.add_argument('--policy',required=True);ap.add_argument('--root',required=True);ap.add_argument('--output',required=True);a=ap.parse_args()
p=json.load(open(a.policy));root=pathlib.Path(a.root);out=pathlib.Path(a.output);out.mkdir(parents=True,exist_ok=False)
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def archive(role,sub,specs):
 dst=out/f'{role}-activation-inputs.tar.gz'
 with dst.open('wb') as raw:
  with gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0,compresslevel=6) as gz:
   with tarfile.open(fileobj=gz,mode='w',format=tarfile.USTAR_FORMAT) as tf:
    for spec in sorted(specs,key=lambda x:x['name']):
     f=root/sub/spec['name'];info=tarfile.TarInfo(spec['name']);info.size=f.stat().st_size;info.mode=0o600;info.uid=info.gid=0;info.uname=info.gname='';info.mtime=0
     with f.open('rb') as src:tf.addfile(info,src)
 return {'role':role,'archive':dst.name,'size':dst.stat().st_size,'sha256':sha(dst),'files':specs}
rows=[archive('opt1','opt1-inputs',p['opt1_input_files']),archive('opt2','opt2-inputs',p['opt2_input_files'])]
summary={'schema':'openwatchlist.r2-4-r1-8-3-4-activation-input-archives.v1','status':'PASS','archive_count':2,'archives':rows}
(out/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n');print(json.dumps(summary,indent=2,sort_keys=True))
