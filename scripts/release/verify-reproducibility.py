#!/usr/bin/env python3
import argparse,hashlib,json,pathlib
p=argparse.ArgumentParser(); p.add_argument('--left',required=True); p.add_argument('--right',required=True); p.add_argument('--output',required=True); a=p.parse_args()
def census(root):
    root=pathlib.Path(root); out={}
    for file in sorted(x for x in root.rglob('*') if x.is_file()):
        rel=file.relative_to(root).as_posix()
        if rel=='SHA256SUMS': continue
        out[rel]=hashlib.sha256(file.read_bytes()).hexdigest()
    return out
left=census(a.left); right=census(a.right)
missing=sorted(set(left)-set(right)); extra=sorted(set(right)-set(left)); different=sorted(k for k in set(left)&set(right) if left[k]!=right[k]); problems=[]
if missing: problems.append({'missing_from_right':missing})
if extra: problems.append({'extra_in_right':extra})
if different: problems.append({'hash_mismatch':different})
out={'schema':'openwatchlist.prerelease-reproducibility.v2','status':'PASS' if not problems else 'FAIL','file_count':len(left),'problems':problems,'hashes':left if not problems else {}}
pathlib.Path(a.output).write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
print(json.dumps(out,indent=2,sort_keys=True))
raise SystemExit(0 if not problems else 1)
