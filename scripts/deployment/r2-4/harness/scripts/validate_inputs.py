#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, pathlib, sys

ap=argparse.ArgumentParser()
ap.add_argument('--policy',required=True);ap.add_argument('--root',required=True);ap.add_argument('--output',required=True)
a=ap.parse_args()
p=json.load(open(a.policy,encoding='utf-8'));root=pathlib.Path(a.root);problems=[];rows=[]

def sha_bytes(raw:bytes)->str:return hashlib.sha256(raw).hexdigest()
def canonical(obj)->bytes:return json.dumps(obj,ensure_ascii=False,separators=(',',':'),sort_keys=True).encode('utf-8')
def hash_object(obj)->str:return sha_bytes(canonical(obj))
def split_passages(text:str)->list[str]:
 text=text.replace('\r\n','\n')
 return [' '.join(part.split()) for part in text.split('\n\n') if ' '.join(part.split())]

def compile_snapshot(manifest:dict)->dict:
 docs=sorted(manifest['documents'],key=lambda x:x['document_id']);passages=[]
 manifest_sha=hash_object({**manifest,'documents':docs})
 for doc in docs:
  for i,text in enumerate(split_passages(doc['text']),1):
   text_sha=sha_bytes(text.encode('utf-8'));identity=f"{doc['document_id']}:{i:04d}:{text_sha}"
   passages.append({'passage_id':'passage_'+sha_bytes(identity.encode())[:24],'document_id':doc['document_id'],'tenant_id':doc['tenant_id'],'kind':doc['kind'],'title':doc['title'],'source_ref':doc['source_ref'],'effective_at':doc['effective_at'],'ordinal':i,'text':text,'text_sha256':text_sha})
 passages.sort(key=lambda x:x['passage_id'])
 snapshot={'schema_version':'openwatchlist.rag-corpus-snapshot.v1','corpus_id':manifest['corpus_id'],'version':manifest['version'],'built_at':manifest['built_at'],'manifest_sha256':manifest_sha,'passage_count':len(passages),'passages':passages,'snapshot_sha256':''}
 snapshot['snapshot_sha256']=hash_object(snapshot)
 return snapshot

for role,key,sub in [('opt1','opt1_input_files','opt1-inputs'),('opt2','opt2_input_files','opt2-inputs')]:
 for spec in p[key]:
  f=root/sub/spec['name']
  if not f.is_file():problems.append(f'missing input: {role}/{spec["name"]}');continue
  b=f.read_bytes();d=sha_bytes(b)
  if len(b)!=spec['size']:problems.append(f'input size mismatch: {role}/{spec["name"]}')
  if d!=spec['sha256']:problems.append(f'input digest mismatch: {role}/{spec["name"]}')
  rows.append({'role':role,'name':spec['name'],'size':len(b),'sha256':d})

corpus_result={'status':'BLOCKED','passage_count':0,'passages':[],'manifest_sha256':None,'snapshot_sha256':None,'source_snapshot_sha256':None,'source_manifest_sha256':None,'problems':[]}
try:
 sources=json.load(open(root/'inputs/SOURCES.json',encoding='utf-8'))
 if sources.get('repository')!=p['repository'] or sources.get('commit')!=p['main_commit']:problems.append('activation input source boundary mismatch')
 source_rows={(x.get('role'),x.get('name')):x for x in sources.get('sources',[])}
 expected_names=set(p['source_commit_paths'])
 if {x.get('name') for x in sources.get('sources',[])}!=expected_names:problems.append('source-lock file set mismatch')
 expected_prefix='https://raw.githubusercontent.com/'+p['repository']+'/'+p['main_commit']+'/'
 for source in sources.get('sources',[]):
  local=root/str(source.get('local_path',''));raw_local=local.read_bytes() if local.is_file() else b'';name=source.get('name')
  if source.get('source_path')!=p['source_commit_paths'].get(name):problems.append(f'source-lock path mismatch: {name}')
  if source.get('source_url')!=expected_prefix+str(source.get('source_path','')):problems.append(f'source-lock URL mismatch: {name}')
  if source.get('size')!=len(raw_local) or source.get('sha256')!=sha_bytes(raw_local):problems.append(f'source-lock local identity mismatch: {name}')
 for row in rows:
  source=source_rows.get((row['role'],row['name']))
  if not source or source.get('sha256')!=row['sha256'] or source.get('size')!=row['size']:problems.append(f'activation input source record mismatch: {row["role"]}/{row["name"]}')
 alert=json.load(open(root/'opt1-inputs/alert-policy.json',encoding='utf-8'));ident=json.load(open(root/'opt1-inputs/identity-registry.json',encoding='utf-8'))
 if not isinstance(alert,dict) or not isinstance(ident,dict):problems.append('Opt1 JSON fixture shape mismatch')
 snapshot_path=root/p['corpus']['snapshot_local_path'];manifest_path=root/p['corpus']['manifest_local_path']
 snapshot_raw=snapshot_path.read_bytes();manifest_raw=manifest_path.read_bytes();snapshot=json.loads(snapshot_raw);manifest=json.loads(manifest_raw)
 cproblems=[]
 if len(snapshot_raw)!=p['corpus']['source_snapshot_size'] or sha_bytes(snapshot_raw)!=p['corpus']['source_snapshot_sha256']:cproblems.append('corpus source snapshot byte identity mismatch')
 if len(manifest_raw)!=p['corpus']['source_manifest_size'] or sha_bytes(manifest_raw)!=p['corpus']['source_manifest_sha256']:cproblems.append('corpus source manifest byte identity mismatch')
 if snapshot.get('schema_version')!=p['corpus']['snapshot_schema']:cproblems.append('corpus snapshot schema mismatch')
 if manifest.get('schema_version')!=p['corpus']['manifest_schema']:cproblems.append('corpus manifest schema mismatch')
 passages=snapshot.get('passages') if isinstance(snapshot.get('passages'),list) else []
 if snapshot.get('passage_count')!=len(passages) or len(passages)!=p['corpus']['passage_count']:cproblems.append('corpus passage count mismatch')
 seen=set();passage_rows=[]
 for item in passages:
  pid=item.get('passage_id');text=item.get('text');expected=item.get('text_sha256');actual=sha_bytes(str(text).encode('utf-8')) if isinstance(text,str) else None
  if not pid or pid in seen:cproblems.append(f'corpus duplicate or empty passage id: {pid}')
  seen.add(pid)
  if actual!=expected:cproblems.append(f'corpus passage checksum mismatch: {pid}')
  passage_rows.append({'passage_id':pid,'text_sha256':actual,'expected_text_sha256':expected,'status':'PASS' if actual==expected else 'BLOCKED'})
 compiled=compile_snapshot(manifest)
 if snapshot.get('manifest_sha256')!=p['corpus']['manifest_sha256'] or compiled['manifest_sha256']!=p['corpus']['manifest_sha256']:cproblems.append('corpus manifest checksum mismatch')
 snap_copy=dict(snapshot);expected_snapshot=snap_copy.get('snapshot_sha256');snap_copy['snapshot_sha256']='';actual_snapshot=hash_object(snap_copy)
 if expected_snapshot!=p['corpus']['snapshot_sha256'] or actual_snapshot!=p['corpus']['snapshot_sha256']:cproblems.append('corpus snapshot checksum mismatch')
 if compiled!=snapshot:cproblems.append('corpus snapshot does not exactly compile from governed manifest')
 corpus_result={'status':'PASS' if not cproblems else 'BLOCKED','passage_count':len(passages),'passages':passage_rows,'manifest_sha256':compiled.get('manifest_sha256'),'snapshot_sha256':actual_snapshot,'source_snapshot_sha256':sha_bytes(snapshot_raw),'source_manifest_sha256':sha_bytes(manifest_raw),'compiled_snapshot_exact_match':compiled==snapshot,'problems':cproblems}
 problems.extend(cproblems)
except Exception as e:problems.append(f'Opt1 governed corpus validation failed: {e}');corpus_result['problems'].append(str(e))

raw=(root/'opt2-inputs/ofac-fixture.owcin').read_text(encoding='utf-8') if (root/'opt2-inputs/ofac-fixture.owcin').is_file() else ''
try:
 lines=[line.split('\t') for line in raw.splitlines()];ids={bytes.fromhex(parts[1]).decode() for parts in lines if parts[0]=='R'};aliases=[bytes.fromhex(parts[3]).decode() for parts in lines if parts[0]=='N' and parts[2]=='alias']
 if not {'ofac:sdn:1001','ofac:sdn:3003'}<=ids:problems.append('catalog fixture identity mismatch')
 if 'Джордан Экзампл' not in aliases or 'Джордан Экзапл' in aliases:problems.append('catalog fixture exact Cyrillic alias mismatch')
 if sha_bytes(raw.encode())!=p['catalog']['source_input_sha256'] or len(raw.encode())!=p['catalog']['source_input_size']:problems.append('catalog fixture governed source identity mismatch')
except Exception as e:problems.append(f'catalog fixture parsing failed: {e}')
out={'schema':'openwatchlist.r2-4-r1-8-3-4-activation-input-validation.v1','status':'PASS' if not problems else 'BLOCKED','input_count':len(rows),'inputs':rows,'corpus_validation':corpus_result,'catalog_fixture_is_nonproduction_conformance_data':True,'problems':problems}
pathlib.Path(a.output).write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');print(json.dumps(out,indent=2,sort_keys=True));raise SystemExit(0 if not problems else 2)
