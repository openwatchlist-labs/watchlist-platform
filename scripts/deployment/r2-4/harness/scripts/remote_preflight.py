#!/usr/bin/env python3
from __future__ import annotations
import base64,hashlib,json,os,pathlib,shutil,socket,subprocess,sys,urllib.request
p=json.loads(base64.b64decode(sys.argv[1]));h=p['host'];name=h['name'];stage=pathlib.Path(p['stage_root']);runtime=pathlib.Path(p['runtime_root']);active=pathlib.Path(p['active_link']);problems=[]
def sha(f):
 q=hashlib.sha256()
 with f.open('rb') as x:
  for b in iter(lambda:x.read(1024*1024),b''):q.update(b)
 return q.hexdigest()
def run(args,timeout=30):return subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout)
def url_json(url,timeout=10):
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));req=urllib.request.Request(url,headers={'User-Agent':'openwatchlist-r183-preflight'})
 with opener.open(req,timeout=timeout) as r:return r.status,json.loads(r.read().decode())
def url_status(url,timeout=10):
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));req=urllib.request.Request(url,headers={'User-Agent':'openwatchlist-r183-preflight'})
 with opener.open(req,timeout=timeout) as r:return r.status,r.read(4096).decode(errors='replace')
def tcp(host,port,timeout=3):
 try:
  with socket.create_connection((host,port),timeout=timeout):return True
 except OSError:return False
def port_free(port):
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 try:s.bind(('127.0.0.1',port));return True
 except OSError:return False
 finally:s.close()
def docker_ok():return shutil.which('docker') is not None and run(['docker','info','--format','{{.ServerVersion}}'],15).returncode==0
def protected_containers():
 cp=run(['docker','ps','--no-trunc','--format','{{json .}}'])
 if cp.returncode:raise RuntimeError(cp.stderr.strip())
 rows=[]
 for line in cp.stdout.splitlines():
  try:x=json.loads(line)
  except Exception:continue
  if x.get('Names')==p['opt1_postgres_container']:continue
  rows.append({k:x.get(k) for k in ('ID','Image','Names','Ports')})
 return sorted(rows,key=lambda x:(x.get('Names') or '',x.get('ID') or ''))
# Identity and exact stage bytes.
if socket.gethostname()!=h['hostname']:problems.append(f'hostname mismatch: {socket.gethostname()}')
manifest={};stage_fingerprint=''
try:
 manifest=json.load(open(stage/'REMOTE-STAGE-MANIFEST.json',encoding='utf-8'))
 if manifest.get('schema')!=p['staging_stage_manifest_schema'] or manifest.get('status')!='PASS' or manifest.get('host')!=name or manifest.get('release')!=p['target_tag']:problems.append('stage manifest identity mismatch')
 for item in manifest.get('files',[]):
  f=stage/item['path']
  if not f.is_file() or f.stat().st_size!=item['size'] or sha(f)!=item['sha256']:problems.append(f'stage drift: {item["path"]}')
 stage_fingerprint=sha(stage/'REMOTE-STAGE-MANIFEST.json')
except Exception as e:problems.append(f'stage verification failed: {e}')
if runtime.exists():problems.append('runtime root already exists')
if active.exists() or active.is_symlink():problems.append('active link already exists')
for exe in p['runtime_executables']:
 f=stage/'runtime/bin'/exe
 if not f.is_file() or f.read_bytes()[:4]!=b'\x7fELF':problems.append(f'staged executable invalid: {exe}')
protected=[];capability={}
try:
 if name=='opt1':
  if not docker_ok():problems.append('Docker daemon unavailable on Opt1')
  else:
   protected=protected_containers()
   if run(['docker','image','inspect',p['opt1_postgres_image']]).returncode:problems.append('governed PostgreSQL image unavailable locally')
   if run(['docker','container','inspect',p['opt1_postgres_container']]).returncode==0:problems.append('owned PostgreSQL container already exists')
   if run(['docker','volume','inspect',p['opt1_postgres_volume']]).returncode==0:problems.append('owned PostgreSQL volume already exists')
  for port in (8080,15432):
   if not port_free(port):problems.append(f'reserved port already bound: {port}')
  for secret in p['opt1_required_secrets']:
   f=stage/'secrets'/secret
   if not f.is_file() or (f.stat().st_mode&0o777)!=0o600 or f.stat().st_size==0:problems.append(f'Opt1 secret missing/invalid: {secret}')
  try:
   cfg=json.load(open(stage/'config/runtime.json'));review=json.load(open(stage/'config/review-console.json'));contract=json.load(open(stage/'config/activation-env-contract.json'))
   text='\n'.join((stage/'config'/n).read_text() for n in ['runtime.json','review-console.json','activation-env-contract.json'])
   if ':5432' in text or '"port": 5432' in text or '"port":5432' in text:problems.append('protected PostgreSQL port referenced by staged config')
   if review.get('ollama_base_url')!=p['g732']['opt1_ollama_base_url']:problems.append('Opt1 Ollama binding mismatch')
   pg=contract.get('postgresql',{})
   if pg.get('host')!='127.0.0.1' or pg.get('port')!=15432:problems.append('Opt1 PostgreSQL activation contract mismatch')
   status,tags=url_json(p['g732']['opt1_ollama_base_url']+'/api/tags')
   models=sorted({m.get('name') or m.get('model') for m in tags.get('models',[]) if isinstance(m,dict)})
   missing=[x for x in p['g732']['required_models'] if x not in models]
   if status!=200 or missing:problems.append(f'Opt1-to-G732 Ollama binding unavailable: missing={missing}')
   capability={'ollama_reachable_from_opt1':status==200,'models':models}
  except Exception as e:problems.append(f'Opt1 configuration/capability check failed: {e}')
 elif name=='g732':
  status,tags=url_json(p['g732']['ollama_base_url']+'/api/tags');models=sorted({m.get('name') or m.get('model') for m in tags.get('models',[]) if isinstance(m,dict)})
  missing=[x for x in p['g732']['required_models'] if x not in models]
  if status!=200 or missing:problems.append(f'G732 Ollama capability mismatch: missing={missing}')
  capability={'ollama_status':status,'models':models,'required_models_present':not missing}
 elif name=='opt2':
  capability={'catalog_mmap_elf':(stage/'runtime/bin/catalog-mmap').read_bytes()[:4]==b'\x7fELF'}
 elif name=='Thinkpad-P50':
  st,body=url_status(p['p50']['qdrant_health_url']);ports={str(x):tcp('127.0.0.1',int(x)) for x in p['p50']['required_tcp_ports']}
  if st!=200:problems.append('P50 Qdrant health endpoint failed')
  for k,v in ports.items():
   if not v:problems.append(f'P50 required TCP port unavailable: {k}')
  capability={'qdrant_status':st,'qdrant_body':body[:512],'tcp_ports':ports}
except Exception as e:problems.append(f'role capability check failed: {e}')
try:
 if name!='opt1' and docker_ok():protected=protected_containers()
except Exception as e:problems.append(f'protected container snapshot failed: {e}')
out={'schema':'openwatchlist.r2-4-r1-8-3-remote-preflight.v1','status':'PASS' if not problems else 'BLOCKED','host':name,'hostname':socket.gethostname(),'role':h['role'],'activation_mode':h['activation_mode'],'stage_root':str(stage),'stage_manifest_sha256':stage_fingerprint,'stage_file_count':manifest.get('file_count'),'runtime_root_exists':runtime.exists(),'active_link_exists':active.exists() or active.is_symlink(),'protected_containers':protected,'protected_containers_sha256':hashlib.sha256(json.dumps(protected,separators=(',',':'),sort_keys=True).encode()).hexdigest(),'capability':capability,'remote_mutation_performed':False,'compiler_required':False,'problems':problems}
print(json.dumps(out,indent=2,sort_keys=True));raise SystemExit(0 if not problems else 2)
