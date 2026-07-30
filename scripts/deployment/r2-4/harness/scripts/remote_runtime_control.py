#!/usr/bin/env python3
from __future__ import annotations
import base64,hashlib,json,os,pathlib,shutil,signal,socket,subprocess,sys,tarfile,time,urllib.parse,urllib.request
p=json.loads(base64.b64decode(sys.argv[1]));action=p['action'];h=p['host'];name=h['name'];stage=pathlib.Path(p['stage_root']);runtime=pathlib.Path(p['runtime_root']);active=pathlib.Path(p['active_link']);container=p['opt1_postgres_container'];volume=p['opt1_postgres_volume'];mutated=False;diagnostics={}
api_host,api_port=p['opt1_api_bind'].rsplit(':',1);api_port=int(api_port);pg_host,pg_port=p['opt1_postgres_bind'].rsplit(':',1);pg_port=int(pg_port)
def canonical_path(path):
 return os.path.realpath(os.fspath(path))
def governed_active():
 return active.is_symlink() and canonical_path(active)==canonical_path(runtime)
def sha(f):
 q=hashlib.sha256()
 with f.open('rb') as x:
  for b in iter(lambda:x.read(1024*1024),b''):q.update(b)
 return q.hexdigest()
def run(args,check=True,timeout=60,env=None):
 cp=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout,env=env)
 if check and cp.returncode:raise RuntimeError(f'command failed {args}: {cp.stderr.strip()}')
 return cp
def docker_ok():return shutil.which('docker') is not None and run(['docker','info','--format','{{.ServerVersion}}'],False,15).returncode==0
def url_get(path,timeout=10,json_result=False):
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));req=urllib.request.Request(f'http://{api_host}:{api_port}/'+path,headers={'User-Agent':'openwatchlist-r183-smoke','X-Forwarded-Proto':'https'})
 with opener.open(req,timeout=timeout) as r:
  b=r.read();return r.status,(json.loads(b) if json_result else b.decode(errors='replace'))
def url_json(url,timeout=10):
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));req=urllib.request.Request(url,headers={'User-Agent':'openwatchlist-r183-capability'})
 with opener.open(req,timeout=timeout) as r:return r.status,json.loads(r.read().decode())
def tcp(host,port,timeout=3):
 try:
  with socket.create_connection((host,port),timeout=timeout):return True
 except OSError:return False
def port_bound(port):return tcp('127.0.0.1',port,1)
def object_hash(obj,field):
 x=dict(obj);x[field]='';return hashlib.sha256(json.dumps(x,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def verify_stage():
 m=json.load(open(stage/'REMOTE-STAGE-MANIFEST.json',encoding='utf-8'))
 if m.get('schema')!=p['staging_stage_manifest_schema'] or m.get('host')!=name or m.get('release')!=p['target_tag'] or m.get('status')!='PASS':raise RuntimeError('stage manifest identity mismatch')
 for item in m.get('files',[]):
  f=stage/item['path']
  if not f.is_file() or f.stat().st_size!=item['size'] or sha(f)!=item['sha256']:raise RuntimeError(f'stage drift: {item["path"]}')
 return sha(stage/'REMOTE-STAGE-MANIFEST.json')
def protected_containers():
 if not docker_ok():return []
 cp=run(['docker','ps','--no-trunc','--format','{{json .}}']);rows=[]
 for line in cp.stdout.splitlines():
  try:x=json.loads(line)
  except Exception:continue
  if x.get('Names')==container:continue
  rows.append({k:x.get(k) for k in ('ID','Image','Names','Ports')})
 return sorted(rows,key=lambda x:(x.get('Names') or '',x.get('ID') or ''))
def safe_extract(archive,dest,expected):
 if not archive.is_file():raise RuntimeError('activation input archive missing')
 dest.mkdir(parents=True,exist_ok=False)
 with tarfile.open(archive,'r:gz') as tf:
  members=tf.getmembers();names=[]
  for m in members:
   q=pathlib.PurePosixPath(m.name)
   if q.is_absolute() or '..' in q.parts or m.issym() or m.islnk() or m.isdev() or not m.isfile():raise RuntimeError(f'unsafe activation archive member: {m.name}')
   names.append(m.name)
  if sorted(names)!=sorted(x['name'] for x in expected):raise RuntimeError('activation archive file set mismatch')
  tf.extractall(dest,filter='data')
 for spec in expected:
  f=dest/spec['name'];os.chmod(f,0o600)
  if f.stat().st_size!=spec['size'] or sha(f)!=spec['sha256']:raise RuntimeError(f'activation input mismatch: {spec["name"]}')
def owned_labels(kind,obj):
 cp=run(['docker',kind,'inspect',obj,'--format','{{json .Config.Labels}}' if kind=='container' else '{{json .Labels}}'],False)
 if cp.returncode:return None
 return json.loads(cp.stdout)
def stop_api():
 global mutated
 pidf=runtime/'platform-api.pid'
 if not pidf.is_file():return
 try:pid=int(pidf.read_text().strip())
 except Exception:raise RuntimeError('invalid platform-api pid file')
 proc=pathlib.Path(f'/proc/{pid}')
 if proc.exists():
  exe=os.path.realpath(proc/'exe')
  if canonical_path(exe)!=canonical_path(runtime/'bin/platform-api'):raise RuntimeError('refuse to signal non-owned process')
  os.kill(pid,signal.SIGTERM)
  for _ in range(100):
   if not proc.exists():break
   time.sleep(.1)
  else:os.kill(pid,signal.SIGKILL)
 mutated=True
 pidf.unlink(missing_ok=True)
def rollback():
 global mutated
 if name=='opt1':
  # Fail closed before filesystem cleanup when Docker might contain owned resources.
  if not docker_ok():raise RuntimeError('Docker daemon unavailable for Opt1 rollback; no mutation performed')
  stop_api()
  labels=owned_labels('container',container)
  if labels is not None:
   if labels.get(p['owned_label_key'])!=p['owned_label_value'] or labels.get(p['release_label_key'])!=p['target_tag']:raise RuntimeError('refuse to remove unowned container')
   run(['docker','rm','-f',container]);mutated=True
  labels=owned_labels('volume',volume)
  if labels is not None:
   if labels.get(p['owned_label_key'])!=p['owned_label_value'] or labels.get(p['release_label_key'])!=p['target_tag']:raise RuntimeError('refuse to remove unowned volume')
   run(['docker','volume','rm',volume]);mutated=True
 if active.is_symlink():
  if not governed_active():raise RuntimeError('refuse to remove unrelated active link')
  active.unlink();mutated=True
 elif active.exists():raise RuntimeError('active path is not governed symlink')
 if runtime.exists():
  if runtime.is_symlink():raise RuntimeError('runtime root is symlink')
  shutil.rmtree(runtime);mutated=True
 if name=='opt1' and (port_bound(api_port) or port_bound(pg_port)):raise RuntimeError('owned ports remain bound after rollback')
def rewrite_string_tree(value,old,new):
 if isinstance(value,str):return value.replace(old,new)
 if isinstance(value,list):return [rewrite_string_tree(x,old,new) for x in value]
 if isinstance(value,dict):return {k:rewrite_string_tree(v,old,new) for k,v in value.items()}
 return value
def collect_strings(value):
 if isinstance(value,str):return [value]
 if isinstance(value,list):
  out=[]
  for x in value:out.extend(collect_strings(x))
  return out
 if isinstance(value,dict):
  out=[]
  for x in value.values():out.extend(collect_strings(x))
  return out
 return []
def is_within(path,root):
 try:pathlib.Path(canonical_path(path)).relative_to(pathlib.Path(canonical_path(root)));return True
 except ValueError:return False
def config_seal_field(path,obj):
 configured=(p.get('opt1_qualification_config_seals') or {}).get(path.name)
 if configured:
  if configured not in obj:raise RuntimeError(f'governed configuration missing expected seal field {configured}: {path.name}')
  return configured
 candidates=[x for x in ('config_sha256','registry_sha256','contract_sha256') if x in obj]
 if len(candidates)>1:raise RuntimeError(f'ambiguous governed configuration seal fields: {path.name}')
 return candidates[0] if candidates else None
def prepare_opt1_tree(root,archive,postgres_required,psql_path):
 shutil.copytree(stage/'runtime',root);shutil.copytree(stage/'config',root/'config');shutil.copytree(stage/'secrets',root/'secrets')
 for f in (root/'secrets').iterdir():os.chmod(f,0o600)
 config_files=sorted(x for x in (root/'config').rglob('*.json') if 'activation-inputs' not in x.parts)
 inputs=root/'config/activation-inputs';safe_extract(archive,inputs,p['opt1_input_files'])
 for d in ['state/runtime','state/outbox','state/backups','state/alert-case','state/assistance','state/security-audit','logs']:(root/d).mkdir(parents=True,exist_ok=True,mode=0o700)
 old_root=str(runtime);new_root=str(root);rewritten=[];resealed=[];rewritten_unsealed=[];examined=[]
 details={'persistent_runtime_root':old_root,'prepared_root':new_root,'config_files_examined':examined,'rewritten_config_files':rewritten,'resealed_config_files':resealed,'rewritten_unsealed_config_files':rewritten_unsealed,'declared_seal_regeneration_complete':False,'persistent_path_residue':[],'activation_input_paths_verified':{},'review_console_activation_input_paths_verified':False}
 diagnostics['config_rebinding']=details
 for cfgp in config_files:
  rel=cfgp.relative_to(root/'config').as_posix();examined.append(rel)
  try:original=json.load(open(cfgp,encoding='utf-8'))
  except Exception as e:raise RuntimeError(f'governed configuration JSON invalid: {rel}: {e}')
  updated=rewrite_string_tree(original,old_root,new_root);changed=updated!=original
  if rel=='runtime.json':
   if not isinstance(updated.get('readiness'),dict):raise RuntimeError('runtime.json readiness object missing')
   updated['readiness']['postgresql_required']=postgres_required;updated['readiness']['psql_path']=str(psql_path);changed=True
  if changed:
   field=config_seal_field(cfgp,updated)
   if field:updated[field]='';updated[field]=object_hash(updated,field);resealed.append({'path':rel,'seal_field':field,'seal_sha256':updated[field]})
   else:rewritten_unsealed.append(rel)
   cfgp.write_text(json.dumps(updated,indent=2,ensure_ascii=False)+'\n',encoding='utf-8');os.chmod(cfgp,0o600);rewritten.append(rel)
 required=set(p.get('opt1_qualification_required_rebound_configs') or ['runtime.json','review-console.json'])
 missing=sorted(required-set(rewritten)) if old_root!=new_root else []
 if missing:raise RuntimeError('required governed configurations were not rebound: '+','.join(missing))
 residue=[]
 for cfgp in config_files:
  if old_root!=new_root and old_root in cfgp.read_text(encoding='utf-8'):residue.append(cfgp.relative_to(root/'config').as_posix())
 details['persistent_path_residue']=residue;details['declared_seal_regeneration_complete']=True
 if residue:raise RuntimeError('persistent runtime path remains in rebound configuration: '+','.join(residue))
 expected={x['name']:inputs/x['name'] for x in p['opt1_input_files']}
 all_config_strings=[]
 for cfgp in config_files:all_config_strings.extend(collect_strings(json.load(open(cfgp,encoding='utf-8'))))
 for value in all_config_strings:
  if '/config/activation-inputs/' in value:
   q=pathlib.Path(value)
   if not q.is_absolute() or not is_within(q,root):raise RuntimeError(f'activation-input path escapes prepared root: {value}')
   if not q.is_file():raise RuntimeError(f'activation-input path is missing: {value}')
 for input_name,input_path in expected.items():
  exact=str(input_path);details['activation_input_paths_verified'][input_name]={'path':exact,'exists':input_path.is_file(),'within_prepared_root':is_within(input_path,root)}
  if exact not in all_config_strings:raise RuntimeError(f'prepared configuration does not reference activation input: {input_name}')
 review_path=root/'config/review-console.json'
 if not review_path.is_file():raise RuntimeError('review-console.json missing from governed configuration')
 review_strings=collect_strings(json.load(open(review_path,encoding='utf-8')))
 missing_review=[name for name,path in expected.items() if str(path) not in review_strings]
 if missing_review:raise RuntimeError('review-console activation-input paths not rebound: '+','.join(missing_review))
 details['review_console_activation_input_paths_verified']=True
 cfgp=root/'config/runtime.json'
 if not cfgp.is_file():raise RuntimeError('runtime.json missing from governed configuration')
 password=(root/'secrets/postgres-runtime-password').read_text(encoding='utf-8').strip();key=(root/'secrets/openwatchlist-runtime-signing-key.hex').read_text(encoding='utf-8').strip()
 if not password or not key:raise RuntimeError('empty Opt1 secret')
 return cfgp,password,key,details
def qualify_opt1(archive):
 global mutated
 if name!='opt1':raise RuntimeError('pre-mutation qualification is Opt1-only')
 if runtime.exists() or active.exists() or active.is_symlink():raise RuntimeError('runtime or active link already exists before qualification')
 qroot=pathlib.Path('/tmp')/(archive.name+'.opt1-qualification')
 if qroot.exists() or qroot.is_symlink():raise RuntimeError('qualification root already exists')
 diagnostics['pre_mutation_qualification']={'temporary_root':str(qroot),'persistent_runtime_root':str(runtime),'docker_invoked':False};result=None
 try:
  mutated=True
  cfgp,_,key,rebinding=prepare_opt1_tree(qroot,archive,False,pathlib.Path('/bin/false'))
  diagnostics['pre_mutation_qualification']['config_rebinding']=rebinding
  env=os.environ.copy();env['OPENWATCHLIST_SIGNING_KEY_HEX']=key;env['OPENWATCHLIST_QUALIFICATION_ROOT']=str(qroot);env.pop('OPENWATCHLIST_POSTGRES_DSN',None)
  check=run([str(qroot/'bin/platform-api'),'check','--config',str(cfgp)],False,120,env)
  diagnostics['pre_mutation_qualification'].update({'check_returncode':check.returncode,'check_stdout':check.stdout,'check_stderr':check.stderr})
  if check.returncode:raise RuntimeError('published platform-api pre-mutation check failed: '+check.stderr.strip())
  result={'status':'PASS','runtime_active':False,'pre_mutation_qualification':True,'persistent_runtime_mutation_performed':False,'temporary_qualification_mutation_performed':True,'docker_invoked':False,'qualification_check_returncode':check.returncode,'config_rebinding':rebinding}
  return result
 finally:
  if qroot.exists() and not qroot.is_symlink():shutil.rmtree(qroot)
  elif qroot.is_symlink():raise RuntimeError('refuse to remove symlinked qualification root')
  removed=not qroot.exists();diagnostics['pre_mutation_qualification']['temporary_root_removed']=removed
  persistent_absent=not runtime.exists() and not active.exists() and not active.is_symlink()
  if result is not None:result.update({'temporary_root_removed':removed,'persistent_runtime_absent':persistent_absent,'stage_preserved':stage.is_dir()})
  if not persistent_absent:raise RuntimeError('persistent runtime state changed during qualification')
def write_psql_wrapper():
 f=runtime/'bin/psql-openwatchlist-wrapper'
 f.write_text(f'#!/bin/sh\nset -eu\ndsn=${{1:?missing_dsn}}\nshift\ncase "$dsn" in\n  postgresql://openwatchlist:*@{pg_host}:{pg_port}/openwatchlist\\?sslmode=disable) ;;\n  *) echo "refusing unexpected PostgreSQL DSN" >&2; exit 64 ;;\nesac\nexec docker exec -i '+container+' psql -U '+p['opt1_postgres_user']+' -d '+p['opt1_postgres_database']+' "$@"\n',encoding='utf-8');os.chmod(f,0o700);return f
def activate_opt1(archive):
 global mutated
 if not docker_ok():raise RuntimeError('Docker unavailable')
 if port_bound(api_port) or port_bound(pg_port):raise RuntimeError('reserved port already bound')
 if run(['docker','image','inspect',p['opt1_postgres_image']],False).returncode:raise RuntimeError('governed image absent; pull forbidden')
 cfgp,password,key,rebinding=prepare_opt1_tree(runtime,archive,True,pathlib.Path('/bin/false'));diagnostics['persistent_config_rebinding']=rebinding
 wrapper=write_psql_wrapper();cfg=json.load(open(cfgp,encoding='utf-8'));cfg['readiness']['psql_path']=str(wrapper);cfg['config_sha256']='';cfg['config_sha256']=object_hash(cfg,'config_sha256');cfgp.write_text(json.dumps(cfg,indent=2,ensure_ascii=False)+'\n',encoding='utf-8');os.chmod(cfgp,0o600)
 run(['docker','volume','create','--label',f"{p['owned_label_key']}={p['owned_label_value']}",'--label',f"{p['release_label_key']}={p['target_tag']}",volume]);mutated=True
 run(['docker','run','-d','--name',container,'--label',f"{p['owned_label_key']}={p['owned_label_value']}",'--label',f"{p['release_label_key']}={p['target_tag']}",'--restart','no','-p',f'{pg_host}:{pg_port}:5432','-e',f"POSTGRES_USER={p['opt1_postgres_user']}",'-e',f"POSTGRES_DB={p['opt1_postgres_database']}",'-e','POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password','--mount',f'type=volume,src={volume},dst=/var/lib/postgresql/data','--mount',f'type=bind,src={runtime/"secrets/postgres-runtime-password"},dst=/run/secrets/postgres-password,readonly',p['opt1_postgres_image']]);mutated=True
 for _ in range(90):
  if run(['docker','exec',container,'pg_isready','-U',p['opt1_postgres_user'],'-d',p['opt1_postgres_database']],False,10).returncode==0:break
  time.sleep(1)
 else:raise RuntimeError('PostgreSQL readiness timeout')
 dsn='postgresql://openwatchlist:'+urllib.parse.quote(password,safe='')+f'@{pg_host}:{pg_port}/openwatchlist?sslmode=disable';env=os.environ.copy();env['OPENWATCHLIST_SIGNING_KEY_HEX']=key;env['OPENWATCHLIST_POSTGRES_DSN']=dsn
 check=run([str(runtime/'bin/platform-api'),'check','--config',str(cfgp)],False,120,env)
 (runtime/'logs/platform-api-check.stdout').write_text(check.stdout);(runtime/'logs/platform-api-check.stderr').write_text(check.stderr)
 if check.returncode:raise RuntimeError('published platform-api check failed: '+check.stderr.strip())
 log=open(runtime/'logs/platform-api.log','ab',buffering=0);proc=subprocess.Popen([str(runtime/'bin/platform-api'),'serve','--config',str(cfgp)],stdout=log,stderr=log,env=env,start_new_session=True);(runtime/'platform-api.pid').write_text(str(proc.pid)+'\n');mutated=True
 for _ in range(120):
  try:
   status,body=url_get('readyz',5,True)
   if status==200 and body.get('status')=='ok':break
  except Exception:pass
  if proc.poll() is not None:raise RuntimeError(f'platform-api exited: {proc.returncode}')
  time.sleep(1)
 else:raise RuntimeError('platform-api readiness timeout')
 active.parent.mkdir(parents=True,exist_ok=True);active.symlink_to(runtime);mutated=True
def activate_opt2(archive):
 global mutated
 shutil.copytree(stage/'runtime',runtime);inputs=runtime/'catalog/input';safe_extract(archive,inputs,p['opt2_input_files']);package=runtime/'catalog'/p['catalog']['package_name'];package.parent.mkdir(parents=True,exist_ok=True)
 input_path=inputs/p['catalog']['input_name'];input_sha=sha(input_path)
 cp=run([str(runtime/'bin/catalog-mmap'),'compile','--input',str(input_path),'--output',str(package)],False,120)
 (runtime/'catalog/compile.stdout').write_text(cp.stdout);(runtime/'catalog/compile.stderr').write_text(cp.stderr)
 compile_info={}
 try:compile_info=json.loads(cp.stdout)
 except Exception:compile_info={'raw_stdout':cp.stdout}
 diagnostics['catalog_compile']={'input_sha256':input_sha,'expected_input_sha256':p['catalog']['source_input_sha256'],'compile_returncode':cp.returncode,'compile_info':compile_info,'compile_stderr':cp.stderr}
 if cp.returncode:raise RuntimeError('catalog-mmap compile failed: '+cp.stderr.strip())
 actual=sha(package);diagnostics['catalog_compile']['actual_package_sha256']=actual;diagnostics['catalog_compile']['expected_package_sha256']=p['catalog']['expected_package_sha256']
 if input_sha!=p['catalog']['source_input_sha256']:raise RuntimeError(f'catalog input SHA mismatch: expected {p["catalog"]["source_input_sha256"]}, actual {input_sha}')
 if actual!=p['catalog']['expected_package_sha256']:raise RuntimeError(f'catalog package SHA mismatch: expected {p["catalog"]["expected_package_sha256"]}, actual {actual}')
 active.parent.mkdir(parents=True,exist_ok=True);active.symlink_to(runtime);mutated=True
def activate():
 if runtime.exists() or active.exists() or active.is_symlink():raise RuntimeError('runtime or active link already exists')
 verify_stage();archive=pathlib.Path(p['remote_archive'])
 if name=='opt1':activate_opt1(archive)
 elif name=='opt2':activate_opt2(archive)
 else:raise RuntimeError('activation prohibited for capability-only role')
def smoke_opt1():
 rows={}
 for ep in p['api_health_paths']:
  status,body=url_get(ep,20,ep!='metrics');rows[ep]={'status_code':status,'body':body if ep!='metrics' else body[:4096]}
  if status!=200:raise RuntimeError(f'endpoint failed: {ep}')
 if rows['readyz']['body'].get('status')!='ok':raise RuntimeError('readyz status mismatch')
 labels=owned_labels('container',container)
 if labels is None or labels.get(p['owned_label_key'])!=p['owned_label_value']:raise RuntimeError('owned container label mismatch')
 if not port_bound(api_port) or not port_bound(pg_port):raise RuntimeError('owned ports not bound')
 return {'endpoints':rows,'api_bound':True,'postgres_bound':True,'container_owned':True}
def json_cmd(args):
 cp=run(args,False,60)
 if cp.returncode:raise RuntimeError(f'catalog command failed: {args}: {cp.stderr.strip()}')
 return json.loads(cp.stdout)
def smoke_opt2():
 b=runtime/'bin/catalog-mmap';pkg=runtime/'catalog'/p['catalog']['package_name']
 verify=json_cmd([str(b),'verify','--package',str(pkg)]);inspect=json_cmd([str(b),'inspect','--package',str(pkg)])
 for x in (verify,inspect):
  if x.get('package_sha256')!=p['catalog']['expected_package_sha256'] or x.get('record_count')!=p['catalog']['record_count'] or x.get('name_count')!=p['catalog']['name_count'] or x.get('identifier_count')!=p['catalog']['identifier_count']:raise RuntimeError('catalog package metadata mismatch')
 nameq=json_cmd([str(b),'lookup-name','--package',str(pkg),'--query',p['catalog']['lookup_name']]);ident=json_cmd([str(b),'lookup-identifier','--package',str(pkg),'--type',p['catalog']['lookup_identifier_type'],'--value',p['catalog']['lookup_identifier_value']]);record=json_cmd([str(b),'lookup-record','--package',str(pkg),'--record-id',p['catalog']['lookup_record_id']])
 if not any(x.get('record_id')=='ofac:sdn:1001' for x in nameq.get('matches',[])):raise RuntimeError('catalog name lookup mismatch')
 if not any(x.get('record_id')=='ofac:sdn:1001' for x in ident.get('matches',[])):raise RuntimeError('catalog identifier lookup mismatch')
 if not any(x.get('record_id')==p['catalog']['lookup_record_id'] and x.get('primary_name')=='Example Vessel' for x in record.get('matches',[])):raise RuntimeError('catalog record lookup mismatch')
 return {'package_sha256':sha(pkg),'verify':verify,'inspect':inspect,'name_lookup':nameq,'identifier_lookup':ident,'record_lookup':record,'resident_daemon_started':False}
def capability():
 if name=='g732':
  st,tags=url_json(p['g732']['ollama_base_url']+'/api/tags');models=sorted({m.get('name') or m.get('model') for m in tags.get('models',[]) if isinstance(m,dict)});missing=[x for x in p['g732']['required_models'] if x not in models]
  if st!=200 or missing:raise RuntimeError(f'G732 model capability mismatch: {missing}')
  return {'ollama_status':st,'models':models,'required_models_present':True,'new_process_started':False}
 if name=='Thinkpad-P50':
  opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));req=urllib.request.Request(p['p50']['qdrant_health_url'],headers={'User-Agent':'openwatchlist-r183-capability'})
  with opener.open(req,timeout=10) as r:st=r.status;body=r.read(512).decode(errors='replace')
  ports={str(x):tcp('127.0.0.1',int(x)) for x in p['p50']['required_tcp_ports']}
  if st!=200 or not all(ports.values()):raise RuntimeError('P50 data/RAG capability mismatch')
  return {'qdrant_status':st,'qdrant_body':body,'tcp_ports':ports,'new_process_started':False}
 raise RuntimeError('capability action only valid for capability-only roles')
def dispatch():
 global mutated
 stage_sha=(sha(stage/'REMOTE-STAGE-MANIFEST.json') if (stage/'REMOTE-STAGE-MANIFEST.json').is_file() else '') if action in ('rollback','cleanup-archive') else verify_stage()
 if action=='qualify':
  if name!='opt1':raise RuntimeError('pre-mutation qualification is Opt1-only')
  out=qualify_opt1(pathlib.Path(p['remote_archive']))
 elif action=='activate':
  try:activate();out={'status':'PASS','runtime_active':True}
  except Exception:
   try:rollback()
   except Exception as rollback_error:diagnostics['local_activation_rollback_error']=str(rollback_error)
   raise
 elif action=='smoke':
  if not governed_active():raise RuntimeError('governed runtime not active')
  out={'status':'PASS','runtime_active':True,'smoke':smoke_opt1() if name=='opt1' else smoke_opt2(),'protected_containers':protected_containers()}
 elif action=='rollback':
  rollback();out={'status':'PASS','runtime_active':False}
 elif action=='capability':out={'status':'PASS','runtime_active':False,'capability':capability(),'protected_containers':protected_containers()}
 elif action=='inspect':out={'status':'PASS','runtime_active':runtime.exists(),'active_link_exists':active.is_symlink(),'active_target':canonical_path(active) if active.is_symlink() else None,'protected_containers':protected_containers(),'stage_manifest_sha256':stage_sha}
 elif action=='cleanup-archive':
  q=pathlib.Path(p['remote_archive']);
  if q.parent!=pathlib.Path('/tmp') or not q.name.startswith('openwatchlist-r183-'):raise RuntimeError('refuse unsafe archive cleanup')
  if q.exists():q.unlink();mutated=True
  out={'status':'PASS','runtime_active':runtime.exists(),'archive_removed':not q.exists()}
 else:raise RuntimeError('unsupported action')
 return {'schema':'openwatchlist.r2-4-r1-8-3-remote-runtime-result.v1','host':name,'role':h['role'],'action':action,'stage_manifest_sha256':stage_sha,'mutation_performed':mutated,'compiler_toolchain_invocation_performed':False,'catalog_package_materialization_performed':action=='activate' and name=='opt2','systemd_mutation_performed':False,'image_pull_or_build_performed':False,**out}
try:
 print(json.dumps(dispatch(),indent=2,sort_keys=True))
except Exception as error:
 failure={'schema':'openwatchlist.r2-4-r1-8-3-remote-runtime-failure.v1','status':'FAILED_OR_BLOCKED','host':name,'role':h.get('role'),'action':action,'error_type':type(error).__name__,'error':str(error),'mutation_performed':mutated,'runtime_active':governed_active(),'diagnostics':diagnostics}
 print(json.dumps(failure,indent=2,sort_keys=True))
 raise
