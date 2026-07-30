from __future__ import annotations
import base64,hashlib,json,os,pathlib,signal,socket,subprocess,sys,tarfile,tempfile,time,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];SCRIPT=ROOT/'scripts/remote_runtime_control.py';BASE=json.load(open(ROOT/'config/policy.json'))
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def manifest(stage,host):
 files=[]
 for f in sorted(x for x in stage.rglob('*') if x.is_file()):files.append({'path':f.relative_to(stage).as_posix(),'sha256':sha(f),'size':f.stat().st_size,'mode':format(f.stat().st_mode&0o777,'04o')})
 x={'schema':BASE['staging_stage_manifest_schema'],'status':'PASS','host':host,'role':'test','release':BASE['target_tag'],'file_count':len(files),'files':files,'secret_files':[],'secret_count':0,'runtime_started':False,'activation_authorized':False,'compiler_required':False,'protected_postgres_port_referenced':False}
 (stage/'REMOTE-STAGE-MANIFEST.json').write_text(json.dumps(x,indent=2,sort_keys=True)+'\n')
def archive(out,files):
 with tarfile.open(out,'w:gz') as tf:
  for name,data in files.items():
   f=out.parent/name;f.write_bytes(data);tf.add(f,arcname=name);f.unlink()
def invoke(policy,host,action,remote,env=None):
 q={**policy,'host':host,'action':action,'remote_archive':str(remote)};b=base64.b64encode(json.dumps(q,separators=(',',':')).encode()).decode();cp=subprocess.run([sys.executable,str(SCRIPT),b],capture_output=True,text=True,env=env,timeout=150)
 return cp,(json.loads(cp.stdout) if cp.returncode==0 else None)
def seal(x,field):
 x=dict(x);x[field]='';x[field]=hashlib.sha256(json.dumps(x,separators=(',',':'),ensure_ascii=False).encode()).hexdigest();return x
def free_port():
 s=socket.socket();s.bind(('127.0.0.1',0));p=s.getsockname()[1];s.close();return p
def opt1_configs(runtime,api_port):
 rr=str(runtime)
 runtime_cfg=seal({'schema_version':'openwatchlist.production-runtime-config.v1','config_id':'x','version':'x','environment':'production','listen_address':f'127.0.0.1:{api_port}','review_console_config_path':'review-console.json','signing_key_env':'OPENWATCHLIST_SIGNING_KEY_HEX','quota_registry_path':'tenant-quotas.json','runtime_state_directory':rr+'/state/runtime','outbox_directory':rr+'/state/outbox','backup_directory':rr+'/state/backups','readiness':{'required_paths':[rr+'/config/activation-inputs/alert-policy.json',rr+'/config/activation-inputs/corpus-snapshot.json',rr+'/config/activation-inputs/identity-registry.json'],'min_free_bytes':0,'postgresql_required':True,'postgresql_dsn_env':'OPENWATCHLIST_POSTGRES_DSN','psql_path':'psql','verify_outbox':False},'config_sha256':''},'config_sha256')
 review={'schema_version':'openwatchlist.review-console-config.v1','config_id':'review','version':'x','alert_policy_path':rr+'/config/activation-inputs/alert-policy.json','corpus_snapshot_path':rr+'/config/activation-inputs/corpus-snapshot.json','auth_registry_path':rr+'/config/activation-inputs/identity-registry.json','ollama_base_url':'http://127.0.0.1:11434'}
 contract=seal({'schema_version':'openwatchlist.activation-environment-contract.v1','contract_id':'x','runtime_config_path':rr+'/config/runtime.json','review_console_config_path':rr+'/config/review-console.json','activation_input_directory':rr+'/config/activation-inputs','postgresql':{'host':'127.0.0.1','port':15432},'contract_sha256':''},'contract_sha256')
 quota=seal({'schema_version':'openwatchlist.tenant-quota-registry.v1','registry_id':'x','version':'x','default':{},'tenants':[],'registry_sha256':''},'registry_sha256')
 return {'runtime.json':runtime_cfg,'review-console.json':review,'activation-env-contract.json':contract,'tenant-quotas.json':quota}
def write_opt1_stage(stage,runtime,api_port,api_script):
 (stage/'runtime/bin').mkdir(parents=True);(stage/'config').mkdir();(stage/'secrets').mkdir()
 api=stage/'runtime/bin/platform-api';api.write_text(api_script);os.chmod(api,0o755)
 for n in ['platform-ops','container-healthcheck','catalog-mmap']:
  f=stage/'runtime/bin'/n;f.write_text('#!/bin/sh\nexit 0\n');os.chmod(f,0o755)
 for name,data in opt1_configs(runtime,api_port).items():(stage/'config'/name).write_text(json.dumps(data))
 (stage/'secrets/openwatchlist-runtime-signing-key.hex').write_text('00'*32);(stage/'secrets/postgres-runtime-password').write_text('secret')
 for f in (stage/'secrets').iterdir():os.chmod(f,0o600)
def realistic_api_script():
 return '''#!/usr/bin/env python3
import hashlib,http.server,json,os,pathlib,sys
def seal_ok(obj,field):
 expected=obj[field];x=dict(obj);x[field]='';actual=hashlib.sha256(json.dumps(x,separators=(',',':'),ensure_ascii=False).encode()).hexdigest();return actual==expected
def strings(v):
 if isinstance(v,str):return [v]
 if isinstance(v,list):
  out=[]
  for x in v:out.extend(strings(x))
  return out
 if isinstance(v,dict):
  out=[]
  for x in v.values():out.extend(strings(x))
  return out
 return []
if sys.argv[1]=='check':
 cfgp=pathlib.Path(sys.argv[sys.argv.index('--config')+1]);root=cfgp.parent.parent
 files=[('runtime.json','config_sha256'),('activation-env-contract.json','contract_sha256'),('tenant-quotas.json','registry_sha256')]
 loaded={'review-console.json':json.load(open(root/'config/review-console.json'))}
 for name,field in files:
  obj=json.load(open(root/'config'/name));loaded[name]=obj
  if not seal_ok(obj,field):print('seal mismatch: '+name,file=sys.stderr);raise SystemExit(11)
 expected=os.environ.get('OPENWATCHLIST_QUALIFICATION_ROOT')
 if expected:
  old=os.environ.get('EXPECTED_PERSISTENT_RUNTIME_ROOT','')
  for obj in loaded.values():
   if old and any(old in value for value in strings(obj)):print('persistent path residue',file=sys.stderr);raise SystemExit(12)
 review=loaded['review-console.json']
 for key in ('alert_policy_path','corpus_snapshot_path','auth_registry_path'):
  path=pathlib.Path(review[key])
  if expected and not str(path).startswith(expected+'/'):print('review path outside qualification root: '+key,file=sys.stderr);raise SystemExit(13)
  if not path.is_file():print('missing review input: '+str(path),file=sys.stderr);raise SystemExit(14)
 print(json.dumps({'status':'ok','root':str(root)}));raise SystemExit()
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write((json.dumps({'status':'ok'}) if self.path!='/metrics' else 'metric 1').encode())
 def log_message(self,*a):pass
http.server.HTTPServer(('127.0.0.1',int(os.environ['FAKE_API_PORT'])),H).serve_forever()
'''
def docker_script():
 return '''#!/usr/bin/env python3
import json,os,pathlib,signal,subprocess,sys
s=pathlib.Path(os.environ['FAKE_DOCKER_STATE']);x=json.loads(s.read_text());a=sys.argv[1:]
def save():s.write_text(json.dumps(x))
if a[0]=='info':print('fake');raise SystemExit()
if a[:2]==['image','inspect']:raise SystemExit()
if a[:2]==['container','inspect']:
 if x.get('container'):print(json.dumps({'openwatchlist.owner':'r2-4-r1-8-3','openwatchlist.release':'v0.1.0-rc.4'}));raise SystemExit()
 raise SystemExit(1)
if a[:2]==['volume','inspect']:
 if x.get('volume'):print(json.dumps({'openwatchlist.owner':'r2-4-r1-8-3','openwatchlist.release':'v0.1.0-rc.4'}));raise SystemExit()
 raise SystemExit(1)
if a[:2]==['volume','create']:x['volume']=True;save();print(a[-1]);raise SystemExit()
if a[0]=='run':
 code='import os,socket,time;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("127.0.0.1",int(os.environ["FAKE_PG_PORT"])));s.listen();time.sleep(300)';q=subprocess.Popen([sys.executable,'-c',code],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True);x.update(container=True,listener=q.pid);save();print('fakeid');raise SystemExit()
if a[0]=='exec':raise SystemExit()
if a[:2]==['rm','-f']:
 try:os.kill(x.get('listener',0),signal.SIGTERM)
 except Exception:pass
 x.pop('container',None);x.pop('listener',None);save();raise SystemExit()
if a[:2]==['volume','rm']:x.pop('volume',None);save();raise SystemExit()
if a[0]=='ps':raise SystemExit()
raise SystemExit(2)
'''
def opt1_archive(t):
 files={'alert-policy.json':b'{}','corpus-snapshot.json':b'{}','identity-registry.json':b'{}'};arc=t/'opt1.tar.gz';archive(arc,files);spec=[{'name':n,'size':len(v),'sha256':hashlib.sha256(v).hexdigest()} for n,v in files.items()];return arc,spec
class RemoteLifecycleTests(unittest.TestCase):
 def test_opt2_activate_smoke_rollback(self):
  with tempfile.TemporaryDirectory() as td:
   base=pathlib.Path(td);real=base/'real';real.mkdir();t=base/'alias';t.symlink_to(real,target_is_directory=True);stage=t/'stage';(stage/'runtime/bin').mkdir(parents=True);runtime=t/'runtime';active=t/'active';fake=stage/'runtime/bin/catalog-mmap';artifact=b'governed-fake-package'
   fake.write_text('''#!/usr/bin/env python3
import hashlib,json,pathlib,sys
cmd=sys.argv[1];a=sys.argv
if cmd=='compile':
 out=pathlib.Path(a[a.index('--output')+1]);out.write_bytes(b'governed-fake-package');print(json.dumps({'package_sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'record_count':3,'name_count':8,'identifier_count':3}))
elif cmd in ('verify','inspect'):print(json.dumps({'package_sha256':hashlib.sha256(pathlib.Path(a[a.index('--package')+1]).read_bytes()).hexdigest(),'record_count':3,'name_count':8,'identifier_count':3,'verified':cmd=='verify'}))
elif cmd=='lookup-name':print(json.dumps({'matches':[{'record_id':'ofac:sdn:1001'}]}))
elif cmd=='lookup-identifier':print(json.dumps({'matches':[{'record_id':'ofac:sdn:1001'}]}))
elif cmd=='lookup-record':print(json.dumps({'matches':[{'record_id':'ofac:sdn:3003','primary_name':'Example Vessel'}]}))
else:raise SystemExit(2)
''');os.chmod(fake,0o755);manifest(stage,'opt2');arc=t/'opt2.tar.gz';archive(arc,{'fixture.owcin':b'fixture'})
   p={**BASE,'stage_root':str(stage),'runtime_root':str(runtime),'active_link':str(active),'opt2_input_files':[{'name':'fixture.owcin','sha256':hashlib.sha256(b'fixture').hexdigest(),'size':7}]};p['catalog']={**BASE['catalog'],'input_name':'fixture.owcin','source_input_sha256':hashlib.sha256(b'fixture').hexdigest(),'source_input_size':7,'expected_package_sha256':hashlib.sha256(artifact).hexdigest()};h={'name':'opt2','hostname':'x','ssh':'x','role':'catalog-capability','activation_mode':'runtime'}
   cp,x=invoke(p,h,'activate',arc);self.assertEqual(cp.returncode,0,cp.stderr);self.assertTrue(active.is_symlink())
   cp,x=invoke(p,h,'smoke',arc);self.assertEqual(cp.returncode,0,cp.stderr);self.assertEqual(x['smoke']['package_sha256'],p['catalog']['expected_package_sha256'])
   cp,x=invoke(p,h,'rollback',arc);self.assertEqual(cp.returncode,0,cp.stderr);self.assertFalse(runtime.exists());self.assertFalse(active.exists());self.assertTrue(stage.exists())
 def test_opt1_realistic_rebinding_activate_smoke_and_rollback(self):
  with tempfile.TemporaryDirectory() as td:
   base=pathlib.Path(td);real=base/'real';real.mkdir();t=base/'alias';t.symlink_to(real,target_is_directory=True);stage=t/'stage';runtime=t/'runtime';active=t/'active';fakebin=t/'fakebin';fakebin.mkdir();state=t/'docker-state.json';state.write_text('{}');api_port,pg_port=free_port(),free_port()
   write_opt1_stage(stage,runtime,api_port,realistic_api_script());docker=fakebin/'docker';docker.write_text(docker_script());os.chmod(docker,0o755);manifest(stage,'opt1');arc,spec=opt1_archive(t)
   p={**BASE,'stage_root':str(stage),'runtime_root':str(runtime),'active_link':str(active),'opt1_input_files':spec,'opt1_api_bind':f'127.0.0.1:{api_port}','opt1_postgres_bind':f'127.0.0.1:{pg_port}'};h={'name':'opt1','hostname':'x','ssh':'x','role':'control-plane-postgres-and-gateway','activation_mode':'runtime'};env=os.environ.copy();env['PATH']=str(fakebin)+os.pathsep+env['PATH'];env['FAKE_DOCKER_STATE']=str(state);env['FAKE_API_PORT']=str(api_port);env['FAKE_PG_PORT']=str(pg_port);env['EXPECTED_PERSISTENT_RUNTIME_ROOT']=str(runtime)
   cp,x=invoke(p,h,'qualify',arc,env);self.assertEqual(cp.returncode,0,cp.stderr);self.assertTrue(x['pre_mutation_qualification']);self.assertFalse(x['runtime_active']);self.assertTrue(x['temporary_root_removed']);self.assertTrue(x['persistent_runtime_absent']);self.assertTrue(x['stage_preserved']);self.assertFalse(runtime.exists());self.assertFalse(active.exists());self.assertEqual(json.loads(state.read_text()),{})
   rebinding=x['config_rebinding'];self.assertEqual(rebinding['persistent_path_residue'],[]);self.assertTrue(rebinding['review_console_activation_input_paths_verified']);self.assertEqual(set(rebinding['rewritten_config_files']),{'runtime.json','review-console.json','activation-env-contract.json'});self.assertEqual({r['path'] for r in rebinding['resealed_config_files']},{'runtime.json','activation-env-contract.json'});self.assertEqual(rebinding['rewritten_unsealed_config_files'],['review-console.json']);self.assertTrue(rebinding['declared_seal_regeneration_complete']);self.assertTrue(all(v['exists'] and v['within_prepared_root'] for v in rebinding['activation_input_paths_verified'].values()))
   cp,x=invoke(p,h,'activate',arc,env);self.assertEqual(cp.returncode,0,cp.stderr)
   cp,x=invoke(p,h,'smoke',arc,env);self.assertEqual(cp.returncode,0,cp.stderr);self.assertTrue(x['smoke']['api_bound'])
   pid=int((runtime/'platform-api.pid').read_text());os.kill(pid,signal.SIGTERM)
   for _ in range(50):
    if not pathlib.Path(f'/proc/{pid}').exists():break
    time.sleep(.1)
   cp,x=invoke(p,h,'rollback',arc,env);self.assertEqual(cp.returncode,0,cp.stderr);self.assertFalse(runtime.exists());self.assertFalse(active.exists());self.assertTrue(stage.exists())
 def test_opt1_prequalification_published_check_failure_is_structured(self):
  with tempfile.TemporaryDirectory() as td:
   t=pathlib.Path(td);stage=t/'stage';runtime=t/'runtime';active=t/'active';write_opt1_stage(stage,runtime,18080,'#!/bin/sh\necho governed-check-failure >&2\nexit 9\n');manifest(stage,'opt1');arc,spec=opt1_archive(t)
   p={**BASE,'stage_root':str(stage),'runtime_root':str(runtime),'active_link':str(active),'opt1_input_files':spec};h={'name':'opt1','hostname':'x','ssh':'x','role':'control-plane-postgres-and-gateway','activation_mode':'runtime'}
   cp,_=invoke(p,h,'qualify',arc);self.assertNotEqual(cp.returncode,0);failure=json.loads(cp.stdout);self.assertIn('published platform-api pre-mutation check failed',failure['error']);self.assertEqual(failure['diagnostics']['pre_mutation_qualification']['check_returncode'],9);self.assertTrue(failure['diagnostics']['pre_mutation_qualification']['temporary_root_removed']);self.assertFalse(runtime.exists());self.assertFalse(active.exists());self.assertTrue(stage.exists())
 def test_opt1_prequalification_rejects_missing_required_runtime_seal(self):
  with tempfile.TemporaryDirectory() as td:
   t=pathlib.Path(td);stage=t/'stage';runtime=t/'runtime';active=t/'active';write_opt1_stage(stage,runtime,18080,realistic_api_script());cfg=json.loads((stage/'config/runtime.json').read_text());cfg.pop('config_sha256');(stage/'config/runtime.json').write_text(json.dumps(cfg));manifest(stage,'opt1');arc,spec=opt1_archive(t)
   p={**BASE,'stage_root':str(stage),'runtime_root':str(runtime),'active_link':str(active),'opt1_input_files':spec};h={'name':'opt1','hostname':'x','ssh':'x','role':'control-plane-postgres-and-gateway','activation_mode':'runtime'}
   cp,_=invoke(p,h,'qualify',arc);self.assertNotEqual(cp.returncode,0);failure=json.loads(cp.stdout);self.assertIn('governed configuration missing expected seal field config_sha256: runtime.json',failure['error']);self.assertTrue(failure['diagnostics']['pre_mutation_qualification']['temporary_root_removed']);self.assertFalse(runtime.exists());self.assertFalse(active.exists())
 def test_opt2_package_mismatch_is_structured_and_rolls_back(self):
  with tempfile.TemporaryDirectory() as td:
   t=pathlib.Path(td);stage=t/'stage';(stage/'runtime/bin').mkdir(parents=True);runtime=t/'runtime';active=t/'active';fake=stage/'runtime/bin/catalog-mmap';artifact=b'unexpected-package'
   fake.write_text('''#!/usr/bin/env python3
import hashlib,json,pathlib,sys
a=sys.argv;out=pathlib.Path(a[a.index('--output')+1]);out.write_bytes(b'unexpected-package');print(json.dumps({'package_sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'record_count':3,'name_count':8,'identifier_count':3}))
''');os.chmod(fake,0o755);manifest(stage,'opt2');arc=t/'opt2.tar.gz';archive(arc,{'fixture.owcin':b'fixture'})
   p={**BASE,'stage_root':str(stage),'runtime_root':str(runtime),'active_link':str(active),'opt2_input_files':[{'name':'fixture.owcin','sha256':hashlib.sha256(b'fixture').hexdigest(),'size':7}]};p['catalog']={**BASE['catalog'],'input_name':'fixture.owcin','source_input_sha256':hashlib.sha256(b'fixture').hexdigest(),'source_input_size':7,'expected_package_sha256':hashlib.sha256(b'expected-package').hexdigest()};h={'name':'opt2','hostname':'x','ssh':'x','role':'catalog-capability','activation_mode':'runtime'}
   cp,_=invoke(p,h,'activate',arc);self.assertNotEqual(cp.returncode,0);failure=json.loads(cp.stdout);diag=failure['diagnostics']['catalog_compile'];self.assertEqual(failure['status'],'FAILED_OR_BLOCKED');self.assertEqual(diag['actual_package_sha256'],hashlib.sha256(artifact).hexdigest());self.assertEqual(diag['expected_package_sha256'],p['catalog']['expected_package_sha256']);self.assertFalse(runtime.exists());self.assertFalse(active.exists());self.assertTrue(stage.exists())
class RemoteSafetyTests(unittest.TestCase):
 def _minimal(self,t,host):
  stage=t/'stage';(stage/'runtime/bin').mkdir(parents=True);f=stage/'runtime/bin/catalog-mmap';f.write_text('#!/bin/sh\nexit 0\n');os.chmod(f,0o755);manifest(stage,host);p={**BASE,'stage_root':str(stage),'runtime_root':str(t/'runtime'),'active_link':str(t/'active')};return stage,p
 def test_capability_only_activation_is_rejected(self):
  with tempfile.TemporaryDirectory() as td:
   t=pathlib.Path(td);stage,p=self._minimal(t,'g732');h={'name':'g732','hostname':'x','ssh':'x','role':'gpu-model-capability','activation_mode':'capability-only'};cp,_=invoke(p,h,'activate',t/'unused.tar.gz');self.assertNotEqual(cp.returncode,0);self.assertIn('activation prohibited for capability-only role',cp.stderr);self.assertFalse((t/'runtime').exists())
 def test_opt1_rollback_without_docker_is_fail_closed(self):
  with tempfile.TemporaryDirectory() as td:
   t=pathlib.Path(td);stage,p=self._minimal(t,'opt1');runtime=t/'runtime';runtime.mkdir();active=t/'active';active.symlink_to(runtime);h={'name':'opt1','hostname':'x','ssh':'x','role':'control-plane-postgres-and-gateway','activation_mode':'runtime'};env=os.environ.copy();empty=t/'empty';empty.mkdir();env['PATH']=str(empty);cp,_=invoke(p,h,'rollback',t/'unused.tar.gz',env);self.assertNotEqual(cp.returncode,0);self.assertTrue(runtime.exists());self.assertTrue(active.is_symlink())
 def test_missing_opt2_archive_cleanup_is_idempotent(self):
  with tempfile.TemporaryDirectory() as td:
   t=pathlib.Path(td);stage,p=self._minimal(t,'opt2');h={'name':'opt2','hostname':'x','ssh':'x','role':'catalog-capability','activation_mode':'runtime'};missing=pathlib.Path('/tmp')/('openwatchlist-r183-test-'+next(tempfile._get_candidate_names())+'-opt2.tar.gz');p['remote_archive']=str(missing);cp,x=invoke(p,h,'cleanup-archive',missing);self.assertEqual(cp.returncode,0,cp.stderr);self.assertTrue(x['archive_removed']);self.assertFalse(x['mutation_performed'])
 def test_unsafe_opt2_archive_is_rejected_and_runtime_removed(self):
  with tempfile.TemporaryDirectory() as td:
   t=pathlib.Path(td);stage,p=self._minimal(t,'opt2');p['opt2_input_files']=[{'name':'fixture.owcin','size':1,'sha256':hashlib.sha256(b'x').hexdigest()}];h={'name':'opt2','hostname':'x','ssh':'x','role':'catalog-capability','activation_mode':'runtime'};arc=t/'unsafe.tar.gz'
   with tarfile.open(arc,'w:gz') as tf:q=t/'x';q.write_bytes(b'x');tf.add(q,arcname='../fixture.owcin')
   cp,_=invoke(p,h,'activate',arc);self.assertNotEqual(cp.returncode,0);self.assertIn('unsafe activation archive member',cp.stderr);self.assertFalse((t/'runtime').exists());self.assertTrue(stage.exists())
