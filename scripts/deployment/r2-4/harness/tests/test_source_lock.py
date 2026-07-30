from __future__ import annotations
import base64,hashlib,json,os,pathlib,subprocess,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class SourceLockTests(unittest.TestCase):
 def _run(self,corrupt=False):
  td=tempfile.TemporaryDirectory();t=pathlib.Path(td.name);work=ROOT
  source=t/'source';source.mkdir();responses=t/'responses';responses.mkdir()
  sources=json.loads((work/'inputs/SOURCES.json').read_text())
  for spec in sources['sources']:
   dst=source/spec['source_path'];dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes((work/spec['local_path']).read_bytes())
  if corrupt:
   target=source/sources['sources'][1]['source_path'];target.write_bytes(target.read_bytes()+b'\n')
  cases=[]
  for index,spec in enumerate(sources['sources']):
   raw=(source/spec['source_path']).read_bytes();response=responses/f'{index}.json'
   response.write_text(json.dumps({'type':'file','encoding':'base64','content':base64.b64encode(raw).decode(),'sha':'fake-'+spec['source_path'].replace('/','-')}))
   cases.append(f'  *"/contents/{spec["source_path"]}?ref="*) cat "$FAKE_RESPONSE_DIR/{index}.json" ;;')
  fake=t/'bin';fake.mkdir();gh=fake/'gh'
  gh.write_text('#!/bin/sh\nendpoint=""\nfor arg in "$@"; do endpoint="$arg"; done\ncase "$endpoint" in\n'+'\n'.join(cases)+'\n  *) echo "unexpected endpoint: $endpoint" >&2; exit 4 ;;\nesac\n')
  os.chmod(gh,0o755)
  out=t/'out.json';env=os.environ.copy();env['PATH']=str(fake)+os.pathsep+env['PATH'];env['FAKE_RESPONSE_DIR']=str(responses)
  cp=subprocess.run(['python3',str(work/'scripts/verify_source_lock.py'),'--policy',str(work/'config/policy.json'),'--root',str(work),'--output',str(out)],capture_output=True,text=True,env=env)
  return td,cp,json.loads(out.read_text())
 def test_exact_commit_pinned_sources_pass_with_offline_gh_fixture(self):
  td,cp,x=self._run();self.addCleanup(td.cleanup);self.assertEqual(cp.returncode,0,cp.stderr);self.assertEqual(x['status'],'PASS');self.assertEqual(x['source_count'],5);self.assertTrue(all(row['byte_equal'] for row in x['sources']))
 def test_remote_byte_mismatch_blocks(self):
  td,cp,x=self._run(True);self.addCleanup(td.cleanup);self.assertNotEqual(cp.returncode,0);self.assertEqual(x['status'],'BLOCKED');self.assertIn('commit-pinned source-lock mismatch: corpus-snapshot.json',x['problems'])
