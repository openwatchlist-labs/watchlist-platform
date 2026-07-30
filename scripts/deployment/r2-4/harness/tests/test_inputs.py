from __future__ import annotations
import hashlib,json,pathlib,shutil,subprocess,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];P=json.load(open(ROOT/'config/policy.json'))
def run_validator(root,out):return subprocess.run(['python3',str(root/'scripts/validate_inputs.py'),'--policy',str(root/'config/policy.json'),'--root',str(root),'--output',str(out)],capture_output=True,text=True)
class InputTests(unittest.TestCase):
 def test_exact_hashes(self):
  for sub,key in [('opt1-inputs','opt1_input_files'),('opt2-inputs','opt2_input_files')]:
   for x in P[key]:
    f=ROOT/sub/x['name'];self.assertEqual(f.stat().st_size,x['size']);self.assertEqual(hashlib.sha256(f.read_bytes()).hexdigest(),x['sha256'])
 def test_exact_governed_corpus_snapshot_and_passages(self):
  f=ROOT/'opt1-inputs/corpus-snapshot.json';x=json.loads(f.read_text());self.assertEqual(f.stat().st_size,3454);self.assertEqual(hashlib.sha256(f.read_bytes()).hexdigest(),'c02b876863c7b40649c8ca94e54248783aaa85a8c480a8ea0de9d3e60f287fd1');self.assertEqual(x['passage_count'],6);self.assertEqual(len(x['passages']),6)
  for passage in x['passages']:self.assertEqual(hashlib.sha256(passage['text'].encode()).hexdigest(),passage['text_sha256'])
  self.assertEqual(x['manifest_sha256'],P['corpus']['manifest_sha256']);self.assertEqual(x['snapshot_sha256'],P['corpus']['snapshot_sha256'])
 def test_exact_source_catalog_fixture(self):
  f=ROOT/'opt2-inputs/ofac-fixture.owcin';raw=f.read_text(encoding='utf-8');aliases=[bytes.fromhex(x.split('\t')[3]).decode() for x in raw.splitlines() if x.startswith('N\t') and x.split('\t')[2]=='alias']
  self.assertEqual(f.stat().st_size,1983);self.assertEqual(hashlib.sha256(f.read_bytes()).hexdigest(),'17559b75fef7e34c1c37dca7192113fb5632b5248255cbb20a9e0ea35803bb21');self.assertIn('Джордан Экзампл',aliases);self.assertNotIn('Джордан Экзапл',aliases)
 def test_input_validator(self):
  with tempfile.TemporaryDirectory() as td:
   out=pathlib.Path(td)/'out.json';cp=run_validator(ROOT,out);self.assertEqual(cp.returncode,0,cp.stderr);x=json.loads(out.read_text());self.assertEqual(x['status'],'PASS');self.assertEqual(x['corpus_validation']['status'],'PASS');self.assertTrue(x['corpus_validation']['compiled_snapshot_exact_match'])
 def test_corrupted_passage_text_is_rejected_independently(self):
  with tempfile.TemporaryDirectory() as td:
   work=pathlib.Path(td)/'work';shutil.copytree(ROOT,work,ignore=shutil.ignore_patterns('validation','SHA256SUMS'))
   f=work/'opt1-inputs/corpus-snapshot.json';x=json.loads(f.read_text());x['passages'][0]['text']+=' corrupted';f.write_text(json.dumps(x,indent=2,ensure_ascii=False)+'\n')
   # Update duplicate package metadata to prove passage-level validation is independent.
   raw=f.read_bytes();digest=hashlib.sha256(raw).hexdigest();policy=json.loads((work/'config/policy.json').read_text());spec=next(v for v in policy['opt1_input_files'] if v['name']=='corpus-snapshot.json');spec.update(size=len(raw),sha256=digest);policy['corpus'].update(source_snapshot_size=len(raw),source_snapshot_sha256=digest);(work/'config/policy.json').write_text(json.dumps(policy,indent=2,sort_keys=True)+'\n')
   sources=json.loads((work/'inputs/SOURCES.json').read_text());src=next(v for v in sources['sources'] if v['name']=='corpus-snapshot.json');src.update(size=len(raw),sha256=digest);(work/'inputs/SOURCES.json').write_text(json.dumps(sources,indent=2,sort_keys=True)+'\n')
   out=work/'out.json';cp=run_validator(work,out);self.assertNotEqual(cp.returncode,0);problems=json.loads(out.read_text())['corpus_validation']['problems'];self.assertTrue(any('passage checksum mismatch' in v for v in problems))
 def test_corrupted_snapshot_checksum_is_rejected(self):
  with tempfile.TemporaryDirectory() as td:
   work=pathlib.Path(td)/'work';shutil.copytree(ROOT,work,ignore=shutil.ignore_patterns('validation','SHA256SUMS'))
   f=work/'opt1-inputs/corpus-snapshot.json';x=json.loads(f.read_text());x['snapshot_sha256']='0'*64;f.write_text(json.dumps(x,indent=2,ensure_ascii=False)+'\n')
   raw=f.read_bytes();digest=hashlib.sha256(raw).hexdigest();policy=json.loads((work/'config/policy.json').read_text());spec=next(v for v in policy['opt1_input_files'] if v['name']=='corpus-snapshot.json');spec.update(size=len(raw),sha256=digest);policy['corpus'].update(source_snapshot_size=len(raw),source_snapshot_sha256=digest);(work/'config/policy.json').write_text(json.dumps(policy,indent=2,sort_keys=True)+'\n')
   sources=json.loads((work/'inputs/SOURCES.json').read_text());src=next(v for v in sources['sources'] if v['name']=='corpus-snapshot.json');src.update(size=len(raw),sha256=digest);(work/'inputs/SOURCES.json').write_text(json.dumps(sources,indent=2,sort_keys=True)+'\n')
   out=work/'out.json';cp=run_validator(work,out);self.assertNotEqual(cp.returncode,0);self.assertIn('corpus snapshot checksum mismatch',json.loads(out.read_text())['corpus_validation']['problems'])
 def test_deterministic_archives(self):
  with tempfile.TemporaryDirectory() as a,tempfile.TemporaryDirectory() as b:
   for out in (a,b):subprocess.check_call(['python3',str(ROOT/'scripts/build_input_archives.py'),'--policy',str(ROOT/'config/policy.json'),'--root',str(ROOT),'--output',str(pathlib.Path(out)/'archives')],stdout=subprocess.DEVNULL)
   for name in ('opt1-activation-inputs.tar.gz','opt2-activation-inputs.tar.gz'):self.assertEqual((pathlib.Path(a)/'archives'/name).read_bytes(),(pathlib.Path(b)/'archives'/name).read_bytes())
