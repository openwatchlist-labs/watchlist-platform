from __future__ import annotations
import json,pathlib,re,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];P=json.load(open(ROOT/'config/policy.json'))
class PolicyTests(unittest.TestCase):
 def test_public_template_is_non_operational_and_sanitized(self):
  self.assertIs(P.get('public_template'),True)
  for host in P['hosts']:
   self.assertIn('.example.invalid',host['hostname'])
   self.assertIn('.example.invalid',host['ssh'])
  self.assertTrue(P['runtime_root'].startswith('/srv/openwatchlist/'))
  self.assertTrue(P['stage_root'].startswith('/srv/openwatchlist/'))
  self.assertNotIn('192'+'.168.',json.dumps(P))
  self.assertNotIn('/home/',json.dumps(P))
 def test_release_boundary(self):
  self.assertEqual(P['release_id'],361927608);self.assertEqual(P['target_tag'],'v0.1.0-rc.4');self.assertEqual(P['main_commit'],'210dc3c00d43f4f4e9ceae6905c24c9c9ea99584');self.assertEqual(P['linux_amd64_runtime_sha256'],'1cf61dce31fad81d8511bac76c5a29aef3c0375a3a26d0c92f58a70a3494a29f')
 def test_exact_hosts_and_modes(self):
  self.assertEqual([(h['name'],h['activation_mode']) for h in P['hosts']],[('opt1','runtime'),('g732','capability-only'),('opt2','runtime'),('Thinkpad-P50','capability-only')])
 def test_exact_approvals(self):
  self.assertEqual(P['activation_approval'],'ACTIVATE_OPENWATCHLIST_R2_4_CONTROLLED_ROLLBACK_QUALIFIED_RUNTIME');self.assertEqual(P['rollback_approval'],'ROLLBACK_OPENWATCHLIST_R2_4_CONTROLLED_RUNTIME')
 def test_postgres_isolation(self):
  self.assertEqual(P['opt1_postgres_bind'],'127.0.0.1:15432');self.assertEqual(P['protected_postgres_port'],5432);self.assertNotEqual(P['opt1_postgres_bind'].split(':')[-1],str(P['protected_postgres_port']))
 def test_owned_resources(self):
  self.assertEqual(P['owned_label_value'],'r2-4-r1-8-3');self.assertTrue(P['opt1_postgres_container'].startswith('openwatchlist-r2-4-rc4-'));self.assertTrue(P['opt1_postgres_volume'].startswith('openwatchlist-r2-4-rc4-'))
 def test_catalog_contract(self):
  c=P['catalog'];self.assertEqual(c['expected_package_sha256'],'8c5e581ad36807c15a2ae00c5cb4e8b7f9154e208b369ff3227617294a473367');self.assertEqual(c['source_input_sha256'],'17559b75fef7e34c1c37dca7192113fb5632b5248255cbb20a9e0ea35803bb21');self.assertEqual(c['source_input_size'],1983);self.assertEqual((c['record_count'],c['name_count'],c['identifier_count']),(3,8,3))
 def test_exact_corpus_contract(self):
  c=P['corpus'];self.assertEqual(c['source_snapshot_size'],3454);self.assertEqual(c['source_snapshot_sha256'],'c02b876863c7b40649c8ca94e54248783aaa85a8c480a8ea0de9d3e60f287fd1');self.assertEqual(c['source_manifest_size'],2287);self.assertEqual(c['source_manifest_sha256'],'ace8cf8199b39d1d4adeb13f16958706ea748a7885ed7cadff8f774c65b08dd0');self.assertEqual(c['manifest_sha256'],'cbf1762e549e285aa0bcaf9c437c32957e4117328c26f52bd0d6a00552535989');self.assertEqual(c['snapshot_sha256'],'3e50b008055e55086da897a2ba4497634638b15afede270d5e95348f3c092def');self.assertEqual(c['passage_count'],6)
 def test_source_lock_rebinding_and_qualification_first_transfer_order(self):
  ready=(ROOT/'scripts/run-activation-readiness.sh').read_text();self.assertIn('independent-commit-pinned-source-lock-verification',ready);self.assertIn('verify_source_lock.py',ready)
  act=(ROOT/'scripts/activate-smoke-rollback-reactivate.sh').read_text();opt1=act.index('opt1-activation-input-transfer-before-qualification');q=act.index('opt1-pre-mutation-configuration-qualification');opt2=act.index('opt2-activation-input-transfer-after-opt1-qualification');a=act.index('first-controlled-activation');self.assertLess(opt1,q);self.assertLess(q,opt2);self.assertLess(opt2,a);self.assertIn('transfer_archive opt1',act[opt1:q]);self.assertIn('invoke qualify opt1',act[q:opt2]);self.assertIn('transfer_archive opt2',act[opt2:a]);self.assertIn('--pre-mutation-qualification',act)
  remote=(ROOT/'scripts/remote_runtime_control.py').read_text();self.assertIn('persistent runtime path remains in rebound configuration',remote);self.assertIn('review-console activation-input paths not rebound',remote);self.assertIn('governed configuration missing expected seal field',remote)
  self.assertEqual(P['opt1_qualification_required_rebound_configs'],['runtime.json','review-console.json']);self.assertNotIn('review-console.json',P['opt1_qualification_config_seals']);self.assertEqual(P['opt1_qualification_required_resealed_configs'],['runtime.json'])
 def test_no_toolchain_or_install_surface(self):
  text='\n'.join(f.read_text(errors='ignore') for f in (ROOT/'scripts').glob('*') if f.is_file())
  for pattern in [r'\bcargo\s+(build|install)',r'\brustc\b',r'\bgo\s+build\b',r'\bapt(-get)?\s+install\b',r'\bdocker\s+pull\b',r'\bdocker\s+build\b',r'\bsystemctl\s+(enable|start|restart|daemon-reload)\b']:
   self.assertIsNone(re.search(pattern,text),pattern)
 def test_capability_hosts_not_activated(self):
  text=(ROOT/'scripts/remote_runtime_control.py').read_text();self.assertIn("raise RuntimeError('activation prohibited for capability-only role')",text)
 def test_manual_rollback_is_bounded(self):
  text=(ROOT/'scripts/rollback-r2-4-controlled-runtime.sh').read_text();self.assertIn('for name in opt1 opt2',text);self.assertNotIn('for name in opt1 g732 opt2 Thinkpad-P50',text)
 def test_automatic_rollback_evidence_contract(self):
  text=(ROOT/'scripts/activate-smoke-rollback-reactivate.sh').read_text();body=text[text.index('auto_rollback(){'):text.index('activation_worker(){')]
  self.assertNotIn('||true',body);self.assertNotIn('|| true',body);self.assertIn('write_automatic_rollback_summary.py',body);self.assertIn('automatic_rollback_succeeded',body);self.assertIn('r183_set_phase "$failed_phase"',body)
 def test_no_nonstdlib_imports(self):
  allowed={'__future__','argparse','base64','datetime','gzip','hashlib','json','os','pathlib','shutil','signal','socket','subprocess','sys','tarfile','tempfile','time','urllib','http','unittest','re'}
  for f in list((ROOT/'scripts').glob('*.py'))+list((ROOT/'tests').glob('*.py')):
   for line in f.read_text().splitlines():
    m=re.match(r'^(?:from|import)\s+([A-Za-z0-9_]+)',line)
    if m:self.assertIn(m.group(1),allowed,(f,m.group(1)))
 def test_no_compiled_python_artifacts(self):
  self.assertFalse(list(ROOT.rglob('__pycache__')));self.assertFalse(list(ROOT.rglob('*.pyc')))
