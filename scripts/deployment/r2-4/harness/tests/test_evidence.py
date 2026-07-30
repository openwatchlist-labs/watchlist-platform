from __future__ import annotations
import json,pathlib,subprocess,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class EvidenceTests(unittest.TestCase):
 def test_readiness_argument_failure_is_durable(self):
  with tempfile.TemporaryDirectory() as td:
   out=pathlib.Path(td)/'evidence';cp=subprocess.run([str(ROOT/'scripts/run-activation-readiness.sh'),'--output',str(out)],capture_output=True,text=True);self.assertNotEqual(cp.returncode,0);self.assertTrue((out/'startup.json').is_file());self.assertTrue((out/'phase.json').is_file());self.assertTrue((out/'failure.json').is_file());self.assertTrue((out/'SHA256SUMS').is_file());self.assertEqual(json.loads((out/'failure.json').read_text())['phase'],'argument-validation')
 def test_activation_wrong_approval_is_durable_without_network(self):
  with tempfile.TemporaryDirectory() as td:
   out=pathlib.Path(td)/'evidence';cp=subprocess.run([str(ROOT/'scripts/activate-smoke-rollback-reactivate.sh'),'--output',str(out),'--approval','WRONG'],capture_output=True,text=True);self.assertNotEqual(cp.returncode,0);f=json.loads((out/'failure.json').read_text());self.assertEqual(f['phase'],'argument-validation');self.assertFalse(f['remote_mutation_performed'])

class AutomaticRollbackEvidenceTests(unittest.TestCase):
 def test_summary_records_per_host_outcomes_and_original_phase(self):
  with tempfile.TemporaryDirectory() as td:
   root=pathlib.Path(td)
   for host in ('opt1','opt2'):
    (root/f'{host}-rollback.exit.txt').write_text('0\n')
    (root/f'{host}-cleanup.exit.txt').write_text('0\n')
    (root/f'{host}-rollback.json').write_text(json.dumps({'status':'PASS','host':host,'action':'rollback'}))
    (root/f'{host}-cleanup.json').write_text(json.dumps({'status':'PASS','host':host,'action':'cleanup-archive'}))
   cp=subprocess.run(['python3',str(ROOT/'scripts/write_automatic_rollback_summary.py'),'--root',str(root),'--original-failure-phase','first-controlled-activation','--rollback-succeeded','true','--cleanup-succeeded','true'],capture_output=True,text=True)
   self.assertEqual(cp.returncode,0,cp.stderr);x=json.loads((root/'summary.json').read_text());self.assertEqual(x['status'],'PASS');self.assertEqual(x['original_failure_phase'],'first-controlled-activation');self.assertTrue(x['rollback_succeeded']);self.assertTrue(x['archive_cleanup_succeeded']);self.assertEqual([r['rollback_returncode'] for r in x['results']],[0,0])
 def test_summary_exposes_failed_host(self):
  with tempfile.TemporaryDirectory() as td:
   root=pathlib.Path(td)
   for host,rc in (('opt1',0),('opt2',1)):
    (root/f'{host}-rollback.exit.txt').write_text(str(rc)+'\n');(root/f'{host}-cleanup.exit.txt').write_text('0\n')
   cp=subprocess.run(['python3',str(ROOT/'scripts/write_automatic_rollback_summary.py'),'--root',str(root),'--original-failure-phase','first-smoke-qualification','--rollback-succeeded','false','--cleanup-succeeded','true'],capture_output=True,text=True)
   self.assertEqual(cp.returncode,0,cp.stderr);x=json.loads((root/'summary.json').read_text());self.assertEqual(x['status'],'FAILED_OR_BLOCKED');self.assertFalse(x['rollback_succeeded']);self.assertEqual(x['results'][1]['rollback_returncode'],1)
