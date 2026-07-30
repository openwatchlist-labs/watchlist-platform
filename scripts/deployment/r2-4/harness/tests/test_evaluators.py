from __future__ import annotations
import json,pathlib,subprocess,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];P=json.load(open(ROOT/'config/policy.json'))
def write(d,name,x):p=pathlib.Path(d)/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(x));return p
class EvaluatorTests(unittest.TestCase):
 def test_activation_readiness_passes_role_bounded_fixture(self):
  with tempfile.TemporaryDirectory() as td:
   t=pathlib.Path(td);pre=t/'pre';pre.mkdir()
   st={'schema':P['staging_summary_schema'],'status':P['staging_status'],'target_tag':P['target_tag'],'runtime_started':False,'activation_performed':False,'problems':[]}
   iv={'status':'PASS','problems':[],'corpus_validation':{'status':'PASS'}};sl={'status':'PASS','problems':[],'commit':P['main_commit'],'repository':P['repository'],'remote_mutation_performed':False,'source_count':5};ar={'status':'PASS','archive_count':2}
   for h in P['hosts']:
    cap={}
    if h['name']=='opt1':cap={'ollama_reachable_from_opt1':True}
    if h['name']=='g732':cap={'required_models_present':True}
    if h['name']=='Thinkpad-P50':cap={'qdrant_status':200}
    write(pre,h['name']+'.json',{'status':'PASS','host':h['name'],'problems':[],'remote_mutation_performed':False,'runtime_root_exists':False,'active_link_exists':False,'capability':cap})
   out=t/'out.json';args=['python3',str(ROOT/'scripts/evaluate_activation_readiness.py'),'--policy',str(ROOT/'config/policy.json'),'--staging-summary',str(write(t,'staging.json',st)),'--input-validation',str(write(t,'iv.json',iv)),'--source-lock',str(write(t,'sl.json',sl)),'--archives',str(write(t,'ar.json',ar)),'--preflights',str(pre),'--output',str(out)];cp=subprocess.run(args,capture_output=True,text=True);self.assertEqual(cp.returncode,0,cp.stderr);x=json.loads(out.read_text());self.assertEqual(x['status'],P['activation_readiness_status']);self.assertTrue(x['pre_mutation_opt1_qualification_required']);self.assertTrue(x['complete_temporary_root_rebinding_required']);self.assertTrue(x['qualification_first_opt2_transfer_required'])
 def test_deployment_evaluator_rejects_stage_drift(self):
  with tempfile.TemporaryDirectory() as td:
   t=pathlib.Path(td)
   for d in ['first','rolled','final','cap1','cap2','pre']:(t/d).mkdir()
   qual=write(t,'qualification.json',{'host':'opt1','action':'qualify','status':'PASS','pre_mutation_qualification':True,'runtime_active':False,'persistent_runtime_mutation_performed':False,'temporary_qualification_mutation_performed':True,'docker_invoked':False,'temporary_root_removed':True,'persistent_runtime_absent':True,'stage_preserved':True,'config_rebinding':{'persistent_path_residue':[],'review_console_activation_input_paths_verified':True,'rewritten_config_files':['runtime.json','review-console.json'],'resealed_config_files':[{'path':'runtime.json'}],'rewritten_unsealed_config_files':['review-console.json'],'declared_seal_regeneration_complete':True,'activation_input_paths_verified':{x['name']:{'exists':True,'within_prepared_root':True} for x in P['opt1_input_files']}}})
   for h in ('opt1','opt2'):
    smoke={'api_bound':True,'postgres_bound':True,'endpoints':{x:{} for x in P['api_health_paths']}} if h=='opt1' else {'package_sha256':P['catalog']['expected_package_sha256'],'resident_daemon_started':False}
    write(t/'first',h+'.json',{'host':h,'status':'PASS','runtime_active':True,'smoke':smoke,'protected_containers':[]});write(t/'final',h+'.json',{'host':h,'status':'PASS','runtime_active':True,'smoke':smoke,'protected_containers':[]});write(t/'pre',h+'.json',{'host':h,'stage_manifest_sha256':'a','protected_containers':[]});write(t/'rolled',h+'.json',{'host':h,'status':'PASS','runtime_active':False,'active_link_exists':False,'stage_manifest_sha256':'b' if h=='opt2' else 'a','protected_containers':[]})
   for h in ('g732','Thinkpad-P50'):
    x={'host':h,'status':'PASS','runtime_active':False,'capability':{'new_process_started':False},'stage_manifest_sha256':'a','protected_containers':[]};write(t/'cap1',h+'.json',x);write(t/'cap2',h+'.json',x);write(t/'pre',h+'.json',{'host':h,'stage_manifest_sha256':'a','protected_containers':[]})
   out=t/'out.json';cp=subprocess.run(['python3',str(ROOT/'scripts/evaluate_deployment.py'),'--policy',str(ROOT/'config/policy.json'),'--pre-mutation-qualification',str(qual),'--first-smoke',str(t/'first'),'--rollback-inspection',str(t/'rolled'),'--final-smoke',str(t/'final'),'--capability-first',str(t/'cap1'),'--capability-final',str(t/'cap2'),'--preflight',str(t/'pre'),'--output',str(out)],capture_output=True,text=True);self.assertNotEqual(cp.returncode,0);self.assertIn('opt2 staged payload drifted',json.loads(out.read_text())['problems'])
 def test_deployment_evaluator_rejects_missing_config_rebinding(self):
  with tempfile.TemporaryDirectory() as td:
   t=pathlib.Path(td)
   for d in ['first','rolled','final','cap1','cap2','pre']:(t/d).mkdir()
   qual=write(t,'qualification.json',{'host':'opt1','action':'qualify','status':'PASS','pre_mutation_qualification':True,'runtime_active':False,'persistent_runtime_mutation_performed':False,'temporary_qualification_mutation_performed':True,'docker_invoked':False,'temporary_root_removed':True,'persistent_runtime_absent':True,'stage_preserved':True,'config_rebinding':{'persistent_path_residue':['review-console.json'],'review_console_activation_input_paths_verified':False,'rewritten_config_files':['runtime.json'],'resealed_config_files':[{'path':'runtime.json'}],'declared_seal_regeneration_complete':False,'activation_input_paths_verified':{}}})
   out=t/'out.json';cp=subprocess.run(['python3',str(ROOT/'scripts/evaluate_deployment.py'),'--policy',str(ROOT/'config/policy.json'),'--pre-mutation-qualification',str(qual),'--first-smoke',str(t/'first'),'--rollback-inspection',str(t/'rolled'),'--final-smoke',str(t/'final'),'--capability-first',str(t/'cap1'),'--capability-final',str(t/'cap2'),'--preflight',str(t/'pre'),'--output',str(out)],capture_output=True,text=True);self.assertNotEqual(cp.returncode,0);problems=json.loads(out.read_text())['problems'];self.assertIn('Opt1 qualification retained persistent runtime path residue',problems);self.assertIn('Opt1 required governed configurations were not rebound',problems)
 def test_deployment_evaluator_rejects_missing_prequalification(self):
  with tempfile.TemporaryDirectory() as td:
   t=pathlib.Path(td);empty=[]
   for d in ['first','rolled','final','cap1','cap2','pre']:(t/d).mkdir()
   qual=write(t,'qualification.json',{'host':'opt1','action':'qualify','status':'BLOCKED','runtime_active':False})
   out=t/'out.json';cp=subprocess.run(['python3',str(ROOT/'scripts/evaluate_deployment.py'),'--policy',str(ROOT/'config/policy.json'),'--pre-mutation-qualification',str(qual),'--first-smoke',str(t/'first'),'--rollback-inspection',str(t/'rolled'),'--final-smoke',str(t/'final'),'--capability-first',str(t/'cap1'),'--capability-final',str(t/'cap2'),'--preflight',str(t/'pre'),'--output',str(out)],capture_output=True,text=True);self.assertNotEqual(cp.returncode,0);self.assertIn('Opt1 pre-mutation qualification failed',json.loads(out.read_text())['problems'])
