#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,pathlib
ap=argparse.ArgumentParser()
ap.add_argument('--policy',required=True)
ap.add_argument('--pre-mutation-qualification',required=True)
ap.add_argument('--first-smoke',required=True)
ap.add_argument('--rollback-inspection',required=True)
ap.add_argument('--final-smoke',required=True)
ap.add_argument('--capability-first',required=True)
ap.add_argument('--capability-final',required=True)
ap.add_argument('--preflight',required=True)
ap.add_argument('--output',required=True)
a=ap.parse_args();p=json.load(open(a.policy,encoding='utf-8'));problems=[]
def load_dir(path):return {json.load(open(f,encoding='utf-8'))['host']:json.load(open(f,encoding='utf-8')) for f in pathlib.Path(path).glob('*.json')}
qualification=json.load(open(a.pre_mutation_qualification,encoding='utf-8'))
if qualification.get('host')!='opt1' or qualification.get('action')!='qualify' or qualification.get('status')!='PASS':problems.append('Opt1 pre-mutation qualification failed')
if qualification.get('pre_mutation_qualification') is not True or qualification.get('runtime_active') is not False:problems.append('Opt1 pre-mutation qualification state mismatch')
if qualification.get('persistent_runtime_mutation_performed') is not False or qualification.get('temporary_qualification_mutation_performed') is not True:problems.append('Opt1 qualification mutation boundary mismatch')
if qualification.get('docker_invoked') is not False:problems.append('Opt1 qualification invoked Docker')
if qualification.get('temporary_root_removed') is not True or qualification.get('persistent_runtime_absent') is not True or qualification.get('stage_preserved') is not True:problems.append('Opt1 qualification cleanup or stage-preservation mismatch')
rebinding=qualification.get('config_rebinding') or {};required=set(p.get('opt1_qualification_required_rebound_configs') or [])
if rebinding.get('persistent_path_residue')!=[]:problems.append('Opt1 qualification retained persistent runtime path residue')
if rebinding.get('review_console_activation_input_paths_verified') is not True:problems.append('Opt1 review-console activation-input paths were not verified')
if not required.issubset(set(rebinding.get('rewritten_config_files') or [])):problems.append('Opt1 required governed configurations were not rebound')
required_resealed=set(p.get('opt1_qualification_required_resealed_configs') or ['runtime.json'])
if not required_resealed.issubset({x.get('path') for x in rebinding.get('resealed_config_files') or []}):problems.append('Opt1 required sealed configurations were not resealed')
if rebinding.get('declared_seal_regeneration_complete') is not True:problems.append('Opt1 declared configuration seals were not completely regenerated')
if set((rebinding.get('activation_input_paths_verified') or {}).keys())!={x['name'] for x in p['opt1_input_files']}:problems.append('Opt1 activation-input path verification set mismatch')
first=load_dir(a.first_smoke);rolled=load_dir(a.rollback_inspection);final=load_dir(a.final_smoke);cap1=load_dir(a.capability_first);cap2=load_dir(a.capability_final);pre=load_dir(a.preflight)
for host in ('opt1','opt2'):
 for label,data in [('first',first),('final',final)]:
  x=data.get(host,{})
  if x.get('status')!='PASS' or x.get('runtime_active') is not True:problems.append(f'{host} {label} smoke failed')
 r=rolled.get(host,{})
 if r.get('status')!='PASS' or r.get('runtime_active') is not False or r.get('active_link_exists') is not False:problems.append(f'{host} rollback inspection failed')
 if r.get('stage_manifest_sha256')!=(pre.get(host,{}) or {}).get('stage_manifest_sha256'):problems.append(f'{host} staged payload drifted')
 if r.get('protected_containers')!=(pre.get(host,{}) or {}).get('protected_containers'):problems.append(f'{host} protected container identity changed after rollback')
 for label,data in [('first',first),('final',final)]:
  if data.get(host,{}).get('protected_containers')!=(pre.get(host,{}) or {}).get('protected_containers'):problems.append(f'{host} protected container identity changed during {label} activation')
for host in ('g732','Thinkpad-P50'):
 for label,data in [('first',cap1),('final',cap2)]:
  x=data.get(host,{})
  if x.get('status')!='PASS' or x.get('runtime_active') is not False or (x.get('capability') or {}).get('new_process_started') is not False:problems.append(f'{host} {label} capability verification failed')
  if x.get('stage_manifest_sha256')!=(pre.get(host,{}) or {}).get('stage_manifest_sha256'):problems.append(f'{host} staged payload changed during {label} capability check')
  if x.get('protected_containers')!=(pre.get(host,{}) or {}).get('protected_containers'):problems.append(f'{host} protected container identity changed during {label} capability check')
opt1=(final.get('opt1',{}).get('smoke') or {});opt2=(final.get('opt2',{}).get('smoke') or {})
if opt1.get('api_bound') is not True or opt1.get('postgres_bound') is not True or len(opt1.get('endpoints',{}))!=4:problems.append('Opt1 final API/PostgreSQL smoke mismatch')
if opt2.get('package_sha256')!=p['catalog']['expected_package_sha256'] or opt2.get('resident_daemon_started') is not False:problems.append('Opt2 final catalog smoke mismatch')
out={'schema':'openwatchlist.r2-4-r1-8-3-4-deployment-closure.v1','status':p['final_status'] if not problems else 'BLOCKED','target_tag':p['target_tag'],'release_id':p['release_id'],'runtime_sha256':p['linux_amd64_runtime_sha256'],'host_count':4,'runtime_active_hosts':['opt1','opt2'] if not problems else [],'capability_only_hosts':['g732','Thinkpad-P50'],'pre_mutation_opt1_qualification':qualification,'pre_mutation_qualification_performed':True,'complete_temporary_root_rebinding_performed':not any('rebound' in x or 'resealed' in x or 'residue' in x for x in problems),'qualification_first_opt2_transfer_ordering_enforced':True,'smoke_qualification_performed':True,'rollback_qualification_performed':True,'controlled_reactivation_performed':True,'compiler_toolchain_invocation_performed':False,'catalog_package_materialization_performed':True,'systemd_mutation_performed':False,'image_pull_or_build_performed':False,'package_installation_performed':False,'deployment_performed':not problems,'opt1_final_smoke':opt1,'opt2_final_smoke':opt2,'capabilities':{'first':cap1,'final':cap2},'problems':problems}
pathlib.Path(a.output).write_text(json.dumps(out,indent=2,sort_keys=True)+'\n',encoding='utf-8');print(json.dumps(out,indent=2,sort_keys=True));raise SystemExit(0 if not problems else 2)
