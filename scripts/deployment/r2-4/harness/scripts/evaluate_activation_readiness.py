#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,json,pathlib
ap=argparse.ArgumentParser();ap.add_argument('--policy',required=True);ap.add_argument('--staging-summary',required=True);ap.add_argument('--input-validation',required=True);ap.add_argument('--source-lock',required=True);ap.add_argument('--archives',required=True);ap.add_argument('--preflights',required=True);ap.add_argument('--output',required=True);a=ap.parse_args()
p=json.load(open(a.policy));st=json.load(open(a.staging_summary));iv=json.load(open(a.input_validation));sl=json.load(open(a.source_lock));ar=json.load(open(a.archives));problems=[];rows=[]
if st.get('schema')!=p['staging_summary_schema'] or st.get('status')!=p['staging_status'] or st.get('target_tag')!=p['target_tag']:problems.append('accepted staging evidence mismatch')
if st.get('runtime_started') is not False or st.get('activation_performed') is not False or st.get('problems')!=[]:problems.append('staging no-start boundary mismatch')
if iv.get('status')!='PASS' or iv.get('problems')!=[] or (iv.get('corpus_validation') or {}).get('status')!='PASS':problems.append('activation input or governed corpus validation failed')
if sl.get('status')!='PASS' or sl.get('problems')!=[] or sl.get('commit')!=p['main_commit'] or sl.get('repository')!=p['repository'] or sl.get('source_count')!=5 or sl.get('remote_mutation_performed') is not False:problems.append('independent source-lock verification failed')
if ar.get('status')!='PASS' or ar.get('archive_count')!=2:problems.append('activation input archive construction failed')
for f in sorted(pathlib.Path(a.preflights).glob('*.json')):
 x=json.load(open(f));rows.append(x)
 if x.get('status')!='PASS' or x.get('problems')!=[] or x.get('remote_mutation_performed') is not False:problems.append(f'host preflight failed: {x.get("host")}')
 if x.get('runtime_root_exists') is not False or x.get('active_link_exists') is not False:problems.append(f'preexisting runtime state: {x.get("host")}')
if {x.get('host') for x in rows}!={h['name'] for h in p['hosts']}:problems.append('four-host preflight result set mismatch')
opt1=next((x for x in rows if x.get('host')=='opt1'),{});g732=next((x for x in rows if x.get('host')=='g732'),{});p50=next((x for x in rows if x.get('host')=='Thinkpad-P50'),{})
if not (opt1.get('capability') or {}).get('ollama_reachable_from_opt1'):problems.append('Opt1-to-G732 Ollama binding not ready')
if not (g732.get('capability') or {}).get('required_models_present'):problems.append('G732 required models not ready')
if (p50.get('capability') or {}).get('qdrant_status')!=200:problems.append('P50 capability not ready')
out={'schema':'openwatchlist.r2-4-r1-8-3-4-activation-readiness.v1','status':p['activation_readiness_status'] if not problems else 'BLOCKED','target_tag':p['target_tag'],'release_id':p['release_id'],'staging_evidence_sha256':hashlib.sha256(pathlib.Path(a.staging_summary).read_bytes()).hexdigest(),'host_count':len(rows),'hosts':rows,'input_validation':iv,'source_lock':sl,'input_archives':ar,'activation_scope':{'runtime_hosts':['opt1','opt2'],'capability_only_hosts':['g732','Thinkpad-P50'],'opt1_api_bind':p['opt1_api_bind'],'opt1_postgres_bind':p['opt1_postgres_bind'],'protected_postgres_port':p['protected_postgres_port']},'pre_mutation_opt1_qualification_required':True,'complete_temporary_root_rebinding_required':True,'qualification_first_opt2_transfer_required':True,'remote_mutation_performed':False,'compiler_required_on_hosts':False,'problems':problems}
pathlib.Path(a.output).write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');print(json.dumps(out,indent=2,sort_keys=True));raise SystemExit(0 if not problems else 2)
