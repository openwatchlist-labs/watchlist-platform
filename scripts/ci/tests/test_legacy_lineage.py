#!/usr/bin/env python3
from __future__ import annotations
import json, os, pathlib, shutil, subprocess, tempfile, unittest

ROOT=pathlib.Path(__file__).resolve().parents[3]
VERIFY=ROOT/'scripts/ci/verify-legacy-lineage.py'

def run(files: list[str]) -> subprocess.CompletedProcess[str]:
    with tempfile.NamedTemporaryFile('w',delete=False,encoding='utf-8') as f:
        f.write('\n'.join(files)+'\n'); name=f.name
    try:
        env=os.environ.copy(); env['PYTHONDONTWRITEBYTECODE']='1'
        return subprocess.run([str(VERIFY),'--root',str(ROOT),'--tracked-file-list',name],text=True,capture_output=True,env=env)
    finally: pathlib.Path(name).unlink(missing_ok=True)

class LegacyLineageRegressionTests(unittest.TestCase):
    def test_current_canonical_tree_passes(self) -> None:
        cp=subprocess.run(['git','-C',str(ROOT),'ls-files'],text=True,capture_output=True,check=True)
        result=run(cp.stdout.splitlines())
        self.assertEqual(result.returncode,0,result.stderr)

    def test_legacy_operational_path_is_rejected(self) -> None:
        result=run(['README.md','scripts/homelab/h1-stage.sh'])
        self.assertNotEqual(result.returncode,0)
        self.assertIn('legacy-only tracked path',result.stderr)

    def test_stale_generated_go_evidence_is_rejected(self) -> None:
        result=run(['README.md','var/homelab/evidence/provider/materialized/selector/internal/screeningapi/stale.go'])
        self.assertNotEqual(result.returncode,0)
        self.assertTrue('legacy-only tracked path' in result.stderr or 'stale generated Go evidence path' in result.stderr)

    def test_raw_result_import_flag_is_fail_closed(self) -> None:
        source=ROOT/'docs/governance/legacy-qualification-lineage.json'
        data=json.loads(source.read_text(encoding='utf-8'))
        with tempfile.TemporaryDirectory() as td:
            tmp=pathlib.Path(td)
            shutil.copytree(ROOT/'docs',tmp/'docs')
            shutil.copytree(ROOT/'scripts',tmp/'scripts')
            data['import_policy']['raw_legacy_test_results_imported']=True
            (tmp/'docs/governance/legacy-qualification-lineage.json').write_text(json.dumps(data),encoding='utf-8')
            files=tmp/'files.txt'; files.write_text('README.md\n',encoding='utf-8')
            cp=subprocess.run([str(VERIFY),'--root',str(tmp),'--tracked-file-list',str(files)],text=True,capture_output=True)
            self.assertNotEqual(cp.returncode,0)
            self.assertIn('raw_legacy_test_results_imported must be false',cp.stderr)

if __name__=='__main__': unittest.main(verbosity=2)
