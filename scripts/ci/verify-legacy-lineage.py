#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, pathlib, subprocess, sys

EXPECTED_SCHEMA = "openwatchlist.legacy-qualification-lineage.v1"
EXPECTED_LEGACY_COMMIT = "31aa23f516018f7577f4dcec95142f981142a6f8"
EXPECTED_LEGACY_TREE = "cd6e0d80584c05bde3a14582ab895b6e4ed79df3"
FORBIDDEN_PREFIXES = (
    "cmd/homelab-qualification/",
    "deploy/homelab/",
    "scripts/homelab/",
    "testdata/homelab/",
    "var/homelab/",
    "target/",
)
FORBIDDEN_SEGMENTS = ("/evidence/", "/materialized/", "/binding-candidates/")

def fail(msg: str) -> None:
    raise SystemExit(f"FAIL: {msg}")

def tracked(root: pathlib.Path, supplied: pathlib.Path | None) -> list[str]:
    if supplied:
        return [x.strip() for x in supplied.read_text(encoding="utf-8").splitlines() if x.strip()]
    cp = subprocess.run(["git","-C",str(root),"ls-files"],text=True,capture_output=True)
    if cp.returncode:
        fail(f"git ls-files failed: {cp.stderr.strip()}")
    return [x for x in cp.stdout.splitlines() if x]

def verify(root: pathlib.Path, supplied: pathlib.Path | None = None) -> None:
    path=root/"docs/governance/legacy-qualification-lineage.json"
    if not path.is_file(): fail(f"missing {path.relative_to(root)}")
    data=json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != EXPECTED_SCHEMA: fail("unexpected lineage schema")
    if data.get("legacy_freeze_commit") != EXPECTED_LEGACY_COMMIT: fail("legacy freeze commit drift")
    if data.get("legacy_freeze_tree") != EXPECTED_LEGACY_TREE: fail("legacy freeze tree drift")
    disp=data.get("disposition",{})
    expected={"visibility":"private","archived":True,"actions_enabled":False,"new_development_allowed":False,"release_source":False,"deployment_source":False}
    for k,v in expected.items():
        if disp.get(k) != v: fail(f"invalid disposition field {k}")
    policy=data.get("import_policy",{})
    for k in ("raw_legacy_test_results_imported","raw_legacy_evidence_imported"):
        if policy.get(k) is not False: fail(f"{k} must be false")
    if policy.get("legacy_test_files_copied") != 0: fail("legacy test files must not be copied")
    if policy.get("legacy_operational_scripts_copied") != 0: fail("legacy operational scripts must not be copied")
    records=data.get("qualification_records")
    if not isinstance(records,list) or len(records) < 5: fail("insufficient qualification lineage")
    for rec in records:
        if rec.get("raw_evidence_imported") is not False: fail(f"raw evidence imported for {rec.get('id')}")
        coverage=rec.get("canonical_coverage")
        if not isinstance(coverage,list) or not coverage: fail(f"missing canonical coverage for {rec.get('id')}")
        for rel in coverage:
            if not (root/rel).exists(): fail(f"missing canonical coverage path: {rel}")
    files=tracked(root,supplied)
    for rel in files:
        norm=rel.replace('\\','/')
        if norm.startswith(FORBIDDEN_PREFIXES): fail(f"legacy-only tracked path: {norm}")
        if any(seg in f"/{norm}" for seg in FORBIDDEN_SEGMENTS): fail(f"generated evidence/materialized path: {norm}")
        if norm.endswith('.go') and ('evidence' in norm or 'materialized' in norm):
            fail(f"stale generated Go evidence path: {norm}")
    required=(
      "docs/governance/legacy-repository.md",
      "docs/governance/legacy-qualification-lineage.md",
      "scripts/ci/tests/test_legacy_lineage.py",
    )
    for rel in required:
        if not (root/rel).is_file(): fail(f"missing {rel}")
    print(f"PASS: sanitized legacy lineage and exclusion regressions ({len(files)} tracked paths)")

def main() -> None:
    ap=argparse.ArgumentParser()
    ap.add_argument('--root',default=None)
    ap.add_argument('--tracked-file-list',type=pathlib.Path)
    ns=ap.parse_args()
    root=pathlib.Path(ns.root).resolve() if ns.root else pathlib.Path(__file__).resolve().parents[2]
    verify(root,ns.tracked_file_list)
if __name__=='__main__': main()
