#!/usr/bin/env python3
"""Fail closed when legacy harness material or unsafe repository state returns."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
EXCLUSIONS = ROOT / ".clean-restart" / "legacy-exclusions.txt"
MANIFEST = ROOT / ".clean-restart" / "import-manifest.json"
PLAN = ROOT / ".clean-restart" / "import-plan.json"
POLICY = ROOT / ".clean-restart" / "import-policy.json"
IMPORTED_HASHES = ROOT / ".clean-restart" / "imported-files.sha256"
BASELINE_HASHES = ROOT / ".clean-restart" / "baseline-files.sha256"


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def git_paths() -> list[str]:
    proc = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        fail(f"git ls-files failed: {proc.stderr.decode('utf-8', 'replace').strip()}")
    return sorted(p.decode("utf-8", "strict") for p in proc.stdout.split(b"\0") if p)


def filesystem_paths() -> list[str]:
    values: list[str] = []
    for base, dirs, files in os.walk(ROOT, topdown=True, followlinks=False):
        dirs[:] = [d for d in dirs if d != ".git"]
        base_path = Path(base)
        for name in dirs + files:
            path = base_path / name
            values.append(path.relative_to(ROOT).as_posix())
    return sorted(values)


def load_patterns() -> list[re.Pattern[str]]:
    if not EXCLUSIONS.is_file():
        fail(f"missing exclusion policy: {EXCLUSIONS.relative_to(ROOT)}")
    patterns: list[re.Pattern[str]] = []
    for line_no, raw in enumerate(EXCLUSIONS.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            patterns.append(re.compile(line, re.IGNORECASE))
        except re.error as exc:
            fail(f"invalid exclusion regex line {line_no}: {exc}")
    return patterns


def parse_hash_list(path: Path) -> dict[str, str]:
    if not path.is_file():
        fail(f"missing checksum list: {path.relative_to(ROOT)}")
    values: dict[str, str] = {}
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            fail(f"invalid checksum-list line {line_no} in {path.relative_to(ROOT)}")
        digest, rel = match.groups()
        if rel.startswith("/") or ".." in Path(rel).parts or rel in values:
            fail(f"unsafe or duplicate checksum path {rel} in {path.relative_to(ROOT)}")
        values[rel] = digest
    if not values:
        fail(f"empty checksum list: {path.relative_to(ROOT)}")
    return values


def validate_provenance(tracked: list[str], verify_bootstrap_bytes: bool) -> None:
    payloads = {}
    for path in (MANIFEST, PLAN, POLICY):
        if not path.is_file():
            fail(f"missing provenance file: {path.relative_to(ROOT)}")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            fail(f"invalid JSON in {path.relative_to(ROOT)}: {exc}")
        if not isinstance(payload, dict) or payload.get("schema_version") != 1:
            fail(f"unsupported provenance schema in {path.relative_to(ROOT)}")
        payloads[path] = payload

    manifest = payloads[MANIFEST]
    plan = payloads[PLAN]
    policy = payloads[POLICY]
    source = manifest.get("source", {})
    if not re.fullmatch(r"[0-9a-f]{40}", str(source.get("commit", ""))):
        fail("import manifest does not contain a full source commit SHA")
    if not re.fullmatch(r"[0-9a-f]{40}", str(source.get("tree", ""))):
        fail("import manifest does not contain a full source tree SHA")
    if plan.get("source", {}).get("commit") != source.get("commit"):
        fail("plan and manifest source commits differ")
    if plan.get("source", {}).get("tree") != source.get("tree"):
        fail("plan and manifest source trees differ")

    policy_sha = hashlib.sha256(POLICY.read_bytes()).hexdigest()
    if manifest.get("policy", {}).get("sha256") != policy_sha:
        fail("durable import policy SHA-256 differs from import manifest")
    if plan.get("policy", {}).get("sha256") != policy_sha:
        fail("durable import policy SHA-256 differs from import plan")
    if policy.get("policy_id") != "openwatchlist-clean-restart-r1.6":
        fail("unexpected durable import policy ID")

    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        fail("import manifest contains no files")
    if manifest.get("file_count") != len(files):
        fail("import manifest file_count does not match files")
    paths = [entry.get("path") for entry in files if isinstance(entry, dict)]
    if len(paths) != len(files) or len(paths) != len(set(paths)):
        fail("import manifest file paths are missing or duplicated")
    if paths != sorted(paths):
        fail("import manifest file paths are not sorted")
    for entry in files:
        path = str(entry.get("path", ""))
        if path.startswith("/") or ".." in Path(path).parts:
            fail(f"unsafe imported path: {path}")
        if not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", ""))):
            fail(f"invalid imported-file SHA-256 for {path}")
        if not re.fullmatch(r"[0-9a-f]{40}", str(entry.get("git_oid", ""))):
            fail(f"invalid imported Git object ID for {path}")

    counts = plan.get("counts", {})
    if counts.get("selected") != len(plan.get("selected", [])):
        fail("plan selected count mismatch")
    if counts.get("excluded") != len(plan.get("excluded", [])):
        fail("plan excluded count mismatch")

    imported_hashes = parse_hash_list(IMPORTED_HASHES)
    expected_hashes = {entry["path"]: entry["sha256"] for entry in files}
    if imported_hashes != expected_hashes:
        fail("imported-files checksum list differs from import manifest")
    baseline_hashes = parse_hash_list(BASELINE_HASHES)
    if ".clean-restart/baseline-files.sha256" in baseline_hashes:
        fail("baseline checksum list must exclude itself")

    # The baseline list is immutable historical provenance. It must contain the
    # exact imported source hashes, but normal post-bootstrap CI must not compare
    # all current files to those initial hashes or future development would be
    # impossible.
    missing_imported = sorted(set(expected_hashes) - set(baseline_hashes))
    if missing_imported:
        fail(f"baseline checksum list omits imported paths: {missing_imported[:10]}")
    for rel, digest in expected_hashes.items():
        if baseline_hashes.get(rel) != digest:
            fail(f"historical baseline hash differs from imported source hash: {rel}")

    if verify_bootstrap_bytes:
        for rel, expected in expected_hashes.items():
            full = ROOT / rel
            if not full.is_file() or full.is_symlink():
                fail(f"imported manifest path is not a regular file: {rel}")
            actual = hashlib.sha256(full.read_bytes()).hexdigest()
            if actual != expected:
                fail(f"imported source blob changed after materialization: {rel}")

        expected_baseline_paths = set(tracked) - {".clean-restart/baseline-files.sha256"}
        if set(baseline_hashes) != expected_baseline_paths:
            missing = sorted(expected_baseline_paths - set(baseline_hashes))
            extra = sorted(set(baseline_hashes) - expected_baseline_paths)
            fail(
                "bootstrap baseline checksum paths differ from tracked files "
                f"missing={missing[:10]} extra={extra[:10]}"
            )
        for rel, digest in baseline_hashes.items():
            full = ROOT / rel
            if not full.is_file() or full.is_symlink():
                fail(f"bootstrap checksum path is not a tracked regular file: {rel}")
            actual = hashlib.sha256(full.read_bytes()).hexdigest()
            if actual != digest:
                fail(f"bootstrap checksum mismatch for tracked file: {rel}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-bootstrap-bytes", action="store_true")
    args = parser.parse_args()

    if ROOT.joinpath("go.work").exists():
        fail("go.work is forbidden in the clean root; use the canonical root module")

    patterns = load_patterns()
    tracked = git_paths()
    tracked_set = set(tracked)

    folded: dict[str, str] = {}
    for path in tracked:
        key = path.casefold()
        if key in folded and folded[key] != path:
            fail(f"case-colliding tracked paths: {folded[key]} and {path}")
        folded[key] = path
        full = ROOT / path
        if full.is_symlink():
            fail(f"tracked symlink is forbidden: {path}")
        for pattern in patterns:
            if pattern.search(path):
                fail(f"tracked legacy/excluded path: {path} (matched {pattern.pattern})")

    go_mods = sorted(path for path in tracked if path == "go.mod" or path.endswith("/go.mod"))
    if go_mods != ["go.mod"]:
        fail(f"exactly one root go.mod is required; found {go_mods}")

    cargo_manifests = sorted(
        path for path in tracked if path == "Cargo.toml" or path.endswith("/Cargo.toml")
    )
    if any(path != "Cargo.toml" for path in cargo_manifests):
        if "Cargo.toml" not in tracked_set:
            fail(f"nested Cargo manifests require a canonical root workspace: {cargo_manifests}")
        if "Cargo.lock" not in tracked_set:
            fail("canonical Cargo workspace requires a tracked root Cargo.lock")

    # Untracked content can still be discovered by `go test ./...`. Reject the
    # exact contamination classes while ignoring ordinary untracked build caches.
    critical = [
        re.compile(r"(^|/)var(/|$)", re.IGNORECASE),
        re.compile(r"(^|/)homelab/evidence(/|$)", re.IGNORECASE),
        re.compile(r"(^|/)materialized/selector(/|$)", re.IGNORECASE),
        re.compile(r"(^|/)provider-activation-r[^/]*/", re.IGNORECASE),
    ]
    for path in filesystem_paths():
        if path in tracked_set:
            continue
        if any(pattern.search(path) for pattern in critical):
            fail(f"untracked legacy contamination path: {path}")
        if path.endswith(".go") and re.search(
            r"(^|/)(evidence|generated|materialized|results)(/|$)", path, re.IGNORECASE
        ):
            fail(f"untracked generated/evidence Go source: {path}")

    workflow_root = ROOT / ".github" / "workflows"
    if workflow_root.is_dir():
        for path in workflow_root.glob("*.y*ml"):
            text = path.read_text(encoding="utf-8")
            if "pull_request_target:" in text:
                fail(f"pull_request_target is forbidden in {path.relative_to(ROOT)}")
            if re.search(r"persist-credentials:\s*true", text, re.IGNORECASE):
                fail(f"persist-credentials true is forbidden in {path.relative_to(ROOT)}")

    validate_provenance(tracked, args.verify_bootstrap_bytes)
    print(f"PASS: clean-restart exclusion gate ({len(tracked)} tracked paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
