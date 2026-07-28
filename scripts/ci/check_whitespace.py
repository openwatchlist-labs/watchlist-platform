#!/usr/bin/env python3
"""Govern exact source-bound inherited whitespace without rewriting source files.

Unchanged imported files may retain only the exact recorded warnings. Once a
reviewed file changes, its inherited exception retires and the changed file must
be whitespace-clean. New warnings anywhere are rejected.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import NoReturn

WARNING_RE = re.compile(
    r"^(?P<path>.+):(?P<line>[1-9][0-9]*): "
    r"(?P<kind>trailing whitespace\.|space before tab in indent\.)$"
)
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def fail(message: str, details: list[str] | None = None) -> NoReturn:
    print(f"FAIL: {message}", file=sys.stderr)
    for detail in details or []:
        print(detail, file=sys.stderr)
    raise SystemExit(1)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read JSON {path}: {exc}")
    if not isinstance(payload, dict):
        fail(f"JSON root is not an object: {path}")
    return payload


def parse_baseline(path: Path) -> tuple[dict[str, str], list[str], dict[str, str]]:
    metadata: dict[str, str] = {}
    warnings: list[str] = []
    file_hashes: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        fail(f"cannot read whitespace baseline {path}: {exc}")
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("warning="):
            warning = line.removeprefix("warning=")
            if not WARNING_RE.fullmatch(warning):
                fail(f"invalid warning at {path}:{number}: {warning}")
            warnings.append(warning)
            continue
        if line.startswith("file_sha256="):
            value = line.removeprefix("file_sha256=")
            if "|" not in value:
                fail(f"invalid file_sha256 at {path}:{number}")
            rel, digest = value.rsplit("|", 1)
            if not rel or not HASH_RE.fullmatch(digest):
                fail(f"invalid file_sha256 at {path}:{number}")
            if rel in file_hashes:
                fail(f"duplicate file_sha256 path: {rel}")
            file_hashes[rel] = digest
            continue
        if "=" not in line:
            fail(f"invalid metadata row at {path}:{number}: {raw}")
        key, value = line.split("=", 1)
        if key in metadata:
            fail(f"duplicate metadata key: {key}")
        metadata[key] = value
    required = {"schema_version", "source_commit", "source_tree"}
    missing = sorted(required - metadata.keys())
    if missing:
        fail(f"whitespace baseline missing metadata: {missing}")
    if metadata["schema_version"] != "1":
        fail("unsupported whitespace baseline schema_version")
    if len(warnings) != len(set(warnings)):
        fail("duplicate whitespace warnings")
    warning_paths = {WARNING_RE.fullmatch(w).group("path") for w in warnings}
    if warning_paths != set(file_hashes):
        fail(
            "whitespace warning paths and file hashes differ",
            [
                f"warning-only={sorted(warning_paths - set(file_hashes))}",
                f"hash-only={sorted(set(file_hashes) - warning_paths)}",
            ],
        )
    return metadata, warnings, file_hashes


def validate_metadata(
    metadata: dict[str, str],
    warnings: list[str],
    file_hashes: dict[str, str],
    plan: dict[str, object],
    manifest: dict[str, object] | None,
) -> None:
    source = plan.get("source", {})
    if not isinstance(source, dict):
        fail("plan source is not an object")
    if metadata["source_commit"] != source.get("commit"):
        fail("whitespace baseline source commit differs from plan")
    if metadata["source_tree"] != source.get("tree"):
        fail("whitespace baseline source tree differs from plan")
    selected = {
        entry.get("path")
        for entry in plan.get("selected", [])
        if isinstance(entry, dict)
    }
    for rel in file_hashes:
        if rel not in selected:
            fail(f"whitespace baseline path is not selected: {rel}")
    if manifest is not None:
        imported = {
            item.get("path"): item.get("sha256")
            for item in manifest.get("files", [])
            if isinstance(item, dict)
        }
        for rel, digest in file_hashes.items():
            if imported.get(rel) != digest:
                fail(f"whitespace baseline hash differs from import manifest: {rel}")
    for warning in warnings:
        match = WARNING_RE.fullmatch(warning)
        assert match is not None
        if match.group("path") not in file_hashes:
            fail(f"warning has no file hash: {warning}")


def tracked_paths(root: Path) -> list[str]:
    proc = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        fail("git ls-files failed", [proc.stderr.decode("utf-8", "replace").strip()])
    return [x.decode("utf-8", "strict") for x in proc.stdout.split(b"\0") if x]


def scan(root: Path) -> list[str]:
    warnings: list[str] = []
    for rel in tracked_paths(root):
        path = root / rel
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        for number, line in enumerate(data.splitlines(), 1):
            if line.endswith((b" ", b"\t")):
                warnings.append(f"{rel}:{number}: trailing whitespace.")
            indent = line[: len(line) - len(line.lstrip(b" \t"))]
            if b" \t" in indent:
                warnings.append(f"{rel}:{number}: space before tab in indent.")
    return warnings


def validate_root(
    root: Path,
    warnings: list[str],
    file_hashes: dict[str, str],
    require_inherited_bytes: bool,
) -> tuple[int, int]:
    warnings_by_path: dict[str, list[str]] = {}
    for warning in warnings:
        match = WARNING_RE.fullmatch(warning)
        assert match is not None
        warnings_by_path.setdefault(match.group("path"), []).append(warning)

    active_paths: set[str] = set()
    retired_paths: set[str] = set()
    for rel, expected in file_hashes.items():
        path = root / rel
        current_matches = path.is_file() and not path.is_symlink() and sha256(path) == expected
        if current_matches:
            active_paths.add(rel)
        else:
            retired_paths.add(rel)
            if require_inherited_bytes:
                fail(f"bootstrap inherited whitespace file hash changed: {rel}")

    allowed = [
        warning
        for warning in warnings
        if WARNING_RE.fullmatch(warning).group("path") in active_paths
    ]
    actual = scan(root)
    if actual != allowed:
        missing = sorted(set(allowed) - set(actual))
        unexpected = sorted(set(actual) - set(allowed))
        fail(
            "tracked-tree whitespace differs from active inherited exceptions",
            [f"missing={missing}", f"unexpected={unexpected}"],
        )
    return len(allowed), len(retired_paths)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--require-inherited-bytes", action="store_true")
    args = parser.parse_args()

    metadata, warnings, file_hashes = parse_baseline(args.baseline)
    plan = load_json(args.plan)
    manifest = load_json(args.manifest) if args.manifest else None
    validate_metadata(metadata, warnings, file_hashes, plan, manifest)
    if args.validate_only:
        print(
            "PASS: inherited whitespace baseline metadata "
            f"({len(warnings)} exact warnings across {len(file_hashes)} files)"
        )
        return 0
    if args.root is None or args.manifest is None:
        fail("--root and --manifest are required outside --validate-only")
    active_warnings, retired_paths = validate_root(
        args.root.resolve(), warnings, file_hashes, args.require_inherited_bytes
    )
    print(
        "PASS: inherited whitespace governance "
        f"({active_warnings} active warnings; {retired_paths} retired file exceptions)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
