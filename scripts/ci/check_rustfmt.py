#!/usr/bin/env python3
"""Govern exact source-bound inherited Rust formatting debt without rewrites.

Unchanged imported Rust files may retain only the exact recorded rustfmt drift.
When one of those files changes, its inherited exception retires and the changed
file must be rustfmt-clean. New formatting drift anywhere is rejected.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import NoReturn

HASH_RE = re.compile(r"^[0-9a-f]{64}$")
TOOLCHAIN_RE = re.compile(r'^\s*channel\s*=\s*"([^"]+)"\s*$', re.MULTILINE)


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


def parse_baseline(path: Path) -> tuple[dict[str, str], dict[str, str]]:
    metadata: dict[str, str] = {}
    path_hashes: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        fail(f"cannot read Rust formatting baseline {path}: {exc}")
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("path_sha256="):
            value = line.removeprefix("path_sha256=")
            if "|" not in value:
                fail(f"invalid path_sha256 at {path}:{number}")
            rel, digest = value.rsplit("|", 1)
            if not rel.endswith(".rs") or not HASH_RE.fullmatch(digest):
                fail(f"invalid path_sha256 at {path}:{number}")
            if rel in path_hashes:
                fail(f"duplicate Rust formatting path: {rel}")
            path_hashes[rel] = digest
            continue
        if "=" not in line:
            fail(f"invalid metadata row at {path}:{number}: {raw}")
        key, value = line.split("=", 1)
        if key in metadata:
            fail(f"duplicate metadata key: {key}")
        metadata[key] = value
    required = {"schema_version", "source_commit", "source_tree", "toolchain_channel"}
    missing = sorted(required - metadata.keys())
    if missing:
        fail(f"Rust formatting baseline missing metadata: {missing}")
    if metadata["schema_version"] != "1":
        fail("unsupported Rust formatting baseline schema_version")
    return metadata, path_hashes


def validate_metadata(
    metadata: dict[str, str],
    path_hashes: dict[str, str],
    plan: dict[str, object],
    manifest: dict[str, object] | None,
) -> None:
    source = plan.get("source", {})
    if not isinstance(source, dict):
        fail("plan source is not an object")
    if metadata["source_commit"] != source.get("commit"):
        fail("Rust formatting baseline source commit differs from plan")
    if metadata["source_tree"] != source.get("tree"):
        fail("Rust formatting baseline source tree differs from plan")
    selected = {
        entry.get("path")
        for entry in plan.get("selected", [])
        if isinstance(entry, dict)
    }
    for rel in path_hashes:
        if rel not in selected:
            fail(f"Rust formatting baseline path is not selected: {rel}")
    if manifest is not None:
        imported = {
            item.get("path"): item.get("sha256")
            for item in manifest.get("files", [])
            if isinstance(item, dict)
        }
        for rel, digest in path_hashes.items():
            if imported.get(rel) != digest:
                fail(f"Rust formatting baseline hash differs from import manifest: {rel}")


def toolchain_channel(root: Path) -> str:
    path = root / "rust-toolchain.toml"
    if not path.is_file():
        fail("missing reconstructed rust-toolchain.toml")
    match = TOOLCHAIN_RE.search(path.read_text(encoding="utf-8"))
    if not match:
        fail("rust-toolchain.toml has no channel")
    return match.group(1)


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


def run(command: list[str], cwd: Path) -> str:
    proc = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        env=os.environ.copy(),
    )
    if proc.returncode != 0:
        fail(f"command failed ({proc.returncode}): {' '.join(command)}", [proc.stdout.rstrip()])
    return proc.stdout.strip()


def copy_tracked_tree(root: Path, destination: Path, paths: list[str]) -> None:
    for rel in paths:
        source = root / rel
        if not source.is_file() or source.is_symlink():
            continue
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def active_exception_paths(root: Path, path_hashes: dict[str, str]) -> set[str]:
    active: set[str] = set()
    for rel, expected in path_hashes.items():
        path = root / rel
        if path.is_file() and not path.is_symlink() and sha256(path) == expected:
            active.add(rel)
    return active


def validate_formatting(
    root: Path,
    metadata: dict[str, str],
    path_hashes: dict[str, str],
    require_inherited_bytes: bool,
) -> None:
    expected_channel = metadata["toolchain_channel"]
    actual_channel = toolchain_channel(root)
    if actual_channel != expected_channel:
        fail(f"Rust toolchain channel differs: expected {expected_channel}, got {actual_channel}")

    rustc_version = run(["rustc", "--version"], root)
    if not rustc_version.startswith(f"rustc {expected_channel} "):
        fail(f"unexpected rustc version for pinned toolchain: {rustc_version}")
    rustfmt_version = run(["rustfmt", "--version"], root)

    active = active_exception_paths(root, path_hashes)
    retired = set(path_hashes) - active
    if require_inherited_bytes and retired:
        fail(
            "bootstrap inherited Rust formatting file hashes changed",
            [f"changed_or_missing={sorted(retired)}"],
        )

    paths = tracked_paths(root)
    before_rs = {
        rel: (root / rel).read_bytes()
        for rel in paths
        if rel.endswith(".rs") and (root / rel).is_file() and not (root / rel).is_symlink()
    }
    with tempfile.TemporaryDirectory(prefix="openwatchlist-rustfmt-check-") as tmp:
        temp_root = Path(tmp)
        copy_tracked_tree(root, temp_root, paths)
        run(["cargo", "fmt", "--all"], temp_root)
        after_rs = {rel: (temp_root / rel).read_bytes() for rel in before_rs}
        changed = sorted(rel for rel in before_rs if before_rs[rel] != after_rs[rel])
        expected = sorted(active)
        if changed != expected:
            fail(
                "Rust formatting drift differs from active inherited exceptions",
                [
                    f"missing={sorted(set(expected) - set(changed))}",
                    f"unexpected={sorted(set(changed) - set(expected))}",
                ],
            )
        run(["cargo", "fmt", "--all", "--", "--check"], temp_root)

    print(
        "PASS: inherited Rust formatting governance "
        f"({len(active)} active exceptions; {len(retired)} retired; "
        f"{rustc_version}; {rustfmt_version})"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--metadata-only", action="store_true")
    parser.add_argument("--require-inherited-bytes", action="store_true")
    args = parser.parse_args()

    metadata, path_hashes = parse_baseline(args.baseline)
    plan = load_json(args.plan)
    manifest = load_json(args.manifest) if args.manifest else None
    validate_metadata(metadata, path_hashes, plan, manifest)
    if args.validate_only:
        print(
            "PASS: inherited Rust formatting baseline metadata "
            f"({len(path_hashes)} exact files; toolchain {metadata['toolchain_channel']})"
        )
        return 0
    if args.root is None or args.manifest is None:
        fail("--root and --manifest are required outside --validate-only")
    root = args.root.resolve()
    actual_channel = toolchain_channel(root)
    if actual_channel != metadata["toolchain_channel"]:
        fail(
            "Rust toolchain channel differs: "
            f"expected {metadata['toolchain_channel']}, got {actual_channel}"
        )
    if args.metadata_only:
        active = active_exception_paths(root, path_hashes)
        if args.require_inherited_bytes and len(active) != len(path_hashes):
            fail("bootstrap inherited Rust formatting file hashes changed")
        print(
            "PASS: inherited Rust formatting provenance "
            f"({len(active)} active byte-bound exceptions; "
            f"{len(path_hashes) - len(active)} retired; toolchain {actual_channel})"
        )
        return 0
    validate_formatting(root, metadata, path_hashes, args.require_inherited_bytes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
