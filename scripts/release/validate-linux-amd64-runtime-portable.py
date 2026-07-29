#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import struct
import tarfile
from typing import Any

EXPECTED_BINARIES = (
    "platform-api",
    "platform-ops",
    "container-healthcheck",
    "catalog-mmap",
)
EXPECTED_MACHINE = 62  # EM_X86_64
EXPECTED_CLASS = 2  # ELFCLASS64
EXPECTED_DATA = 1  # ELFDATA2LSB
EXPECTED_VERSION = 1
EXPECTED_TYPES = {2, 3}  # ET_EXEC or ET_DYN (PIE)
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_elf64_x86_64(data: bytes, name: str) -> dict[str, Any]:
    problems: list[dict[str, Any]] = []
    if len(data) < 64:
        problems.append({"code": "elf_header_truncated", "size": len(data)})
        return {"path": name, "status": "FAIL", "problems": problems}

    ident = data[:16]
    if ident[:4] != b"\x7fELF":
        problems.append({"code": "elf_magic_mismatch", "actual_hex": ident[:4].hex()})
    if ident[4] != EXPECTED_CLASS:
        problems.append({"code": "elf_class_mismatch", "actual": ident[4], "expected": EXPECTED_CLASS})
    if ident[5] != EXPECTED_DATA:
        problems.append({"code": "elf_endianness_mismatch", "actual": ident[5], "expected": EXPECTED_DATA})
    if ident[6] != EXPECTED_VERSION:
        problems.append({"code": "elf_ident_version_mismatch", "actual": ident[6], "expected": EXPECTED_VERSION})

    endian = "<" if ident[5] == 1 else ">"
    try:
        e_type, e_machine, e_version = struct.unpack_from(endian + "HHI", data, 16)
        e_ehsize = struct.unpack_from(endian + "H", data, 52)[0]
    except struct.error as exc:
        problems.append({"code": "elf_header_unpack_failed", "error": str(exc)})
        return {"path": name, "status": "FAIL", "problems": problems}

    if e_type not in EXPECTED_TYPES:
        problems.append({"code": "elf_type_mismatch", "actual": e_type, "expected": sorted(EXPECTED_TYPES)})
    if e_machine != EXPECTED_MACHINE:
        problems.append({"code": "elf_machine_mismatch", "actual": e_machine, "expected": EXPECTED_MACHINE})
    if e_version != EXPECTED_VERSION:
        problems.append({"code": "elf_header_version_mismatch", "actual": e_version, "expected": EXPECTED_VERSION})
    if e_ehsize < 64:
        problems.append({"code": "elf_header_size_invalid", "actual": e_ehsize, "minimum": 64})

    return {
        "path": name,
        "status": "PASS" if not problems else "FAIL",
        "elf": {
            "class": "ELF64" if ident[4] == 2 else ident[4],
            "endianness": "little" if ident[5] == 1 else "big" if ident[5] == 2 else ident[5],
            "machine": "x86-64" if e_machine == EXPECTED_MACHINE else e_machine,
            "machine_id": e_machine,
            "type": e_type,
            "header_size": e_ehsize,
        },
        "problems": problems,
    }


def safe_member_name(name: str) -> bool:
    pure = pathlib.PurePosixPath(name)
    return bool(name) and not pure.is_absolute() and ".." not in pure.parts and "" not in pure.parts


def load_json_bytes(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value


def validate_archive(archive_path: pathlib.Path, manifest_path: pathlib.Path) -> dict[str, Any]:
    problems: list[dict[str, Any]] = []
    binaries: list[dict[str, Any]] = []

    if not archive_path.is_file():
        return {"status": "FAIL", "problems": [{"code": "archive_missing", "path": str(archive_path)}]}
    if not manifest_path.is_file():
        return {"status": "FAIL", "problems": [{"code": "manifest_missing", "path": str(manifest_path)}]}

    try:
        external = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "FAIL", "problems": [{"code": "external_manifest_unreadable", "error": str(exc)}]}

    if not isinstance(external, dict):
        return {"status": "FAIL", "problems": [{"code": "external_manifest_not_object"}]}

    version = external.get("version")
    vcs_ref = external.get("vcs_ref")
    target = external.get("target")
    if external.get("schema") != "openwatchlist.linux-amd64-runtime-manifest.v1":
        problems.append({"code": "manifest_schema_mismatch", "actual": external.get("schema")})
    if not isinstance(version, str) or not version:
        problems.append({"code": "manifest_version_invalid", "actual": version})
    if not isinstance(vcs_ref, str) or not re.fullmatch(r"[0-9a-f]{40}", vcs_ref):
        problems.append({"code": "manifest_vcs_ref_invalid", "actual": vcs_ref})
    if target != {"os": "linux", "arch": "amd64", "rust_target": "x86_64-unknown-linux-gnu"}:
        problems.append({"code": "manifest_target_mismatch", "actual": target})
    if external.get("compiler_required_on_runtime_host") is not False:
        problems.append({"code": "compiler_runtime_contract_mismatch"})
    if external.get("deployment_performed") is not False:
        problems.append({"code": "deployment_boundary_mismatch"})

    expected_root = f"openwatchlist-{version}-linux-amd64-runtime" if isinstance(version, str) else None
    file_bytes: dict[str, bytes] = {}
    file_modes: dict[str, int] = {}
    directory_names: set[str] = set()

    try:
        with tarfile.open(archive_path, "r:gz") as tf:
            members = tf.getmembers()
            if not members:
                problems.append({"code": "archive_empty"})
            seen_names: set[str] = set()
            roots: set[str] = set()
            for member in members:
                if member.name in seen_names:
                    problems.append({"code": "archive_duplicate_member", "path": member.name})
                    continue
                seen_names.add(member.name)
                if not safe_member_name(member.name):
                    problems.append({"code": "archive_unsafe_path", "path": member.name})
                    continue
                roots.add(member.name.split("/", 1)[0])
                if member.issym() or member.islnk():
                    problems.append({"code": "archive_link_forbidden", "path": member.name})
                elif member.isdir():
                    directory_names.add(member.name.rstrip("/"))
                    if member.mode & 0o777 != 0o755:
                        problems.append({"code": "archive_directory_mode_mismatch", "path": member.name, "actual": oct(member.mode & 0o777), "expected": "0o755"})
                elif member.isfile():
                    extracted = tf.extractfile(member)
                    if extracted is None:
                        problems.append({"code": "archive_file_unreadable", "path": member.name})
                        continue
                    file_bytes[member.name] = extracted.read()
                    file_modes[member.name] = member.mode & 0o777
                else:
                    problems.append({"code": "archive_member_type_forbidden", "path": member.name})
            if len(roots) != 1:
                problems.append({"code": "archive_root_count_mismatch", "roots": sorted(roots)})
            elif expected_root and roots != {expected_root}:
                problems.append({"code": "archive_root_mismatch", "actual": sorted(roots), "expected": expected_root})
    except (tarfile.TarError, OSError) as exc:
        problems.append({"code": "archive_unreadable", "error": str(exc)})

    if expected_root:
        expected_files = {
            f"{expected_root}/bin/{name}" for name in EXPECTED_BINARIES
        } | {
            f"{expected_root}/manifest.json",
            f"{expected_root}/SHA256SUMS",
        }
        actual_files = set(file_bytes)
        missing = sorted(expected_files - actual_files)
        extra = sorted(actual_files - expected_files)
        if missing:
            problems.append({"code": "archive_expected_files_missing", "paths": missing})
        if extra:
            problems.append({"code": "archive_unexpected_files", "paths": extra})

        expected_dirs = {f"{expected_root}/bin"}
        extra_dirs = sorted(directory_names - expected_dirs)
        missing_dirs = sorted(expected_dirs - directory_names)
        if missing_dirs:
            problems.append({"code": "archive_expected_directories_missing", "paths": missing_dirs})
        if extra_dirs:
            problems.append({"code": "archive_unexpected_directories", "paths": extra_dirs})

        for path in sorted(expected_files):
            if path not in file_modes:
                continue
            expected_mode = 0o755 if "/bin/" in path else 0o644
            if file_modes[path] != expected_mode:
                problems.append({"code": "archive_file_mode_mismatch", "path": path, "actual": oct(file_modes[path]), "expected": oct(expected_mode)})

        embedded_path = f"{expected_root}/manifest.json"
        checksums_path = f"{expected_root}/SHA256SUMS"
        if embedded_path in file_bytes:
            try:
                embedded = load_json_bytes(file_bytes[embedded_path], "embedded manifest")
                external_without_archive = dict(external)
                external_without_archive.pop("archive", None)
                if embedded != external_without_archive:
                    problems.append({"code": "embedded_external_manifest_mismatch"})
            except ValueError as exc:
                problems.append({"code": "embedded_manifest_unreadable", "error": str(exc)})

        checksum_entries: dict[str, str] = {}
        if checksums_path in file_bytes:
            try:
                lines = file_bytes[checksums_path].decode("utf-8").splitlines()
            except UnicodeDecodeError as exc:
                problems.append({"code": "checksums_not_utf8", "error": str(exc)})
                lines = []
            for line_number, line in enumerate(lines, 1):
                if "  ./" not in line:
                    problems.append({"code": "checksum_line_malformed", "line": line_number})
                    continue
                digest, rel = line.split("  ./", 1)
                if not HEX64.fullmatch(digest) or not safe_member_name(rel):
                    problems.append({"code": "checksum_line_malformed", "line": line_number})
                    continue
                if rel in checksum_entries:
                    problems.append({"code": "checksum_duplicate_path", "path": rel})
                    continue
                checksum_entries[rel] = digest

            checksum_subjects = {
                path[len(expected_root) + 1 :]: data
                for path, data in file_bytes.items()
                if path != checksums_path
            }
            if set(checksum_entries) != set(checksum_subjects):
                problems.append({
                    "code": "checksum_subject_set_mismatch",
                    "missing": sorted(set(checksum_subjects) - set(checksum_entries)),
                    "extra": sorted(set(checksum_entries) - set(checksum_subjects)),
                })
            for rel, data in checksum_subjects.items():
                expected_digest = checksum_entries.get(rel)
                actual_digest = sha256_bytes(data)
                if expected_digest is not None and expected_digest != actual_digest:
                    problems.append({"code": "checksum_mismatch", "path": rel, "actual": actual_digest, "expected": expected_digest})

        manifest_files = external.get("files")
        if not isinstance(manifest_files, list):
            problems.append({"code": "manifest_files_invalid"})
        else:
            by_path = {item.get("path"): item for item in manifest_files if isinstance(item, dict) and isinstance(item.get("path"), str)}
            expected_manifest_paths = {f"bin/{name}" for name in EXPECTED_BINARIES}
            if set(by_path) != expected_manifest_paths:
                problems.append({"code": "manifest_file_set_mismatch", "actual": sorted(by_path), "expected": sorted(expected_manifest_paths)})
            for rel in sorted(expected_manifest_paths):
                archive_name = f"{expected_root}/{rel}"
                if archive_name not in file_bytes or rel not in by_path:
                    continue
                item = by_path[rel]
                actual_digest = sha256_bytes(file_bytes[archive_name])
                actual_size = len(file_bytes[archive_name])
                if item.get("sha256") != actual_digest:
                    problems.append({"code": "manifest_file_hash_mismatch", "path": rel})
                if item.get("size") != actual_size:
                    problems.append({"code": "manifest_file_size_mismatch", "path": rel, "actual": actual_size, "expected": item.get("size")})
                if item.get("mode") != "0755":
                    problems.append({"code": "manifest_file_mode_mismatch", "path": rel, "actual": item.get("mode")})

        for name in EXPECTED_BINARIES:
            archive_name = f"{expected_root}/bin/{name}"
            if archive_name in file_bytes:
                record = parse_elf64_x86_64(file_bytes[archive_name], f"bin/{name}")
                binaries.append(record)
                problems.extend({"code": item["code"], "path": f"bin/{name}", **{k: v for k, v in item.items() if k != "code"}} for item in record["problems"])

    archive_contract = external.get("archive")
    if isinstance(archive_contract, dict):
        actual_archive_hash = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        actual_archive_size = archive_path.stat().st_size
        if archive_contract.get("name") != archive_path.name:
            problems.append({"code": "external_archive_name_mismatch", "actual": archive_path.name, "expected": archive_contract.get("name")})
        if archive_contract.get("sha256") != actual_archive_hash:
            problems.append({"code": "external_archive_hash_mismatch", "actual": actual_archive_hash, "expected": archive_contract.get("sha256")})
        if archive_contract.get("size") != actual_archive_size:
            problems.append({"code": "external_archive_size_mismatch", "actual": actual_archive_size, "expected": archive_contract.get("size")})
    else:
        problems.append({"code": "external_archive_contract_missing"})

    return {
        "schema": "openwatchlist.linux-amd64-runtime-portable-validation.v1",
        "status": "PASS" if not problems else "FAIL",
        "archive": {
            "name": archive_path.name,
            "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
            "size": archive_path.stat().st_size,
        },
        "manifest": {
            "name": manifest_path.name,
            "sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        },
        "target": {"os": "linux", "arch": "amd64", "elf_machine": "x86-64", "elf_machine_id": EXPECTED_MACHINE},
        "binary_count": len(binaries),
        "binaries": binaries,
        "safe_archive_validation_performed": True,
        "sha256_validation_performed": True,
        "portable_elf_header_validation_performed": True,
        "binary_execution_performed": False,
        "dynamic_linker_validation_performed": False,
        "compiler_invocation_performed": False,
        "compiler_required_on_runtime_host": False,
        "deployment_performed": False,
        "problem_count": len(problems),
        "problems": problems,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Portable structural validator for OpenWatchlist Linux AMD64 runtime archives")
    parser.add_argument("--archive", required=True, type=pathlib.Path)
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()

    result = validate_archive(args.archive, args.manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
