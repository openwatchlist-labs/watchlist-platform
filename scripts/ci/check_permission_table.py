#!/usr/bin/env python3
"""Fail the build when resourcePermissions in internal/reviewauth/registry.go
does not track every permission string actually tested by internal/reviewconsoleapi
and every concrete permission listed in configs/**/identity-registry*.json (PR #102).

resourcePermissions is the closed, enumerable set of concrete permission strings the
system checks, grouped by resource. It must track every permission string that:
1. Appears in a permit(...) call in internal/reviewconsoleapi
2. Appears as a concrete permission in any identity-registry*.json config

A "resource.*" wildcard grant expands to exactly this set -- not to any permission
string that happens to share the "resource." prefix.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)


@dataclass(frozen=True)
class Permission:
    value: str
    source: str
    location: str


def find_identity_registries(root: Path) -> list[Path]:
    """Find all identity-registry*.json files in configs subdirectories."""
    registries = list(root.glob("configs/**/identity-registry*.json"))
    return sorted(registries)


def extract_permissions_from_configs(registries: list[Path]) -> set[str]:
    """Extract all concrete permission strings from identity-registry*.json files.

    Excludes wildcard permissions like "alert.*" and "*", returning only
    concrete permissions that are actually checked or expected to exist.
    """
    concrete_perms: set[str] = set()

    for path in registries:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, FileNotFoundError) as e:
            fail(f"Failed to parse {path}: {e}")
            raise SystemExit(1)

        for role in data.get("roles", []):
            for perm in role.get("permissions", []):
                if perm == "*":
                    continue
                if not perm.endswith(".*"):
                    concrete_perms.add(perm)

    return concrete_perms


def extract_permissions_from_code(root: Path) -> set[str]:
    """Extract all permission strings passed to permit(...) calls in reviewconsoleapi."""
    permit_perms: set[str] = set()

    review_api_dir = root / "internal" / "reviewconsoleapi"
    if not review_api_dir.is_dir():
        fail(f"reviewconsoleapi directory not found: {review_api_dir}")
        raise SystemExit(1)

    for go_file in review_api_dir.glob("*.go"):
        text = go_file.read_text(encoding="utf-8")

        for m in re.finditer(r'permit\s*\(\s*[^,]+\s*,\s*[^,]+\s*,\s*"([^"]+)"\s*\)', text):
            permit_perms.add(m.group(1))

    return permit_perms


def extract_resource_permissions(root: Path) -> dict[str, set[str]]:
    """Extract resourcePermissions map from internal/reviewauth/registry.go.

    Returns a dict mapping resource name to set of concrete permissions.
    """
    registry_file = root / "internal" / "reviewauth" / "registry.go"
    if not registry_file.is_file():
        fail(f"registry.go not found: {registry_file}")
        raise SystemExit(1)

    text = registry_file.read_text(encoding="utf-8")

    resource_perms: dict[str, set[str]] = {}

    # Find the resourcePermissions variable assignment
    # Pattern: var resourcePermissions = map[string][]string{ ... }
    match = re.search(
        r'var\s+resourcePermissions\s*=\s*map\[string\]\[\]string\s*\{(.*?)\n\}',
        text,
        re.DOTALL
    )

    if not match:
        fail("Could not find resourcePermissions map in registry.go")
        raise SystemExit(1)

    map_body = match.group(1)

    # Extract each resource entry: "resource": {"perm1", "perm2", ...},
    # Each line typically has: "resource": {"perm1", "perm2"},
    for line in map_body.split('\n'):
        line = line.strip()
        if not line:
            continue

        # Parse line like: "alert": {"alert.read"},
        entry_match = re.match(r'"([^"]+)"\s*:\s*\{([^}]*)\}', line)
        if not entry_match:
            continue

        resource = entry_match.group(1)
        perms_str = entry_match.group(2)

        perms: set[str] = set()
        for perm_match in re.finditer(r'"([^"]+)"', perms_str):
            perms.add(perm_match.group(1))

        resource_perms[resource] = perms

    return resource_perms


def run(root: Path) -> int:
    registries = find_identity_registries(root)
    if not registries:
        fail("No identity-registry*.json files found")
        raise SystemExit(1)

    config_perms = extract_permissions_from_configs(registries)
    code_perms = extract_permissions_from_code(root)
    resource_perms = extract_resource_permissions(root)

    all_required_perms = config_perms | code_perms
    all_defined_perms: set[str] = set()
    for perms in resource_perms.values():
        all_defined_perms.update(perms)

    ok = True

    for perm in sorted(all_required_perms):
        if perm not in all_defined_perms:
            fail(
                f"Permission {perm!r} is used in configs or code but not found "
                f"in resourcePermissions map (internal/reviewauth/registry.go)"
            )
            ok = False

    for resource, perms in sorted(resource_perms.items()):
        for perm in sorted(perms):
            if perm not in all_required_perms:
                fail(
                    f"Permission {perm!r} in resourcePermissions map "
                    f"(resource {resource!r}) does not correspond to any real permission "
                    f"found in configs or code"
                )
                ok = False

    if ok:
        config_count = len(registries)
        print(
            f"PASS: check_permission_table "
            f"({len(all_required_perms)} required permission(s) checked "
            f"against {config_count} config file(s), "
            f"{len(all_defined_perms)} defined permission(s) in resourcePermissions)"
        )
        return 0
    return 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)

    root = args.root.resolve()
    return run(root)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
