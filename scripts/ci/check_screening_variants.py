#!/usr/bin/env python3
"""Regrowth gate for the screening-api variants deleted under REL-10
(ADR-0002 §9). Fails the build if any `cmd/screening-api-v8*` or
`internal/screeningapiv8*` path reappears in `git ls-files`.

ADR-0001:222-229 is the reason this exists rather than relying on review:
this debt already grew back once.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

FORBIDDEN_PREFIXES = (
    "cmd/screening-api-v8",
    "internal/screeningapiv8",
)


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)


def tracked_files(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.splitlines()


def run(root: Path) -> int:
    offenders = [
        path
        for path in tracked_files(root)
        if any(path.startswith(prefix) for prefix in FORBIDDEN_PREFIXES)
    ]
    if offenders:
        for path in offenders:
            fail(f"{path}: a v8 screening-api variant path was reintroduced -- ADR-0002 §9")
        return 1
    print("PASS: check_screening_variants (no v8 screening-api variant paths present)")
    return 0


def main(argv: list[str]) -> int:
    del argv
    return run(ROOT)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
