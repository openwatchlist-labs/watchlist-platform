#!/usr/bin/env python3
"""Fail the build when Go source outside the seam hands SQL naming a
tenant-scoped relation to a command runner (ADR-0001 SEC-1, §3).

Detection is deliberately a grep-style backstop rather than dataflow
analysis (ADR §3 point 3): it scans Go string literals for the SQL verbs
INSERT INTO / UPDATE / DELETE FROM / FROM / JOIN immediately followed by a
relation named in db/tenant_scoped_tables.txt (the single source of truth,
ADR §3 point 1), and fails on any such call site that is not inside
internal/tenantsql or covered by the two-class allowlist (ADR §3 point 4).
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TABLES = ROOT / "db" / "tenant_scoped_tables.txt"
DEFAULT_ALLOWLIST = ROOT / "db" / "tenant_binding_allowlist.txt"

SEAM_PACKAGE_PREFIX = "internal/tenantsql/"

SQL_VERBS = ("INSERT INTO", "UPDATE", "DELETE FROM", "FROM", "JOIN")

STRING_LITERAL_RE = re.compile(
    r'"(?:[^"\\\n]|\\.)*"'   # interpreted string literals (single line)
    r"|`[^`]*`",             # raw string literals (may span lines)
)

FUNC_DECL_RE = re.compile(r"^func\s*(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)

SKIP_DIRS = {".git"}


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)


@dataclass(frozen=True)
class AllowlistEntry:
    kind: str  # "permanent" | "transitional"
    matcher: str
    justification: str
    line_no: int


@dataclass(frozen=True)
class CallSite:
    rel_path: str
    line_no: int
    verb: str
    relation: str
    func_name: str | None


def load_tables(path: Path) -> list[str]:
    if not path.is_file():
        fail(f"missing tenant-scoped table list: {path}")
        raise SystemExit(1)
    tables = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not tables:
        fail(f"tenant-scoped table list is empty: {path}")
        raise SystemExit(1)
    return tables


def load_allowlist(path: Path) -> list[AllowlistEntry]:
    if not path.is_file():
        fail(f"missing tenant-binding allowlist: {path}")
        raise SystemExit(1)
    entries: list[AllowlistEntry] = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = raw.split("\t")
        if len(parts) != 3:
            fail(f"{path}:{line_no}: malformed allowlist entry (expected 3 tab-separated fields)")
            raise SystemExit(1)
        kind, matcher, justification = (p.strip() for p in parts)
        if kind not in ("permanent", "transitional"):
            fail(f"{path}:{line_no}: unknown allowlist class {kind!r}")
            raise SystemExit(1)
        if not matcher:
            fail(f"{path}:{line_no}: allowlist entry has an empty matcher")
            raise SystemExit(1)
        if not justification:
            fail(f"{path}:{line_no}: allowlist entry for {matcher!r} has no justification")
            raise SystemExit(1)
        entries.append(AllowlistEntry(kind, matcher, justification, line_no))
    return entries


def go_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for base, dirs, files in _walk(root):
        for name in files:
            if name.endswith(".go"):
                out.append(Path(base) / name)
    return sorted(out)


def _walk(root: Path):
    import os

    for base, dirs, files in os.walk(root, topdown=True, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        yield base, dirs, files


def enclosing_func(prefix_text: str) -> str | None:
    last = None
    for m in FUNC_DECL_RE.finditer(prefix_text):
        last = m
    return last.group(1) if last else None


def find_call_sites(root: Path, tables: list[str]) -> tuple[list[CallSite], set[str]]:
    table_pattern = "|".join(re.escape(t) for t in tables)
    verb_res = [(verb, re.compile(rf'\b{re.escape(verb)}\s+"?({table_pattern})\b')) for verb in SQL_VERBS]

    sites: list[CallSite] = []
    all_func_names: set[str] = set()
    seen: set[tuple[str, int, str]] = set()

    for path in go_files(root):
        text = path.read_text(encoding="utf-8")
        rel_path = path.relative_to(root).as_posix()
        all_func_names.update(m.group(1) for m in FUNC_DECL_RE.finditer(text))
        for lit in STRING_LITERAL_RE.finditer(text):
            literal = lit.group(0)
            for verb, verb_re in verb_res:
                for m in verb_re.finditer(literal):
                    relation = m.group(1)
                    abs_start = lit.start() + m.start()
                    line_no = text.count("\n", 0, abs_start) + 1
                    key = (rel_path, line_no, relation)
                    if key in seen:
                        continue
                    seen.add(key)
                    func_name = enclosing_func(text[: lit.start()])
                    sites.append(CallSite(rel_path, line_no, verb, relation, func_name))
    return sites, all_func_names


def allows(entry: AllowlistEntry, site: CallSite) -> bool:
    matcher = entry.matcher
    if matcher.endswith("/"):
        return site.rel_path.startswith(matcher)
    if "/" in matcher:
        return site.rel_path == matcher
    return site.func_name == matcher


def entry_resolves(entry: AllowlistEntry, root: Path, all_func_names: set[str]) -> bool:
    # Transitional entries only resolve by matching a live call site; if we
    # get here for a transitional entry it matched none, so it is stale.
    if entry.kind == "transitional":
        return False
    matcher = entry.matcher
    if matcher.endswith("/"):
        return (root / matcher).is_dir()
    if "/" in matcher:
        return (root / matcher).is_file()
    return matcher in all_func_names


def run(root: Path, tables_path: Path, allowlist_path: Path) -> int:
    tables = load_tables(tables_path)
    allowlist = load_allowlist(allowlist_path)
    sites, all_func_names = find_call_sites(root, tables)

    ok = True
    matched_entries: set[AllowlistEntry] = set()

    for site in sites:
        if site.rel_path.startswith(SEAM_PACKAGE_PREFIX):
            continue
        matched_entry = None
        for entry in allowlist:
            if allows(entry, site):
                matched_entry = entry
                break
        if matched_entry is None:
            fail(
                f"{site.rel_path}:{site.line_no}: {site.verb} {site.relation} reaches a "
                f"command runner outside internal/tenantsql and outside the allowlist "
                f"({allowlist_path}) -- ADR-0001 §3"
            )
            ok = False
        else:
            matched_entries.add(matched_entry)

    for entry in allowlist:
        if entry in matched_entries:
            continue
        if not entry_resolves(entry, root, all_func_names):
            fail(
                f"{allowlist_path}:{entry.line_no}: {entry.kind} allowlist entry "
                f"{entry.matcher!r} no longer resolves to real code; remove it"
            )
            ok = False

    if ok:
        print(
            f"PASS: check_tenant_binding "
            f"({len(sites)} call site(s) checked against {len(tables)} tenant-scoped "
            f"relation(s), {len(allowlist)} allowlist entries)"
        )
        return 0
    return 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--tables", type=Path, default=None)
    parser.add_argument("--allowlist", type=Path, default=None)
    args = parser.parse_args(argv)

    root = args.root.resolve()
    tables_path = args.tables if args.tables is not None else root / "db" / "tenant_scoped_tables.txt"
    allowlist_path = args.allowlist if args.allowlist is not None else root / "db" / "tenant_binding_allowlist.txt"
    return run(root, tables_path, allowlist_path)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
