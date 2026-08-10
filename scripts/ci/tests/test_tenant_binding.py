#!/usr/bin/env python3
from __future__ import annotations
import pathlib, subprocess, sys, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
CHECK = ROOT / "scripts/ci/check_tenant_binding.py"

TABLES = "alert_record\nalert_case\n"

# A permanent entry whose matcher is guaranteed to exist in every fixture
# tree written by write_tree() below, so tests unrelated to staleness don't
# have to fabricate a real "Migrate" function just to keep the allowlist
# itself from being flagged as stale.
PERMANENT_ALLOWLIST = "permanent\tdb/\tAlways present: write_tree() creates db/.\n"


def run(root: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECK), "--root", str(root)],
        text=True,
        capture_output=True,
    )


def write_tree(root: pathlib.Path, tables: str, allowlist: str, go_files: dict[str, str]) -> None:
    (root / "db").mkdir(parents=True, exist_ok=True)
    (root / "db" / "tenant_scoped_tables.txt").write_text(tables, encoding="utf-8")
    (root / "db" / "tenant_binding_allowlist.txt").write_text(allowlist, encoding="utf-8")
    for rel, content in go_files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


class TenantBindingCheckTests(unittest.TestCase):
    def test_current_repo_tree_passes(self) -> None:
        result = run(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS: check_tenant_binding", result.stdout)

    def test_unbound_query_against_listed_relation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            write_tree(
                root,
                TABLES,
                PERMANENT_ALLOWLIST,
                {
                    "internal/somesink/postgres.go": (
                        "package somesink\n\n"
                        "func (p *PostgresSink) Persist(ctx context.Context, id string) error {\n"
                        '\tsql := "INSERT INTO alert_record(alert_id) VALUES (" + id + ")"\n'
                        "\treturn p.run(ctx, sql)\n"
                        "}\n"
                    ),
                },
            )
            result = run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("internal/somesink/postgres.go:4", result.stderr)
            self.assertIn("INSERT INTO alert_record", result.stderr)

    def test_call_site_inside_seam_package_is_permitted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            write_tree(
                root,
                TABLES,
                PERMANENT_ALLOWLIST,
                {
                    "internal/tenantsql/bind.go": (
                        "package tenantsql\n\n"
                        "func WithTenant(ctx context.Context) error {\n"
                        '\tsql := "INSERT INTO alert_record(alert_id) VALUES (1)"\n'
                        "\treturn run(ctx, sql)\n"
                        "}\n"
                    ),
                },
            )
            result = run(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_call_site_covered_by_transitional_allowlist_entry_is_permitted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            allowlist = PERMANENT_ALLOWLIST + (
                "transitional\tinternal/somesink/postgres.go\tPre-seam sink; moves to internal/tenantsql.\n"
            )
            write_tree(
                root,
                TABLES,
                allowlist,
                {
                    "internal/somesink/postgres.go": (
                        "package somesink\n\n"
                        "func (p *PostgresSink) Persist(ctx context.Context, id string) error {\n"
                        '\tsql := "INSERT INTO alert_record(alert_id) VALUES (" + id + ")"\n'
                        "\treturn p.run(ctx, sql)\n"
                        "}\n"
                    ),
                },
            )
            result = run(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_stale_transitional_entry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            allowlist = PERMANENT_ALLOWLIST + (
                "transitional\tinternal/somesink/postgres.go\tPre-seam sink; moves to internal/tenantsql.\n"
            )
            write_tree(
                root,
                TABLES,
                allowlist,
                {
                    # File exists but no longer touches a tenant-scoped relation.
                    "internal/somesink/postgres.go": (
                        "package somesink\n\n"
                        "func (p *PostgresSink) Ping(ctx context.Context) error {\n"
                        '\treturn p.run(ctx, "SELECT 1")\n'
                        "}\n"
                    ),
                },
            )
            result = run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("no longer resolves to real code", result.stderr)

    def test_stale_permanent_function_entry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            allowlist = (
                "permanent\tMigrate\towl_migrator runs schema DDL, unbound by design.\n"
                "permanent\tRotate\tstale entry: no function named Rotate exists anywhere.\n"
            )
            write_tree(
                root,
                TABLES,
                allowlist,
                {
                    "internal/somesink/postgres.go": (
                        "package somesink\n\n"
                        "func (p *PostgresSink) Migrate(ctx context.Context) error {\n"
                        "\treturn p.run(ctx, SchemaSQL)\n"
                        "}\n"
                    ),
                },
            )
            result = run(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("'Rotate'", result.stderr)
            self.assertIn("no longer resolves to real code", result.stderr)
            self.assertNotIn("'Migrate'", result.stderr)

    def test_relation_absent_from_table_list_is_not_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            write_tree(
                root,
                TABLES,  # only alert_record and alert_case are declared
                PERMANENT_ALLOWLIST,
                {
                    "internal/somesink/postgres.go": (
                        "package somesink\n\n"
                        "func (p *PostgresSink) Persist(ctx context.Context) error {\n"
                        '\treturn p.run(ctx, "INSERT INTO screening_ledger_event(x) VALUES (1)")\n'
                        "}\n"
                    ),
                },
            )
            result = run(root)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
