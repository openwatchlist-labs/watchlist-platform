#!/usr/bin/env python3
"""Negative tests for check_permission_table.py."""

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def run_check(root: Path) -> tuple[int, str, str]:
    """Run check_permission_table.py against a given root, return (returncode, stdout, stderr)."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "ci" / "check_permission_table.py"), "--root", str(root)],
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout, result.stderr


def test_detects_missing_permission():
    """Test that the check fails when a real permission is missing from resourcePermissions."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        # Copy the structure needed by the check
        (tmpdir_path / "configs" / "review-console").mkdir(parents=True)
        (tmpdir_path / "internal" / "reviewconsoleapi").mkdir(parents=True)
        (tmpdir_path / "internal" / "reviewauth").mkdir(parents=True)

        # Copy identity registry (uses real config with security.audit.read)
        registry_config = ROOT / "configs" / "review-console" / "identity-registry-r1.json"
        if registry_config.exists():
            (tmpdir_path / "configs" / "review-console" / "identity-registry-r1.json").write_text(
                registry_config.read_text()
            )

        # Copy server.go (uses permit() calls including security.audit.read)
        server_file = ROOT / "internal" / "reviewconsoleapi" / "server.go"
        if server_file.exists():
            (tmpdir_path / "internal" / "reviewconsoleapi" / "server.go").write_text(
                server_file.read_text()
            )

        # Create a registry.go with security.audit.read REMOVED from resourcePermissions
        registry_template = ROOT / "internal" / "reviewauth" / "registry.go"
        if registry_template.exists():
            content = registry_template.read_text()
            # Remove security.audit.read from resourcePermissions by removing the "security" entry
            broken_content = content.replace(
                '"security": {"security.audit.read"},\n',
                ''
            )
            # Also remove it from the PermissionAllowed function if it exists
            broken_content = broken_content.replace(
                '"security.audit.read"',
                ''
            )
            (tmpdir_path / "internal" / "reviewauth" / "registry.go").write_text(broken_content)

        returncode, stdout, stderr = run_check(tmpdir_path)

        # Should fail
        if returncode == 0:
            print("FAIL: check should have failed when security.audit.read is missing")
            print(f"stdout: {stdout}")
            print(f"stderr: {stderr}")
            return False

        # Should name the specific missing permission
        if "security.audit.read" not in stderr:
            print("FAIL: error message should mention security.audit.read")
            print(f"stderr: {stderr}")
            return False

        print("PASS: test_detects_missing_permission")
        return True


def test_detects_stale_permission():
    """Test that the check fails when resourcePermissions contains a fake/unused permission."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        # Copy the structure needed by the check
        (tmpdir_path / "configs" / "review-console").mkdir(parents=True)
        (tmpdir_path / "internal" / "reviewconsoleapi").mkdir(parents=True)
        (tmpdir_path / "internal" / "reviewauth").mkdir(parents=True)

        # Copy identity registry
        registry_config = ROOT / "configs" / "review-console" / "identity-registry-r1.json"
        if registry_config.exists():
            (tmpdir_path / "configs" / "review-console" / "identity-registry-r1.json").write_text(
                registry_config.read_text()
            )

        # Copy server.go
        server_file = ROOT / "internal" / "reviewconsoleapi" / "server.go"
        if server_file.exists():
            (tmpdir_path / "internal" / "reviewconsoleapi" / "server.go").write_text(
                server_file.read_text()
            )

        # Create a registry.go with a fake permission added to resourcePermissions
        registry_template = ROOT / "internal" / "reviewauth" / "registry.go"
        if registry_template.exists():
            content = registry_template.read_text()
            # Add a fake permission entry
            broken_content = content.replace(
                '"evidence":   {"evidence.request", "evidence.submit"},',
                '"evidence":   {"evidence.request", "evidence.submit"},\n\t"fake_resource": {"fake.permission"},'
            )
            (tmpdir_path / "internal" / "reviewauth" / "registry.go").write_text(broken_content)

        returncode, stdout, stderr = run_check(tmpdir_path)

        # Should fail
        if returncode == 0:
            print("FAIL: check should have failed when fake permission is present")
            print(f"stdout: {stdout}")
            print(f"stderr: {stderr}")
            return False

        # Should name the specific fake permission
        if "fake.permission" not in stderr:
            print("FAIL: error message should mention fake.permission")
            print(f"stderr: {stderr}")
            return False

        print("PASS: test_detects_stale_permission")
        return True


def main(argv: list[str]) -> int:
    """Run all negative tests."""
    results = [
        test_detects_missing_permission(),
        test_detects_stale_permission(),
    ]

    if all(results):
        print("\nAll negative tests passed")
        return 0
    else:
        print("\nSome negative tests failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
