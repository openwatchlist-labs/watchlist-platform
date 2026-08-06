// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// No Rust dependency: cmd/ofac-runtime's compile/inspect subcommands are
// pure Go (internal/ofacruntime), unlike production cmd/screening-api.
// This file covers compile and inspect with a genuine happy path;
// readiness/activate/rollback (internal/catalogruntime) are not covered
// here - a reasonable next addition, not attempted in this pass.
package main_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ofac-runtime-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "ofac-runtime")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/ofac-runtime for testing: " + err.Error() + "\n" + string(out))
	}

	os.Exit(m.Run())
}

func run(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = "../.." // repo root, so relative fixture paths below resolve
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err == nil {
		return outBuf.String(), errBuf.String(), 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return outBuf.String(), errBuf.String(), exitErr.ExitCode()
	}
	panic("ofac-runtime did not run at all (not just a nonzero exit): " + err.Error())
}

func TestHappyPath_CompileThenInspect(t *testing.T) {
	tmpPkg := filepath.Join(t.TempDir(), "fresh.owpcat")

	stdout, stderr, code := run("-command", "compile",
		"-catalog", "test/golden/ofac/ofac-sdn-fixture.catalog.json",
		"-package", tmpPkg)
	if code != 0 {
		t.Fatalf("compile: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte("package_checksum")) {
		t.Fatalf("compile: expected package_checksum in output, got: %s", stdout)
	}
	if _, err := os.Stat(tmpPkg); err != nil {
		t.Fatalf("compile: expected output package file to exist at %s: %v", tmpPkg, err)
	}

	stdout, stderr, code = run("-command", "inspect", "-package", tmpPkg)
	if code != 0 {
		t.Fatalf("inspect: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte("compiled-catalog-package-manifest")) {
		t.Fatalf("inspect: expected a manifest in output, got: %s", stdout)
	}
}

func TestCompileMissingRequiredFlagsExitsWithCode2(t *testing.T) {
	_, stderr, code := run("-command", "compile")
	if code != 2 {
		t.Fatalf("expected exit code 2 when --catalog/--package are missing, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("requires --catalog and --package")) {
		t.Fatalf("expected a specific missing-flags message, got %q", stderr)
	}
}

func TestUnsupportedCommandExitsWithCode2(t *testing.T) {
	_, stderr, code := run("-command", "bogus-command")
	if code != 2 {
		t.Fatalf("expected exit code 2 for an unsupported --command, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("unsupported --command")) {
		t.Fatalf("expected an 'unsupported --command' message, got %q", stderr)
	}
}

func TestCompileMissingCatalogFailsCleanlyWithCode1(t *testing.T) {
	_, stderr, code := run("-command", "compile",
		"-catalog", "/definitely/does/not/exist.json",
		"-package", filepath.Join(t.TempDir(), "out.owpcat"))
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing catalog file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing catalog file: %s", stderr)
	}
}

func TestInspectMissingPackageFailsCleanlyWithCode1(t *testing.T) {
	_, stderr, code := run("-command", "inspect", "-package", "/definitely/does/not/exist.owpcat")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing package file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing package file: %s", stderr)
	}
}
