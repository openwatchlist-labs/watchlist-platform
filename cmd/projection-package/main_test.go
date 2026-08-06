// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// No Rust dependency: this compiles the intermediate JSON projection
// format only (internal/projectionpackage), not the Rust catalog-mmap
// binary itself (that's a separate step - see scripts/dev/verify-rust-mmap-compatibility.sh
// and issue #13). The happy path here reuses the same committed fixture
// pair independently verified during the #13 investigation
// (test/fixtures/projection-package/catalog-descriptor.json +
// canonical-input.json), and reproduces the exact same package_sha256
// (b652a63ff...) found then.
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
	dir, err := os.MkdirTemp("", "projection-package-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "projection-package")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/projection-package for testing: " + err.Error() + "\n" + string(out))
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
	panic("projection-package did not run at all (not just a nonzero exit): " + err.Error())
}

const knownPackageSHA256 = "b652a63ffd2c8ed73dd40e8fb3530670ad49798fb3140fe3de8ac02ec12f7167"

func TestHappyPath_CompileThenVerify(t *testing.T) {
	outputRoot := t.TempDir()

	stdout, stderr, code := run("compile",
		"-catalog-descriptor", "test/fixtures/projection-package/catalog-descriptor.json",
		"-input", "test/fixtures/projection-package/canonical-input.json",
		"-output-root", outputRoot)
	if code != 0 {
		t.Fatalf("compile: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(knownPackageSHA256)) {
		t.Fatalf("compile: expected the known package_sha256 %s in output, got: %s", knownPackageSHA256, stdout)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"status":"ok"`)) {
		t.Fatalf("compile: expected status ok, got: %s", stdout)
	}

	packageDir := filepath.Join(outputRoot, knownPackageSHA256)
	stdout, stderr, code = run("verify", "-package", packageDir)
	if code != 0 {
		t.Fatalf("verify: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(knownPackageSHA256)) {
		t.Fatalf("verify: expected the same package_sha256 in output, got: %s", stdout)
	}
}

func TestInspectIsAliasOfVerify(t *testing.T) {
	// main.go literally routes "inspect" to the same runVerify function as
	// "verify" - confirmed by reading the source, not assumed. This test
	// proves that alias actually holds for the compiled binary.
	outputRoot := t.TempDir()
	_, _, code := run("compile",
		"-catalog-descriptor", "test/fixtures/projection-package/catalog-descriptor.json",
		"-input", "test/fixtures/projection-package/canonical-input.json",
		"-output-root", outputRoot)
	if code != 0 {
		t.Fatalf("setup compile failed with code %d", code)
	}
	packageDir := filepath.Join(outputRoot, knownPackageSHA256)

	verifyOut, _, verifyCode := run("verify", "-package", packageDir)
	inspectOut, _, inspectCode := run("inspect", "-package", packageDir)
	if verifyCode != inspectCode {
		t.Fatalf("expected verify and inspect to behave identically, got codes %d vs %d", verifyCode, inspectCode)
	}
	if verifyOut != inspectOut {
		t.Fatalf("expected verify and inspect to produce identical output, got:\nverify:  %s\ninspect: %s", verifyOut, inspectOut)
	}
}

func TestNoArgsPrintsUsageAndExitsWithCode2(t *testing.T) {
	_, stderr, code := run()
	if code != 2 {
		t.Fatalf("expected exit code 2 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: projection-package")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnknownSubcommandExitsWithCode2(t *testing.T) {
	_, stderr, code := run("bogus-subcommand")
	if code != 2 {
		t.Fatalf("expected exit code 2 for an unknown subcommand, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: projection-package")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestCompileMissingDescriptorFailsCleanlyWithCode1(t *testing.T) {
	_, stderr, code := run("compile",
		"-catalog-descriptor", "/definitely/does/not/exist.json",
		"-input", "test/fixtures/projection-package/canonical-input.json",
		"-output-root", t.TempDir())
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing descriptor file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing descriptor file: %s", stderr)
	}
}

func TestVerifyMissingPackageFailsCleanlyWithCode1(t *testing.T) {
	_, stderr, code := run("verify", "-package", "/definitely/does/not/exist")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing package directory, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing package directory: %s", stderr)
	}
}
