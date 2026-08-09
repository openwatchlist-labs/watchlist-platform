// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// Reuses the exact projection-package fixture pair independently
// verified during the #13 investigation (test/fixtures/projection-package/
// catalog-descriptor.json and its compiled b652a63f... package
// directory), plus the candidate-scoring policy already used for
// cmd/candidate-score's tests. Stateful, like cmd/alert-case: activate
// persists to --state-dir, and status/rollback read it back.
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
	dir, err := os.MkdirTemp("", "scoring-activation-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "scoring-activation")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/scoring-activation for testing: " + err.Error() + "\n" + string(out))
	}

	os.Exit(m.Run())
}

func run(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = "../.." // repo root, so relative fixture paths resolve
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
	panic("scoring-activation did not run at all (not just a nonzero exit): " + err.Error())
}

const (
	catalogDescriptor  = "test/fixtures/projection-package/catalog-descriptor.json"
	projectionPackage  = "test/fixtures/projection-package/packages/b652a63ffd2c8ed73dd40e8fb3530670ad49798fb3140fe3de8ac02ec12f7167"
	scoringPolicy      = "configs/scoring/candidate-scoring-r1.json"
	knownProjectionSHA = "b652a63ffd2c8ed73dd40e8fb3530670ad49798fb3140fe3de8ac02ec12f7167"
)

func TestHappyPath_ActivateThenStatus(t *testing.T) {
	stateDir := t.TempDir()

	stdout, stderr, code := run("activate", "-state-dir", stateDir, "-activation-id", "act-001",
		"-catalog-descriptor", catalogDescriptor, "-projection-package", projectionPackage, "-policy", scoringPolicy)
	if code != 0 {
		t.Fatalf("activate: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(knownProjectionSHA)) {
		t.Fatalf("expected the known projection_package_sha256 in output, got: %s", stdout)
	}

	stdout, stderr, code = run("status", "-state-dir", stateDir)
	if code != 0 {
		t.Fatalf("status: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"activation_id":"act-001"`)) {
		t.Fatalf("expected status to reflect the activated activation_id, got: %s", stdout)
	}
}

func TestNoArgsExitsWithCode2(t *testing.T) {
	_, stderr, code := run()
	if code != 2 {
		t.Fatalf("expected exit code 2 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: scoring-activation")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnknownCommandExitsWithCode2(t *testing.T) {
	_, stderr, code := run("bogus-command")
	if code != 2 {
		t.Fatalf("expected exit code 2 for an unknown command, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: scoring-activation")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestStatusWithNoActivationFailsCleanlyWithCode1(t *testing.T) {
	_, stderr, code := run("status", "-state-dir", t.TempDir())
	if code != 1 {
		t.Fatalf("expected exit code 1 when no activation has ever been performed, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error: %s", stderr)
	}
}

func TestActivateMissingDescriptorFailsCleanlyWithCode1(t *testing.T) {
	_, stderr, code := run("activate", "-state-dir", t.TempDir(), "-activation-id", "act-001",
		"-catalog-descriptor", "/definitely/does/not/exist.json", "-projection-package", projectionPackage, "-policy", scoringPolicy)
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing catalog descriptor, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing catalog descriptor: %s", stderr)
	}
}
