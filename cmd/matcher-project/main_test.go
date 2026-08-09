// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// This binary needs a screening.EvidenceBundle as input - generated here
// by actually running cmd/iso20022-inspect -output evidence against its
// own known-working pacs.008 fixture (see
// cmd/iso20022-inspect/main_test.go), rather than hand-authoring an
// evidence bundle that might not match the current schema.
package main_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var (
	binaryPath         string
	evidenceBundlePath string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "matcher-project-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "matcher-project")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/matcher-project for testing: " + err.Error() + "\n" + string(out))
	}

	inspectBinPath := filepath.Join(dir, "iso20022-inspect")
	build = exec.Command("go", "build", "-o", inspectBinPath, "../iso20022-inspect")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/iso20022-inspect (test prerequisite) for testing: " + err.Error() + "\n" + string(out))
	}

	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		panic(err)
	}
	inspectCmd := exec.Command(inspectBinPath, "-output", "evidence", "test/fixtures/iso20022/pacs008/pacs008-basic.xml")
	inspectCmd.Dir = repoRoot
	out, err := inspectCmd.Output()
	if err != nil {
		panic("failed to generate prerequisite evidence bundle via iso20022-inspect: " + err.Error())
	}
	evidenceBundlePath = filepath.Join(dir, "evidence-bundle.json")
	if err := os.WriteFile(evidenceBundlePath, out, 0o644); err != nil {
		panic(err)
	}

	os.Exit(m.Run())
}

func run(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
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
	panic("matcher-project did not run at all (not just a nonzero exit): " + err.Error())
}

func TestHappyPath_RequestsOutput(t *testing.T) {
	stdout, stderr, code := run(evidenceBundlePath)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version": "candidate-search-request-batch/v1alpha1"`)) {
		t.Fatalf("expected a candidate-search-request-batch result (the default output), got: %s", stdout)
	}
}

func TestHappyPath_ReplayOutput(t *testing.T) {
	stdout, stderr, code := run("-output", "replay", evidenceBundlePath)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version": "matcher-replay-envelope/v1alpha1"`)) {
		t.Fatalf("expected a matcher-replay-envelope result, got: %s", stdout)
	}
}

func TestNoArgsExitsWithCode2(t *testing.T) {
	_, stderr, code := run()
	if code != 2 {
		t.Fatalf("expected exit code 2 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: matcher-project")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnsupportedOutputExitsWithCode2(t *testing.T) {
	_, stderr, code := run("-output", "bogus", evidenceBundlePath)
	if code != 2 {
		t.Fatalf("expected exit code 2 for an unsupported --output value, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("unsupported --output")) {
		t.Fatalf("expected an 'unsupported --output' message, got %q", stderr)
	}
}

func TestMissingInputFileFailsCleanlyWithCode1(t *testing.T) {
	_, stderr, code := run("/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing input file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing input file: %s", stderr)
	}
}

func TestMultipleJSONValuesFailsCleanly(t *testing.T) {
	// main.go explicitly rejects trailing JSON after the first value -
	// verified from source, testing that behavior actually holds.
	path := filepath.Join(t.TempDir(), "double.json")
	data, err := os.ReadFile(evidenceBundlePath)
	if err != nil {
		t.Fatal(err)
	}
	doubled := append(append([]byte{}, data...), data...)
	if err := os.WriteFile(path, doubled, 0o644); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := run(path)
	if code != 1 {
		t.Fatalf("expected exit code 1 for multiple JSON values in one file, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("multiple JSON values are not allowed")) {
		t.Fatalf("expected a 'multiple JSON values are not allowed' message, got %q", stderr)
	}
}
