// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// The --config flag's default value already points at a real committed
// fixture (configs/vendor-adapters/phase9e-api-example.json), so "check"
// works with zero flags - verified this actually produces a real result
// (3 profiles, postgres_required: false) before writing the assertion.
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
	dir, err := os.MkdirTemp("", "vendor-adapter-api-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "vendor-adapter-api")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/vendor-adapter-api for testing: " + err.Error() + "\n" + string(out))
	}

	os.Exit(m.Run())
}

func run(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = "../.." // repo root, so the default --config path resolves
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
	panic("vendor-adapter-api did not run at all (not just a nonzero exit): " + err.Error())
}

func TestHappyPath_CheckWithDefaultConfig(t *testing.T) {
	stdout, stderr, code := run("check")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"status":"ok"`)) {
		t.Fatalf("expected status ok, got: %s", stdout)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"profile_count":3`)) {
		t.Fatalf("expected profile_count 3 from the default fixture config, got: %s", stdout)
	}
}

func TestNoArgsExitsWithCode2(t *testing.T) {
	_, stderr, code := run()
	if code != 2 {
		t.Fatalf("expected exit code 2 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("vendor-adapter-api check|serve")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnknownCommandExitsWithCode2(t *testing.T) {
	// Note: unlike its usage message above, the unknown-command path
	// prints NOTHING to stderr before exiting 2 - verified this by
	// running the binary directly, not assumed consistent with the
	// no-args case just because both exit with the same code.
	stdout, stderr, code := run("bogus-command")
	if code != 2 {
		t.Fatalf("expected exit code 2 for an unknown command, got %d (stdout: %q, stderr: %q)", code, stdout, stderr)
	}
}

func TestMissingConfigFileFailsCleanlyWithCode1(t *testing.T) {
	_, stderr, code := run("check", "-config", "/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing config file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing config file: %s", stderr)
	}
}
