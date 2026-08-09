// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// Every subcommand's flags already default to real committed
// configs/fixtures (configs/evaluation/phase10-release-gates-r1.json,
// test/fixtures/release-qualification/suite.json) - no data invented
// here. Confirmed the real suite genuinely qualifies against the real
// gate set (status: "qualified", exit 0) before writing the happy-path
// assertion - a "not qualified" (exit 2) case is not covered, since that
// would need either a stricter gate config or a worse suite that doesn't
// currently exist as a committed fixture.
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
	dir, err := os.MkdirTemp("", "release-qualification-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "release-qualification")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/release-qualification for testing: " + err.Error() + "\n" + string(out))
	}

	os.Exit(m.Run())
}

func run(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = "../.." // repo root, so default gate/suite paths resolve
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
	panic("release-qualification did not run at all (not just a nonzero exit): " + err.Error())
}

func TestHappyPath_EvaluateThenVerify(t *testing.T) {
	report := filepath.Join(t.TempDir(), "report.json")
	stdout, stderr, code := run("evaluate", "-output", report)
	if code != 0 {
		t.Fatalf("evaluate: expected exit code 0 (the real fixture suite genuinely qualifies), got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"status":"qualified"`)) {
		t.Fatalf("expected status qualified, got: %s", stdout)
	}

	stdout, stderr, code = run("verify", "-report", report)
	if code != 0 {
		t.Fatalf("verify: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"status":"ok"`)) {
		t.Fatalf("expected status ok, got: %s", stdout)
	}
}

func TestHappyPath_CheckGates(t *testing.T) {
	stdout, stderr, code := run("check-gates")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"gate_count":19`)) {
		t.Fatalf("expected gate_count 19, got: %s", stdout)
	}
}

func TestNoArgsFailsWithUsageMessage(t *testing.T) {
	_, stderr, code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: release-qualification")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnknownCommandFailsCleanly(t *testing.T) {
	_, stderr, code := run("bogus-command")
	if code != 1 {
		t.Fatalf("expected exit code 1 for an unknown command, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("unknown command")) {
		t.Fatalf("expected an 'unknown command' message, got %q", stderr)
	}
}

func TestVerifyMissingReportFlagFailsCleanly(t *testing.T) {
	_, stderr, code := run("verify")
	if code != 1 {
		t.Fatalf("expected exit code 1 when --report is missing, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("--report required")) {
		t.Fatalf("expected a '--report required' message, got %q", stderr)
	}
}

func TestEvaluateMissingGatesFileFailsCleanly(t *testing.T) {
	_, stderr, code := run("evaluate", "-gates", "/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing gates file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing gates file: %s", stderr)
	}
}
