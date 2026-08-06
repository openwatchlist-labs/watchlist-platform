// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// No Rust dependency. Like cmd/false-positive-classify, every error path
// here exits with code 1 - no separate usage-specific exit code (main()
// just os.Exit(1)s on any error from run()). Three subcommands all get
// real happy-path coverage using existing committed fixtures
// (test/fixtures/candidate-scoring/, configs/scoring/candidate-scoring-r1.json)
// rather than hand-constructed input.
package main_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "candidate-score-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "candidate-score")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/candidate-score for testing: " + err.Error() + "\n" + string(out))
	}

	os.Exit(m.Run())
}

func run(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = "../.." // repo root, so relative fixture/config paths resolve
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
	panic("candidate-score did not run at all (not just a nonzero exit): " + err.Error())
}

const policyPath = "configs/scoring/candidate-scoring-r1.json"

func TestHappyPath_CheckPolicy(t *testing.T) {
	stdout, stderr, code := run("check-policy", "-policy", policyPath)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	var output struct {
		PolicyID string `json:"policy_id"`
	}
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("output was not valid JSON: %v\noutput: %s", err, stdout)
	}
	if output.PolicyID != "candidate-scoring-r1" {
		t.Fatalf("expected policy_id \"candidate-scoring-r1\", got %q", output.PolicyID)
	}
}

func TestHappyPath_Score(t *testing.T) {
	stdout, stderr, code := run("score",
		"-policy", policyPath,
		"-input", "test/fixtures/candidate-scoring/realtime.request.json")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"request_id": "screening-fixture-name-001"`)) {
		t.Fatalf("expected the fixture's request_id echoed in output, got: %s", stdout)
	}
}

func TestHappyPath_Batch(t *testing.T) {
	stdout, stderr, code := run("batch",
		"-policy", policyPath,
		"-input", "test/fixtures/candidate-scoring/batch.request.json")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"batch_id": "batch-fixture-001"`)) {
		t.Fatalf("expected the fixture's batch_id echoed in output, got: %s", stdout)
	}
}

func TestDobContradictionFixture(t *testing.T) {
	// A specifically interesting fixture (contradicting date-of-birth
	// evidence) - worth its own case since it's the kind of scenario most
	// likely to reveal a scoring regression, not just a generic smoke test.
	stdout, stderr, code := run("score",
		"-policy", policyPath,
		"-input", "test/fixtures/candidate-scoring/dob-contradiction.request.json")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if stdout == "" {
		t.Fatal("expected non-empty output")
	}
}

func TestNoArgsFailsWithUsageMessage(t *testing.T) {
	_, stderr, code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1 with no args (this binary uses exit 1 for usage errors too, not exit 2), got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: candidate-score")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestMissingPolicyFlagFailsCleanly(t *testing.T) {
	_, stderr, code := run("score", "-input", "test/fixtures/candidate-scoring/realtime.request.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 when --policy is missing, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("--policy is required")) {
		t.Fatalf("expected a '--policy is required' message, got %q", stderr)
	}
}

func TestMissingPolicyFileFailsCleanly(t *testing.T) {
	_, stderr, code := run("score", "-policy", "/definitely/does/not/exist.json",
		"-input", "test/fixtures/candidate-scoring/realtime.request.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing policy file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing policy file: %s", stderr)
	}
}

func TestUnknownCommandFailsCleanly(t *testing.T) {
	_, stderr, code := run("bogus-command", "-policy", policyPath)
	if code != 1 {
		t.Fatalf("expected exit code 1 for an unknown command, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte(`unknown command "bogus-command"`)) {
		t.Fatalf("expected an 'unknown command' message, got %q", stderr)
	}
}
