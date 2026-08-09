// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// No Rust dependency. Unlike every other cmd/ package tested so far,
// this one is STATEFUL - most subcommands operate against a --state-dir
// that persists alerts/cases/audit events across invocations (a
// nonexistent --state-dir is auto-created, verified by running the
// binary directly before writing tests, not assumed). Each test that
// needs state uses t.TempDir() for isolation, matching the pattern
// already used for compiled-output paths in cmd/ofac-runtime and
// cmd/projection-package's tests.
//
// Scope: "migrate" is not covered - it requires a live PostgreSQL DSN and
// a psql executable, meaningfully heavier infrastructure than anything
// else tested in this batch. A fixture for it exists
// (test/fixtures/alert-case/fake-psql.sh), suggesting a path to testing
// it later, but it wasn't pursued here to keep this batch's scope
// consistent with everything else covered so far (real, but not
// requiring new infrastructure setup).
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
	dir, err := os.MkdirTemp("", "alert-case-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "alert-case")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/alert-case for testing: " + err.Error() + "\n" + string(out))
	}

	os.Exit(m.Run())
}

func run(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = "../.." // repo root, so relative fixture/policy paths resolve
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
	panic("alert-case did not run at all (not just a nonzero exit): " + err.Error())
}

const policyPath = "test/fixtures/alert-case/policy.json"
const createAlertInput = "test/fixtures/alert-case/create-alert.request.json"

func TestHappyPath_CheckPolicy(t *testing.T) {
	stdout, stderr, code := run("check-policy", "-policy", policyPath)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	var out struct {
		PolicyID string `json:"policy_id"`
		Status   string `json:"status"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("output was not valid JSON: %v\noutput: %s", err, stdout)
	}
	if out.PolicyID != "phase9ab-alert-policy" || out.Status != "ok" {
		t.Fatalf("unexpected output: %s", stdout)
	}
}

// TestHappyPath_FullStatefulWorkflow exercises create-alert, replay
// (same input twice), alert, status, verify-alert, and verify-audit
// against a single shared temp state directory - proving the persistent
// store actually works end to end, not just that each subcommand runs in
// isolation.
func TestHappyPath_FullStatefulWorkflow(t *testing.T) {
	stateDir := t.TempDir()

	stdout, stderr, code := run("create-alert", "-state-dir", stateDir, "-policy", policyPath, "-input", createAlertInput)
	if code != 0 {
		t.Fatalf("create-alert: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	var created struct {
		Alert struct {
			AlertID string `json:"alert_id"`
		} `json:"alert"`
		Replayed bool `json:"replayed"`
	}
	if err := json.Unmarshal([]byte(stdout), &created); err != nil {
		t.Fatalf("create-alert output was not valid JSON: %v\noutput: %s", err, stdout)
	}
	if created.Replayed {
		t.Fatal("expected replayed=false on first creation")
	}
	if created.Alert.AlertID == "" {
		t.Fatal("expected a non-empty alert_id")
	}
	alertID := created.Alert.AlertID

	stdout, stderr, code = run("create-alert", "-state-dir", stateDir, "-policy", policyPath, "-input", createAlertInput)
	if code != 0 {
		t.Fatalf("replay create-alert: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	var replayed struct {
		Replayed bool `json:"replayed"`
	}
	_ = json.Unmarshal([]byte(stdout), &replayed)
	if !replayed.Replayed {
		t.Fatalf("expected replayed=true when the same input is submitted again with the same state dir, got: %s", stdout)
	}

	_, stderr, code = run("alert", "-state-dir", stateDir, "-policy", policyPath, "-id", alertID)
	if code != 0 {
		t.Fatalf("alert: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}

	stdout, stderr, code = run("status", "-state-dir", stateDir, "-policy", policyPath)
	if code != 0 {
		t.Fatalf("status: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	var status struct {
		AlertCount int `json:"alert_count"`
	}
	_ = json.Unmarshal([]byte(stdout), &status)
	if status.AlertCount != 1 {
		t.Fatalf("expected alert_count=1 after one (replayed) creation, got %d - output: %s", status.AlertCount, stdout)
	}

	_, stderr, code = run("verify-alert", "-state-dir", stateDir, "-policy", policyPath, "-id", alertID)
	if code != 0 {
		t.Fatalf("verify-alert: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}

	stdout, stderr, code = run("verify-audit", "-state-dir", stateDir, "-policy", policyPath)
	if code != 0 {
		t.Fatalf("verify-audit: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	var audit struct {
		AuditEventCount int `json:"audit_event_count"`
	}
	_ = json.Unmarshal([]byte(stdout), &audit)
	if audit.AuditEventCount == 0 {
		t.Fatalf("expected a nonzero audit_event_count, got 0 - output: %s", stdout)
	}
}

func TestNoArgsFailsWithUsageMessage(t *testing.T) {
	_, stderr, code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: alert-case")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnknownCommandFailsCleanly(t *testing.T) {
	_, stderr, code := run("bogus-command")
	if code != 1 {
		t.Fatalf("expected exit code 1 for an unknown command, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte(`unknown command "bogus-command"`)) {
		t.Fatalf("expected an 'unknown command' message, got %q", stderr)
	}
}

func TestMissingPolicyFileFailsCleanly(t *testing.T) {
	_, stderr, code := run("check-policy", "-policy", "/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing policy file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing policy file: %s", stderr)
	}
}

func TestMissingInputFlagFailsCleanly(t *testing.T) {
	_, stderr, code := run("create-alert", "-state-dir", t.TempDir(), "-policy", policyPath)
	if code != 1 {
		t.Fatalf("expected exit code 1 when --input is missing, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("--input is required")) {
		t.Fatalf("expected an '--input is required' message, got %q", stderr)
	}
}

func TestAlertNotFoundFailsCleanly(t *testing.T) {
	_, stderr, code := run("alert", "-state-dir", t.TempDir(), "-policy", policyPath, "-id", "alert_does_not_exist")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a nonexistent alert ID, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a nonexistent alert ID: %s", stderr)
	}
}
