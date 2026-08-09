// See cmd/platform-api/main_test.go for the black-box subprocess pattern,
// and cmd/case-assistance-api/main_test.go for the config-assembly recipe
// this reuses. Uses the real committed
// test/fixtures/case-assistance/models/responses.json fixture (real
// model IDs like granite4.1:8b) as the model_fixture_path, rather than a
// hand-rolled placeholder.
//
// Scope: check, status, verify-audit, and models - all genuinely
// verified real happy paths, requiring no additional case-lifecycle
// setup. "assist"/"review"/"record" were investigated but require a
// case that actually EXISTS with at least one event in the alert-case
// store (confirmed via the actual errors: "invalid case_id" for a
// malformed ID - format-only, easy to satisfy - then "case verification
// failed: case has no events" once a correctly-formatted but
// non-existent case_id is used) - populating that requires chaining
// cmd/alert-case's create-case and case-event subcommands with their own
// request schemas, a third layer of chained tooling on top of what's
// already here. Left as a further integration test, not attempted in
// this pass. "migrate" needs a live PostgreSQL DSN, same reason it's
// skipped for cmd/alert-case and cmd/screening-ledger.
package main_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var (
	binaryPath  string
	repoRoot    string
	happyConfig string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "case-assistance-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "case-assistance")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/case-assistance for testing: " + err.Error() + "\n" + string(out))
	}

	root, err := filepath.Abs("../..")
	if err != nil {
		panic(err)
	}
	repoRoot = root

	config := map[string]any{
		"listen_address":             "127.0.0.1:0",
		"assistance_state_directory": filepath.Join(dir, "assistance-state"),
		"alert_case_state_directory": filepath.Join(dir, "alert-case-state"),
		"alert_policy_path":          filepath.Join(repoRoot, "test/fixtures/alert-case/policy.json"),
		"corpus_snapshot_path":       filepath.Join(repoRoot, "test/fixtures/case-assistance/corpus/snapshot.json"),
		"model_mode":                 "fixture",
		"model_fixture_path":         filepath.Join(repoRoot, "test/fixtures/case-assistance/models/responses.json"),
		"ollama_required":            false,
		"models": map[string]any{
			"primary_model_id":   "granite4.1:8b",
			"reasoning_model_id": "qwen3:14b",
			"guardian_model_id":  "granite4.1-guardian:8b",
			"context_tokens":     4096,
			"keep_alive":         "5m",
			"max_output_bytes":   8192,
		},
		"postgres_required": false,
		"max_body_bytes":    1048576,
		"timeout_seconds":   30,
	}
	configBytes, _ := json.Marshal(config)
	happyConfig = filepath.Join(dir, "config.json")
	if err := os.WriteFile(happyConfig, configBytes, 0o644); err != nil {
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
	panic("case-assistance did not run at all (not just a nonzero exit): " + err.Error())
}

func TestHappyPath_Check(t *testing.T) {
	stdout, stderr, code := run("check", "-config", happyConfig)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"status":"ok"`)) {
		t.Fatalf("expected status ok, got: %s", stdout)
	}
}

func TestHappyPath_Status(t *testing.T) {
	stdout, stderr, code := run("status", "-config", happyConfig)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"status":"ok"`)) {
		t.Fatalf("expected status ok, got: %s", stdout)
	}
}

func TestHappyPath_VerifyAudit(t *testing.T) {
	stdout, stderr, code := run("verify-audit", "-config", happyConfig)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"status":"ok"`)) {
		t.Fatalf("expected status ok, got: %s", stdout)
	}
}

func TestHappyPath_Models(t *testing.T) {
	stdout, stderr, code := run("models", "-config", happyConfig)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"granite4.1:8b"`)) {
		t.Fatalf("expected the fixture's real model IDs listed, got: %s", stdout)
	}
}

func TestNoArgsFailsWithUsageMessage(t *testing.T) {
	_, stderr, code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: case-assistance")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnknownCommandFailsCleanly(t *testing.T) {
	_, stderr, code := run("bogus-command", "-config", happyConfig)
	if code != 1 {
		t.Fatalf("expected exit code 1 for an unknown command, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte(`unknown command "bogus-command"`)) {
		t.Fatalf("expected an 'unknown command' message, got %q", stderr)
	}
}

func TestMissingConfigFileFailsCleanly(t *testing.T) {
	_, stderr, code := run("check", "-config", "/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing config file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing config file: %s", stderr)
	}
}
