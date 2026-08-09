// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// Unlike cmd/platform-api or cmd/review-console-api, this service's
// config chain is shallow enough to assemble directly: it just needs a
// state directory, the real committed alert-case policy fixture
// (test/fixtures/alert-case/policy.json), and postgres_required: false
// to avoid needing a live PostgreSQL for "check" - verified this
// actually produces a real, working result before writing the happy-path
// assertion.
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
	dir, err := os.MkdirTemp("", "alert-case-api-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "alert-case-api")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/alert-case-api for testing: " + err.Error() + "\n" + string(out))
	}

	root, err := filepath.Abs("../..")
	if err != nil {
		panic(err)
	}
	repoRoot = root

	config := map[string]any{
		"listen_address":    "127.0.0.1:0",
		"state_directory":   filepath.Join(dir, "state"),
		"policy_path":       filepath.Join(repoRoot, "test/fixtures/alert-case/policy.json"),
		"stream_id":         "test-stream",
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
	panic("alert-case-api did not run at all (not just a nonzero exit): " + err.Error())
}

func TestHappyPath_Check(t *testing.T) {
	stdout, stderr, code := run("check", "-config", happyConfig)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	var out struct {
		Status           string `json:"status"`
		PostgresRequired bool   `json:"postgres_required"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("output was not valid JSON: %v\noutput: %s", err, stdout)
	}
	if out.Status != "ok" || out.PostgresRequired {
		t.Fatalf("unexpected output: %s", stdout)
	}
}

func TestNoArgsFailsWithUsageMessage(t *testing.T) {
	_, stderr, code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: alert-case-api")) {
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
