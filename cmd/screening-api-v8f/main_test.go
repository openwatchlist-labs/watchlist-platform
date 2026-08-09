// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// Scope: failure modes only. This is the canary/shadow variant - its
// Config needs BOTH an activation_state_directory AND a
// promotion_state_directory (screeningapiv8f.NewServer requires a real
// promotion.json to exist, confirmed via the actual "load promotion
// status: open .../promotion.json: no such file or directory" error, not
// assumed), plus TWO upstream URLs (current/candidate) whose responses
// likely need to cross-reference matching activation/promotion lineage
// IDs the same way cmd/screening-api-v8e's upstream fixture did (see
// that file's comment for the exact "active_catalog_lineage_mismatch"
// discovery). Building a fully consistent activation + promotion + dual
// upstream chain is a bigger integration-test effort than this batch's
// black-box approach was scoped to build - left for later, not silently
// skipped.
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
	dir, err := os.MkdirTemp("", "screening-api-v8f-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "screening-api-v8f")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/screening-api-v8f for testing: " + err.Error() + "\n" + string(out))
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
	panic("screening-api-v8f did not run at all (not just a nonzero exit): " + err.Error())
}

func TestNoArgsExitsWithCode2(t *testing.T) {
	_, stderr, code := run()
	if code != 2 {
		t.Fatalf("expected exit code 2 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: screening-api-v8f")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnknownCommandExitsWithCode2(t *testing.T) {
	_, stderr, code := run("bogus-command")
	if code != 2 {
		t.Fatalf("expected exit code 2 for an unknown command, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: screening-api-v8f")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestCheckMissingConfigFlagFailsCleanlyWithCode1(t *testing.T) {
	// Exit 1, not 2: "--config is required" is an application-level check
	// (loadConfig's own `if *path == ""`), not a flag-parse error - only
	// genuine parse failures and the top-level usage/unknown-command
	// checks use exit 2. Corrected this assertion after running the
	// binary and seeing the real exit code, not assumed consistent with
	// the no-args/unknown-command cases above.
	_, stderr, code := run("check")
	if code != 1 {
		t.Fatalf("expected exit code 1 when --config is missing, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("--config is required")) {
		t.Fatalf("expected a '--config is required' message, got %q", stderr)
	}
}

func TestCheckMissingConfigFileFailsCleanlyWithCode1(t *testing.T) {
	_, stderr, code := run("check", "-config", "/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing config file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing config file: %s", stderr)
	}
}

func TestCheckWithoutPromotionStateFailsCleanlyWithCode1(t *testing.T) {
	// The specific finding noted at the top of this file, verified
	// directly rather than assumed: a syntactically valid config with
	// fresh, never-activated/never-promoted state directories fails
	// cleanly (not a panic) once NewServer tries to load promotion
	// state that doesn't exist yet.
	config := map[string]any{
		"listen_address":             "127.0.0.1:0",
		"current_base_url":           "http://127.0.0.1:1",
		"candidate_base_url":         "http://127.0.0.1:1",
		"activation_state_directory": t.TempDir(),
		"promotion_state_directory":  t.TempDir(),
		"idempotency_directory":      t.TempDir(),
		"instance_id":                "test-instance",
		"max_body_bytes":             1048576,
		"request_timeout_millis":     5000,
	}
	configPath := filepath.Join(t.TempDir(), "config.json")
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := run("check", "-config", configPath)
	if code != 1 {
		t.Fatalf("expected exit code 1 for a fresh, never-promoted state, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for missing promotion state: %s", stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("promotion")) {
		t.Fatalf("expected a promotion-related error message, got %q", stderr)
	}
}
