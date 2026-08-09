// See cmd/platform-api/main_test.go for the black-box subprocess pattern,
// and cmd/review-console-api/main_test.go for the config-assembly
// approach this duplicates (each cmd/ package compiles as its own main,
// so test helpers aren't shared across packages - this is the same
// recipe, not a different one, kept in sync deliberately).
package main_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewauth"
)

var (
	binaryPath  string
	repoRoot    string
	happyConfig string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "review-console-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "review-console")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/review-console for testing: " + err.Error() + "\n" + string(out))
	}

	root, err := filepath.Abs("../..")
	if err != nil {
		panic(err)
	}
	repoRoot = root

	happyConfig, err = buildHappyConfig(dir)
	if err != nil {
		panic("failed to assemble a working config for testing: " + err.Error())
	}

	os.Exit(m.Run())
}

func buildHappyConfig(dir string) (string, error) {
	registry := reviewauth.Registry{
		SchemaVersion: reviewauth.RegistrySchemaV1,
		RegistryID:    "test-fixture-registry",
		Version:       "r1",
		Roles: []reviewauth.Role{
			{RoleID: "analyst", Permissions: []string{"case.read", "case.write"}},
		},
		Users: []reviewauth.User{
			{UserID: "test-analyst", DisplayName: "Test Analyst", Active: true, SessionEpoch: 1,
				Bindings: []reviewauth.RoleBinding{{TenantID: "tenant-a", Roles: []string{"analyst"}}}},
		},
	}
	sum, err := reviewauth.HashObject(registry)
	if err != nil {
		return "", err
	}
	registry.RegistrySHA256 = sum
	registryPath := filepath.Join(dir, "registry.json")
	registryBytes, _ := json.Marshal(registry)
	if err := os.WriteFile(registryPath, registryBytes, 0o644); err != nil {
		return "", err
	}

	modelFixturePath := filepath.Join(dir, "model-fixture.json")
	modelFixture := `{"models": ["test-model"], "responses": {"test-model": "This is a fixture response."}, "errors": {}}`
	if err := os.WriteFile(modelFixturePath, []byte(modelFixture), 0o644); err != nil {
		return "", err
	}

	config := map[string]any{
		"listen_address":             "127.0.0.1:0",
		"alert_case_state_directory": filepath.Join(dir, "alert-case-state"),
		"assistance_state_directory": filepath.Join(dir, "assistance-state"),
		"alert_policy_path":          filepath.Join(repoRoot, "test/fixtures/alert-case/policy.json"),
		"corpus_snapshot_path":       filepath.Join(repoRoot, "test/fixtures/case-assistance/corpus/snapshot.json"),
		"model_mode":                 "fixture",
		"model_fixture_path":         modelFixturePath,
		"ollama_required":            false,
		"models": map[string]any{
			"primary_model_id":   "test-model",
			"reasoning_model_id": "test-model",
			"guardian_model_id":  "test-model",
			"context_tokens":     4096,
			"keep_alive":         "5m",
			"max_output_bytes":   8192,
		},
		"auth_registry_path":       registryPath,
		"signing_key_path":         filepath.Join(repoRoot, "test/fixtures/review-console/signing-key.hex"),
		"security_audit_directory": filepath.Join(dir, "security-audit"),
		"security_audit_stream_id": "test-stream",
		"max_token_ttl_minutes":    60,
		"max_body_bytes":           1048576,
		"timeout_seconds":          30,
		"console_enabled":          true,
	}
	configPath := filepath.Join(dir, "config.json")
	configBytes, _ := json.MarshalIndent(config, "", "  ")
	if err := os.WriteFile(configPath, configBytes, 0o644); err != nil {
		return "", err
	}
	return configPath, nil
}

func run(stdin string, args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
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
	panic("review-console did not run at all (not just a nonzero exit): " + err.Error())
}

func TestHappyPath_Check(t *testing.T) {
	stdout, stderr, code := run("", "check", "--config", happyConfig)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"status":"ok"`)) {
		t.Fatalf("expected status ok, got: %s", stdout)
	}
}

func TestHappyPath_Registry(t *testing.T) {
	stdout, stderr, code := run("", "registry", "--config", happyConfig)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	var out struct {
		RoleCount int `json:"role_count"`
		UserCount int `json:"user_count"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("output was not valid JSON: %v\noutput: %s", err, stdout)
	}
	if out.RoleCount != 1 || out.UserCount != 1 {
		t.Fatalf("expected role_count=1 and user_count=1, got: %s", stdout)
	}
}

// TestHappyPath_IssueThenVerifyToken proves a real issued token actually
// verifies successfully - not just that both commands individually run
// without error.
func TestHappyPath_IssueThenVerifyToken(t *testing.T) {
	stdout, stderr, code := run("", "issue-token", "--config", happyConfig, "-user", "test-analyst", "-tenant", "tenant-a")
	if code != 0 {
		t.Fatalf("issue-token: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	var issued struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(stdout), &issued); err != nil {
		t.Fatalf("issue-token output was not valid JSON: %v\noutput: %s", err, stdout)
	}
	if issued.Token == "" {
		t.Fatal("expected a non-empty token")
	}

	stdout, stderr, code = run("", "verify-token", "--config", happyConfig, "-token", issued.Token)
	if code != 0 {
		t.Fatalf("verify-token: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	var verified struct {
		Status      string   `json:"status"`
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal([]byte(stdout), &verified); err != nil {
		t.Fatalf("verify-token output was not valid JSON: %v\noutput: %s", err, stdout)
	}
	if verified.Status != "ok" {
		t.Fatalf("expected status ok, got: %s", stdout)
	}
	if len(verified.Permissions) == 0 {
		t.Fatalf("expected nonempty permissions from the analyst role, got: %s", stdout)
	}
}

func TestVerifyTokenReadsFromStdinWhenFlagOmitted(t *testing.T) {
	stdout, stderr, code := run("", "issue-token", "--config", happyConfig, "-user", "test-analyst", "-tenant", "tenant-a")
	if code != 0 {
		t.Fatalf("issue-token: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	var issued struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal([]byte(stdout), &issued)

	// main.go's verify-token falls back to reading /dev/stdin when -token
	// is empty - verified this by reading the source before writing this
	// test, not assumed. Note: this relies on real stdin, not portable to
	// every environment, but this repo's own test binary runs on Linux
	// where /dev/stdin is standard.
	_, stderr, code = run(issued.Token+"\n", "verify-token", "--config", happyConfig)
	if code != 0 {
		t.Fatalf("expected exit code 0 when reading token from stdin, got %d (stderr: %q)", code, stderr)
	}
}

func TestHappyPath_VerifySecurityAudit(t *testing.T) {
	stdout, stderr, code := run("", "verify-security-audit", "--config", happyConfig)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"status":"ok"`)) {
		t.Fatalf("expected status ok, got: %s", stdout)
	}
}

func TestNoArgsFailsWithUsageMessage(t *testing.T) {
	_, stderr, code := run("")
	if code != 1 {
		t.Fatalf("expected exit code 1 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: review-console")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnknownCommandFailsCleanly(t *testing.T) {
	_, stderr, code := run("", "bogus-command", "--config", happyConfig)
	if code != 1 {
		t.Fatalf("expected exit code 1 for an unknown command, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("unknown command")) {
		t.Fatalf("expected an 'unknown command' message, got %q", stderr)
	}
}

func TestInvalidTokenFailsCleanly(t *testing.T) {
	_, stderr, code := run("", "verify-token", "--config", happyConfig, "-token", "not-a-real-token")
	if code != 1 {
		t.Fatalf("expected exit code 1 for an invalid token, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for an invalid token: %s", stderr)
	}
}

func TestMissingConfigFileFailsCleanly(t *testing.T) {
	_, stderr, code := run("", "check", "--config", "/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing config file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing config file: %s", stderr)
	}
}
