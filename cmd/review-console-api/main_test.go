// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// This package's config chain is at least as deep as platform-api's
// (RuntimeConfig -> QuotaRegistry -> reviewconsoleapi in that case), but
// unlike platform-api, a full working config WAS successfully assembled
// here - reusing several existing fixtures (test/fixtures/alert-case/policy.json,
// test/fixtures/case-assistance/corpus/snapshot.json,
// test/fixtures/review-console/signing-key.hex) plus one piece built
// programmatically in TestMain: a valid reviewauth.Registry with a
// correctly computed RegistrySHA256 (using the package's own exported
// HashObject function, the same approach internal/reviewauth's own tests
// use - not guessed at). model_mode "fixture" avoids needing a live
// Ollama instance.
//
// This directly closes the internal/reviewconsoleapi zero-test gap noted
// in issue #15's original text, via this package's only entrypoint.
package main_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewauth"
)

var (
	binaryPath  string
	repoRoot    string
	happyConfig string // path to a fully working config, built once in TestMain
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "review-console-api-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "review-console-api")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/review-console-api for testing: " + err.Error() + "\n" + string(out))
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

// buildHappyConfig assembles a full, working config chain in a scratch
// directory: a valid identity registry (built programmatically using
// reviewauth's own exported HashObject, so the checksum is always
// correct even if the struct shape changes later), a minimal fixture
// model-client response file, and state directories - then reuses
// existing committed fixtures for the alert policy, corpus snapshot, and
// signing key rather than inventing those too.
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
	panic("review-console-api did not run at all (not just a nonzero exit): " + err.Error())
}

func TestHappyPath_Check(t *testing.T) {
	stdout, stderr, code := run("check", "--config", happyConfig)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q, stdout: %q)", code, stderr, stdout)
	}
	var out struct {
		Status         string `json:"status"`
		ConsoleEnabled bool   `json:"console_enabled"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("output was not valid JSON: %v\noutput: %s", err, stdout)
	}
	if out.Status != "ok" || !out.ConsoleEnabled {
		t.Fatalf("unexpected output: %s", stdout)
	}
}

func TestNoArgsFailsWithUsageMessage(t *testing.T) {
	_, stderr, code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: review-console-api")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnknownCommandFailsCleanly(t *testing.T) {
	_, stderr, code := run("bogus-command", "--config", happyConfig)
	if code != 1 {
		t.Fatalf("expected exit code 1 for an unknown command, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("unknown command")) {
		t.Fatalf("expected an 'unknown command' message, got %q", stderr)
	}
}

func TestMissingConfigFileFailsCleanly(t *testing.T) {
	_, stderr, code := run("check", "--config", "/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing config file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing config file: %s", stderr)
	}
}

func TestBadRegistryChecksumFailsCleanly(t *testing.T) {
	// Tampers with a copy of the working config's registry to have a
	// wrong checksum, proving the checksum validation this whole config
	// chain depends on actually fires - not just that a well-formed
	// config happens to work.
	dir := t.TempDir()
	registry := reviewauth.Registry{
		SchemaVersion: reviewauth.RegistrySchemaV1,
		RegistryID:    "bad",
		Version:       "r1",
		Roles: []reviewauth.Role{
			{RoleID: "analyst", Permissions: []string{"case.read"}},
		},
		Users: []reviewauth.User{
			{UserID: "test-analyst", DisplayName: "Test Analyst", Active: true, SessionEpoch: 1,
				Bindings: []reviewauth.RoleBinding{{TenantID: "tenant-a", Roles: []string{"analyst"}}}},
		},
		// Deliberately correct in every field except the checksum itself -
		// otherwise this test would fail for the wrong reason (missing
		// fields) rather than proving the checksum check specifically
		// fires. Caught this exact mistake on the first version of this
		// test: an earlier, structurally-incomplete "bad" registry failed
		// with "roles and users are required" before ever reaching the
		// checksum comparison.
		RegistrySHA256: "0000000000000000000000000000000000000000000000000000000000000000",
	}
	registryBytes, _ := json.Marshal(registry)
	badRegistryPath := filepath.Join(dir, "bad-registry.json")
	if err := os.WriteFile(badRegistryPath, registryBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	configBytes, err := os.ReadFile(happyConfig)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(configBytes, &config); err != nil {
		t.Fatal(err)
	}
	config["auth_registry_path"] = badRegistryPath
	badConfigBytes, _ := json.Marshal(config)
	badConfigPath := filepath.Join(dir, "bad-config.json")
	if err := os.WriteFile(badConfigPath, badConfigBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := run("check", "--config", badConfigPath)
	if code != 1 {
		t.Fatalf("expected exit code 1 for a registry with an invalid checksum, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("checksum")) {
		t.Fatalf("expected a checksum-related error message, got %q", stderr)
	}
}
