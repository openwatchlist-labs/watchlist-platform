// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// Stateful, like cmd/alert-case: init -> register-component ->
// register-version -> activate -> snapshot/verify, each step persisting
// to a --store directory. Reuses the real committed component/version
// input fixtures (test/fixtures/catalog-registry/*.json) - their IDs are
// deterministically derived from their content (namespace + component
// key), which is why the version fixture's hardcoded component_id
// matches what registering the component fixture actually produces -
// confirmed by running the full chain manually before writing this file,
// not assumed to just line up.
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
	dir, err := os.MkdirTemp("", "catalog-registry-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "catalog-registry")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/catalog-registry for testing: " + err.Error() + "\n" + string(out))
	}

	os.Exit(m.Run())
}

func run(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = "../.." // repo root, so relative fixture input paths resolve
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
	panic("catalog-registry did not run at all (not just a nonzero exit): " + err.Error())
}

const (
	componentInput = "test/fixtures/catalog-registry/official-ofac-sdn.component.json"
	versionInput   = "test/fixtures/catalog-registry/official-ofac-sdn-v1.version.json"
	componentID    = "catalog_component_ed835720fdb2b3a505927488"
	versionID      = "catalog_version_10c16906983641525bcc85a4"
)

func TestHappyPath_FullWorkflow(t *testing.T) {
	store := t.TempDir()

	_, stderr, code := run("init", "-store", store, "-namespace", "demo-bank")
	if code != 0 {
		t.Fatalf("init: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}

	_, stderr, code = run("register-component", "-store", store, "-input", componentInput)
	if code != 0 {
		t.Fatalf("register-component: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}

	stdout, stderr, code := run("register-version", "-store", store, "-input", versionInput)
	if code != 0 {
		t.Fatalf("register-version: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(componentID)) {
		t.Fatalf("expected the registered version to reference the deterministic component ID, got: %s", stdout)
	}

	_, stderr, code = run("activate", "-store", store,
		"-component-id", componentID, "-version-id", versionID,
		"-actor", "test-operator", "-reason", "initial activation")
	if code != 0 {
		t.Fatalf("activate: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}

	stdout, stderr, code = run("verify", "-store", store)
	if code != 0 {
		t.Fatalf("verify: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	var v struct {
		Valid                bool `json:"valid"`
		ComponentCount       int  `json:"component_count"`
		VersionCount         int  `json:"version_count"`
		ActiveComponentCount int  `json:"active_component_count"`
	}
	if err := json.Unmarshal([]byte(stdout), &v); err != nil {
		t.Fatalf("verify output was not valid JSON: %v\noutput: %s", err, stdout)
	}
	if !v.Valid || v.ComponentCount != 1 || v.VersionCount != 1 || v.ActiveComponentCount != 1 {
		t.Fatalf("unexpected verify result after a full happy-path workflow: %s", stdout)
	}

	_, stderr, code = run("snapshot", "-store", store)
	if code != 0 {
		t.Fatalf("snapshot: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
}

func TestHappyPath_PostgresSchema(t *testing.T) {
	// Just emits a static SQL migration string - no store/state involved
	// at all, verified by reading main.go before testing.
	stdout, stderr, code := run("postgres-schema")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte("CREATE TABLE")) {
		t.Fatalf("expected SQL DDL output, got: %s", stdout)
	}
}

func TestNoArgsFailsWithUsageMessage(t *testing.T) {
	_, stderr, code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: catalog-registry")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnknownSubcommandFailsCleanly(t *testing.T) {
	_, stderr, code := run("bogus-subcommand")
	if code != 1 {
		t.Fatalf("expected exit code 1 for an unsupported subcommand, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte(`unsupported subcommand "bogus-subcommand"`)) {
		t.Fatalf("expected an 'unsupported subcommand' message, got %q", stderr)
	}
}

func TestRegisterVersionForUnregisteredComponentFailsCleanly(t *testing.T) {
	store := t.TempDir()
	_, _, code := run("init", "-store", store, "-namespace", "demo-bank")
	if code != 0 {
		t.Fatalf("init setup failed with code %d", code)
	}
	_, stderr, code := run("register-version", "-store", store, "-input", versionInput)
	if code != 1 {
		t.Fatalf("expected exit code 1 when registering a version for an unregistered component, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("is not registered")) {
		t.Fatalf("expected an 'is not registered' message, got %q", stderr)
	}
}
