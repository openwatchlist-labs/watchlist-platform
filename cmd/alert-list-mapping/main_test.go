// See cmd/platform-api/main_test.go for the black-box subprocess pattern,
// and cmd/provider-refresh/main_test.go for the same "needs a
// catalog-registry store as prerequisite" pattern. This one goes further:
// a real full workflow (init -> register -> resolve -> verify) is built
// using the real committed mapping input fixture
// (test/fixtures/alert-list-mapping/fircosoft-ofac-official.mapping.json),
// chained on top of a freshly-built catalog-registry store using the same
// component/version fixtures already proven in
// cmd/catalog-registry/main_test.go.
package main_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var (
	binaryPath                string
	catalogRegistryBinaryPath string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "alert-list-mapping-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "alert-list-mapping")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/alert-list-mapping for testing: " + err.Error() + "\n" + string(out))
	}

	catalogRegistryBinaryPath = filepath.Join(dir, "catalog-registry")
	build = exec.Command("go", "build", "-o", catalogRegistryBinaryPath, "../catalog-registry")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/catalog-registry (test prerequisite) for testing: " + err.Error() + "\n" + string(out))
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
	panic("alert-list-mapping did not run at all (not just a nonzero exit): " + err.Error())
}

const (
	componentInput = "test/fixtures/catalog-registry/official-ofac-sdn.component.json"
	versionInput   = "test/fixtures/catalog-registry/official-ofac-sdn-v1.version.json"
	componentID    = "catalog_component_ed835720fdb2b3a505927488"
	versionID      = "catalog_version_10c16906983641525bcc85a4"
	mappingInput   = "test/fixtures/alert-list-mapping/fircosoft-ofac-official.mapping.json"
)

// freshActivatedCatalogRegistryStore builds a real catalog-registry store
// with one component registered, versioned, and activated - the same
// sequence independently proven in cmd/catalog-registry/main_test.go.
func freshActivatedCatalogRegistryStore(t *testing.T) string {
	t.Helper()
	store := t.TempDir()
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	steps := [][]string{
		{"init", "-store", store, "-namespace", "demo-bank"},
		{"register-component", "-store", store, "-input", componentInput},
		{"register-version", "-store", store, "-input", versionInput},
		{"activate", "-store", store, "-component-id", componentID, "-version-id", versionID, "-actor", "test-operator", "-reason", "init"},
	}
	for _, args := range steps {
		cmd := exec.Command(catalogRegistryBinaryPath, args...)
		cmd.Dir = repoRoot
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("prerequisite catalog-registry %v failed: %v\n%s", args, err, out)
		}
	}
	return store
}

func TestHappyPath_FullWorkflow(t *testing.T) {
	catalogStore := freshActivatedCatalogRegistryStore(t)
	mappingStore := t.TempDir()

	_, stderr, code := run("init", "-store", mappingStore, "-namespace", "demo-bank")
	if code != 0 {
		t.Fatalf("init: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}

	stdout, stderr, code := run("register", "-store", mappingStore, "-catalog-registry-store", catalogStore, "-input", mappingInput)
	if code != 0 {
		t.Fatalf("register: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"registered": true`)) {
		t.Fatalf("expected registered: true, got: %s", stdout)
	}

	stdout, stderr, code = run("resolve", "-store", mappingStore, "-catalog-registry-store", catalogStore,
		"-source-system-id", "fircosoft-prod", "-raw-list-name", "WLS_OFAC_001")
	if code != 0 {
		t.Fatalf("resolve: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version": "alert-list-resolution/v1alpha1"`)) {
		t.Fatalf("expected an alert-list-resolution result, got: %s", stdout)
	}

	stdout, stderr, code = run("verify", "-store", mappingStore, "-catalog-registry-store", catalogStore)
	if code != 0 {
		t.Fatalf("verify: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"valid": true`)) {
		t.Fatalf("expected valid: true, got: %s", stdout)
	}

	_, stderr, code = run("snapshot", "-store", mappingStore, "-catalog-registry-store", catalogStore)
	if code != 0 {
		t.Fatalf("snapshot: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
}

func TestHappyPath_PostgresSchema(t *testing.T) {
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
	if !bytes.Contains([]byte(stderr), []byte("usage: alert-list-mapping")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnsupportedSubcommandFailsCleanly(t *testing.T) {
	_, stderr, code := run("bogus-subcommand")
	if code != 1 {
		t.Fatalf("expected exit code 1 for an unsupported subcommand, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte(`unsupported subcommand "bogus-subcommand"`)) {
		t.Fatalf("expected an 'unsupported subcommand' message, got %q", stderr)
	}
}

func TestInitMissingRequiredFlagFailsCleanly(t *testing.T) {
	_, stderr, code := run("init")
	if code != 1 {
		t.Fatalf("expected exit code 1 when required flags are missing, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("--store is required")) {
		t.Fatalf("expected a '--store is required' message, got %q", stderr)
	}
}
