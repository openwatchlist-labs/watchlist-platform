// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// Scope: "init" (needs a catalog-registry store as its one prerequisite,
// built here the same way cmd/catalog-registry/main_test.go's happy path
// does) plus failure modes and postgres-schema. "analyze"/"decide"/
// "promote"/"rollback" need a THIRD subsystem (an alert-list-mapping
// store) chained in as well as specific analysis input JSON - a fuller
// multi-system integration test worth writing separately, not attempted
// here, consistent with skipping cmd/alert-case's "migrate" and
// cmd/vendor-adapter's "submit" for similar escalating-dependency
// reasons.
package main_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var binaryPath string
var catalogRegistryBinaryPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "provider-refresh-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "provider-refresh")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/provider-refresh for testing: " + err.Error() + "\n" + string(out))
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
	panic("provider-refresh did not run at all (not just a nonzero exit): " + err.Error())
}

func freshCatalogRegistryStore(t *testing.T) string {
	t.Helper()
	store := t.TempDir()
	cmd := exec.Command(catalogRegistryBinaryPath, "init", "-store", store, "-namespace", "demo-bank")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to initialize prerequisite catalog-registry store: %v\n%s", err, out)
	}
	return store
}

func TestHappyPath_Init(t *testing.T) {
	catalogStore := freshCatalogRegistryStore(t)
	stdout, stderr, code := run("init", "-store", t.TempDir(), "-catalog-registry-store", catalogStore, "-namespace", "demo-bank")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version": "provider-refresh-registry/v1alpha1"`)) {
		t.Fatalf("expected a provider-refresh-registry result, got: %s", stdout)
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
	if !bytes.Contains([]byte(stderr), []byte("usage: provider-refresh")) {
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

func TestInitMissingRequiredFlagFailsCleanly(t *testing.T) {
	_, stderr, code := run("init")
	if code != 1 {
		t.Fatalf("expected exit code 1 when required flags are missing, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("--store is required")) {
		t.Fatalf("expected a '--store is required' message, got %q", stderr)
	}
}

func TestInitWithMissingCatalogRegistryStoreFailsCleanly(t *testing.T) {
	_, stderr, code := run("init", "-store", t.TempDir(), "-catalog-registry-store", "/definitely/does/not/exist", "-namespace", "demo-bank")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing catalog-registry-store, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing catalog-registry-store: %s", stderr)
	}
}
