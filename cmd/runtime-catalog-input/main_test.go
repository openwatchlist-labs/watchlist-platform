// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// Important finding: this tool only accepts catalogs originating from
// OFAC Advanced XML Version 3 ("official catalogs must originate from
// OFAC Advanced XML Version 3") - the direct-list catalog format used
// throughout most of this repo's other tests
// (test/golden/ofac/ofac-sdn-fixture.catalog.json) is correctly
// rejected. Discovered this by trying it first and reading the actual
// error, not assumed. Uses the real, already-compiled golden catalog
// from the Advanced XML pipeline instead
// (test/golden/ofac-advanced/ofac-sdn-catalog.json).
package main_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "runtime-catalog-input-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "runtime-catalog-input")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/runtime-catalog-input for testing: " + err.Error() + "\n" + string(out))
	}

	os.Exit(m.Run())
}

func run(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = "../.." // repo root, so relative fixture paths resolve
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
	panic("runtime-catalog-input did not run at all (not just a nonzero exit): " + err.Error())
}

const (
	advancedCatalog = "test/golden/ofac-advanced/ofac-sdn-catalog.json"
	directCatalog   = "test/golden/ofac/ofac-sdn-fixture.catalog.json"
	componentID     = "catalog_component_ed835720fdb2b3a505927488"
)

func TestHappyPath_ExportProducesFileAndSummary(t *testing.T) {
	out := filepath.Join(t.TempDir(), "catalog.owcin")
	stdout, stderr, code := run("-catalog", advancedCatalog, "-component-id", componentID, "-output", out)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version": "runtime-catalog-input/v1alpha1"`)) {
		t.Fatalf("expected a runtime-catalog-input summary, got: %s", stdout)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("expected the .owcin output file to exist: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty .owcin content")
	}
}

func TestHappyPath_OutputDirectoryIsCreatedIfMissing(t *testing.T) {
	// writeAtomic in main.go calls os.MkdirAll on the output's parent
	// directory - verified this from source, testing it actually holds.
	out := filepath.Join(t.TempDir(), "nested", "does", "not", "exist", "catalog.owcin")
	_, stderr, code := run("-catalog", advancedCatalog, "-component-id", componentID, "-output", out)
	if code != 0 {
		t.Fatalf("expected exit code 0 even with a nonexistent parent directory, got %d (stderr: %q)", code, stderr)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("expected the output file (and its parent dirs) to be created: %v", err)
	}
}

func TestDirectListCatalogIsRejected(t *testing.T) {
	// The specific finding noted at the top of this file: a catalog in
	// the OTHER (direct-list) schema is correctly rejected, not silently
	// accepted just because it's also a valid OFAC catalog JSON in
	// general terms.
	out := filepath.Join(t.TempDir(), "catalog.owcin")
	_, stderr, code := run("-catalog", directCatalog, "-component-id", componentID, "-output", out)
	if code != 1 {
		t.Fatalf("expected exit code 1 for a direct-list catalog, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("OFAC Advanced XML Version 3")) {
		t.Fatalf("expected an 'OFAC Advanced XML Version 3' rejection message, got %q", stderr)
	}
}

func TestMissingRequiredFlagsExitsWithCode2(t *testing.T) {
	_, stderr, code := run("-catalog", advancedCatalog)
	if code != 2 {
		t.Fatalf("expected exit code 2 when --component-id/--output are missing, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: runtime-catalog-input")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestMissingCatalogFileFailsCleanlyWithCode1(t *testing.T) {
	out := filepath.Join(t.TempDir(), "catalog.owcin")
	_, stderr, code := run("-catalog", "/definitely/does/not/exist.json", "-component-id", componentID, "-output", out)
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing catalog file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing catalog file: %s", stderr)
	}
}
