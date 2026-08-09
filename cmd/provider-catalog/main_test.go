// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// Important: internal/providerentity's catalog schema is NOT the same as
// matcherprovider's exact-match FixtureCatalog schema (see issue #12) -
// synthetic-catalog-v1.json (used elsewhere in this repo for
// ExactMatchFixtureProvider) has a "provider_id" field this package's
// LoadCatalog rejects as unrecognized. Discovered this by actually
// running "validate" against it before writing tests, not assumed
// compatible just because both are called "provider" catalogs. Tests
// here instead chain: "project" builds a valid provider-entity catalog
// from a real OpenSanctions-like snapshot fixture, and that output feeds
// validate/compare/hybrid.
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
	dir, err := os.MkdirTemp("", "provider-catalog-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "provider-catalog")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/provider-catalog for testing: " + err.Error() + "\n" + string(out))
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
	panic("provider-catalog did not run at all (not just a nonzero exit): " + err.Error())
}

const (
	snapshotFixture = "test/fixtures/provider-entity/opensanctions-like-snapshot.json"
	directFixture   = "test/golden/ofac/ofac-sdn-fixture.catalog.json"
)

func projectFixtureCatalog(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "provider-catalog.json")
	_, stderr, code := run("project", "-snapshot", snapshotFixture, "-output", out)
	if code != 0 {
		t.Fatalf("setup 'project' failed: exit %d (stderr: %q)", code, stderr)
	}
	return out
}

func TestHappyPath_Project(t *testing.T) {
	stdout, stderr, code := run("project", "-snapshot", snapshotFixture)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version": "provider-entity-catalog/v1alpha1"`)) {
		t.Fatalf("expected a provider-entity catalog, got: %s", stdout)
	}
}

func TestHappyPath_Validate(t *testing.T) {
	providerCatalog := projectFixtureCatalog(t)
	stdout, stderr, code := run("validate", "-catalog", providerCatalog)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"valid": true`)) {
		t.Fatalf("expected valid: true, got: %s", stdout)
	}
}

func TestHappyPath_Compare(t *testing.T) {
	providerCatalog := projectFixtureCatalog(t)
	stdout, stderr, code := run("compare", "-provider", providerCatalog, "-direct", directFixture)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version": "catalog-comparison/v1alpha1"`)) {
		t.Fatalf("expected a catalog-comparison result, got: %s", stdout)
	}
}

func TestHappyPath_Hybrid(t *testing.T) {
	providerCatalog := projectFixtureCatalog(t)
	stdout, stderr, code := run("hybrid", "-provider", providerCatalog, "-direct", directFixture)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version": "hybrid-overlay-catalog/v1alpha1"`)) {
		t.Fatalf("expected a hybrid-overlay-catalog result, got: %s", stdout)
	}
}

func TestNoArgsFailsWithUsageMessage(t *testing.T) {
	_, stderr, code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: provider-catalog")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestValidateMissingFlagFailsCleanly(t *testing.T) {
	_, stderr, code := run("validate")
	if code != 1 {
		t.Fatalf("expected exit code 1 when --catalog is missing, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("--catalog is required")) {
		t.Fatalf("expected a '--catalog is required' message, got %q", stderr)
	}
}

func TestValidateRejectsIncompatibleSchema(t *testing.T) {
	// The specific finding noted at the top of this file: a catalog in a
	// different (matcherprovider fixture) schema is correctly rejected,
	// not silently accepted just because it's also JSON.
	_, stderr, code := run("validate", "-catalog", "test/fixtures/providers/synthetic/synthetic-catalog-v1.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for an incompatible catalog schema, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("unknown field")) {
		t.Fatalf("expected an 'unknown field' rejection message, got %q", stderr)
	}
}
