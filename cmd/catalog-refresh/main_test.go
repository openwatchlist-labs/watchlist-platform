// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// The "simulate" command (the default) has every flag already defaulting
// to a real committed fixture (test/fixtures/catalog-refresh/*), so the
// happy path needs no flags at all - verified this actually produces
// real output before writing the assertion, not assumed from the
// defaults alone.
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
	dir, err := os.MkdirTemp("", "catalog-refresh-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "catalog-refresh")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/catalog-refresh for testing: " + err.Error() + "\n" + string(out))
	}

	os.Exit(m.Run())
}

func run(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = "../.." // repo root, so the default fixture paths resolve
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
	panic("catalog-refresh did not run at all (not just a nonzero exit): " + err.Error())
}

func TestHappyPath_SimulateWithDefaults(t *testing.T) {
	stdout, stderr, code := run()
	if code != 0 {
		t.Fatalf("expected exit code 0 with zero flags (defaults point at real fixtures), got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version": "catalog-refresh-replay/v1alpha1"`)) {
		t.Fatalf("expected a catalog-refresh-replay result, got: %s", stdout)
	}
}

func TestUnknownCommandExitsWithCode2(t *testing.T) {
	_, stderr, code := run("-command", "bogus")
	if code != 2 {
		t.Fatalf("expected exit code 2 for an unknown --command value, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: catalog-refresh")) {
		t.Fatalf("expected usage message, got %q", stderr)
	}
}

func TestDiffWithoutRequiredCatalogsExitsWithCode2(t *testing.T) {
	// mustCatalog() falls through to the same usage/exit-2 path as an
	// unknown command when a required catalog path flag is empty -
	// verified this by running the binary directly, not assumed from
	// reading main.go alone (an empty-required-flag case could plausibly
	// have used a distinct exit code, as several other cmd/ packages in
	// this project do).
	_, stderr, code := run("-command", "diff")
	if code != 2 {
		t.Fatalf("expected exit code 2 for 'diff' with no --base-catalog/--target-catalog, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: catalog-refresh")) {
		t.Fatalf("expected usage message, got %q", stderr)
	}
}

func TestSimulateWithMissingXMLFixtureFailsCleanly(t *testing.T) {
	_, stderr, code := run("-base-xml", "/definitely/does/not/exist.xml")
	if code == 0 {
		t.Fatal("expected a nonzero exit code for a missing --base-xml file")
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing --base-xml file: %s", stderr)
	}
}
