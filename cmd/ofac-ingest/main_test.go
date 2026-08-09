// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// Important: without -input, this binary defaults to downloading from a
// real external URL (ofacsource.OfficialSDNXMLURL) - every test here
// passes -input pointing at a local fixture specifically to avoid any
// live network dependency, verified this default behavior by reading
// main.go before writing tests, not assumed safe.
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
	dir, err := os.MkdirTemp("", "ofac-ingest-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "ofac-ingest")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/ofac-ingest for testing: " + err.Error() + "\n" + string(out))
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
	panic("ofac-ingest did not run at all (not just a nonzero exit): " + err.Error())
}

const localFixture = "test/fixtures/ofac/sdn/sdn-fixture.xml"

func TestHappyPath_Manifest(t *testing.T) {
	stdout, stderr, code := run("-input", localFixture, "-output", "manifest", "-acquired-at", "2026-01-01T00:00:00Z")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"dataset_id": "ofac-sdn"`)) {
		t.Fatalf("expected a manifest with dataset_id ofac-sdn, got: %s", stdout)
	}
}

func TestHappyPath_Catalog(t *testing.T) {
	stdout, stderr, code := run("-input", localFixture, "-output", "catalog", "-acquired-at", "2026-01-01T00:00:00Z")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"catalog_id": "ofac-sdn-direct"`)) {
		t.Fatalf("expected a direct-list catalog, got: %s", stdout)
	}
}

func TestUnsupportedOutputExitsWithCode2(t *testing.T) {
	_, stderr, code := run("-input", localFixture, "-output", "bogus", "-acquired-at", "2026-01-01T00:00:00Z")
	if code != 2 {
		t.Fatalf("expected exit code 2 for an unsupported --output value, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("unsupported --output")) {
		t.Fatalf("expected an 'unsupported --output' message, got %q", stderr)
	}
}

func TestExtraPositionalArgExitsWithCode2(t *testing.T) {
	_, stderr, code := run("extra-positional-arg")
	if code != 2 {
		t.Fatalf("expected exit code 2 for an unexpected positional argument, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: ofac-ingest")) {
		t.Fatalf("expected usage message, got %q", stderr)
	}
}

func TestMissingInputFileFailsCleanlyWithCode1(t *testing.T) {
	_, stderr, code := run("-input", "/definitely/does/not/exist.xml", "-acquired-at", "2026-01-01T00:00:00Z")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing input file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing input file: %s", stderr)
	}
}

func TestInvalidAcquiredAtFailsCleanlyWithCode1(t *testing.T) {
	_, stderr, code := run("-input", localFixture, "-acquired-at", "not-a-valid-timestamp")
	if code != 1 {
		t.Fatalf("expected exit code 1 for an invalid --acquired-at value, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for an invalid --acquired-at value: %s", stderr)
	}
}
