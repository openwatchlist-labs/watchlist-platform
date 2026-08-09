// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// Important finding, worth knowing if working near cmd/rag-corpus too:
// this repo has TWO separate, parallel RAG implementations -
// internal/rag (this package, and cmd/rag-query) and
// internal/assistancerag (cmd/rag-corpus). test/fixtures/rag/corpus-manifest.json
// and test/golden/rag/corpus-snapshot.json are correctly shaped for
// internal/rag, NOT internal/assistancerag - confirmed by actually
// running this binary against them and diffing the output against the
// committed golden file (byte-identical aside from the randomly
// generated snapshot_id). cmd/rag-corpus/main_test.go had to build its
// own manifest programmatically because internal/assistancerag's schema
// is genuinely different from what these fixtures contain - see that
// file's own comment for the "unknown field" errors that revealed this.
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
	dir, err := os.MkdirTemp("", "rag-index-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "rag-index")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/rag-index for testing: " + err.Error() + "\n" + string(out))
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
	panic("rag-index did not run at all (not just a nonzero exit): " + err.Error())
}

const manifestFixture = "test/fixtures/rag/corpus-manifest.json"

func TestHappyPath_BuildSnapshotToStdout(t *testing.T) {
	stdout, stderr, code := run("-manifest", manifestFixture)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"corpus_id": "openwatchlist-policy-fixture-r1"`)) {
		t.Fatalf("expected the fixture's corpus_id in output, got: %s", stdout)
	}
}

func TestHappyPath_BuildSnapshotToFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "snapshot.json")
	_, stderr, code := run("-manifest", manifestFixture, "-output", out)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("expected output file to exist: %v", err)
	}
	if !bytes.Contains(data, []byte(`"corpus_id": "openwatchlist-policy-fixture-r1"`)) {
		t.Fatalf("expected the fixture's corpus_id in the written file, got: %s", data)
	}
}

func TestMissingManifestFlagFailsCleanly(t *testing.T) {
	_, stderr, code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1 when --manifest is missing, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("--manifest is required")) {
		t.Fatalf("expected a '--manifest is required' message, got %q", stderr)
	}
}

func TestMissingManifestFileFailsCleanly(t *testing.T) {
	_, stderr, code := run("-manifest", "/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing manifest file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing manifest file: %s", stderr)
	}
}
