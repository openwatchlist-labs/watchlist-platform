// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// Important finding: the committed test/fixtures/rag/corpus-manifest.json
// and test/golden/rag/corpus-snapshot.json use a richer, DIFFERENT schema
// (source_id/path/publisher/source_tier/document_type/jurisdiction, with
// file-path document references) than what LoadManifest/LoadSnapshot
// currently accept (a simpler schema: document_id/tenant_id/kind/title/
// source_ref/effective_at/text, inline). Same with
// test/fixtures/rag/entity-type-query.json, which has query_text but the
// current RetrievalQuery struct expects terms []string. Discovered all
// three by actually running the commands against them and reading the
// "unknown field"/"query terms are required" errors, not assumed
// compatible just because the fixtures live in the expected directory.
// This file builds a minimal, schema-correct manifest and query
// programmatically instead - using REAL document content from
// test/fixtures/rag/documents/approved-policy.md, not synthetic text.
package main_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var (
	binaryPath string
	repoRoot   string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "rag-corpus-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "rag-corpus")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/rag-corpus for testing: " + err.Error() + "\n" + string(out))
	}

	root, err := filepath.Abs("../..")
	if err != nil {
		panic(err)
	}
	repoRoot = root

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
	panic("rag-corpus did not run at all (not just a nonzero exit): " + err.Error())
}

// buildValidManifest constructs a schema-correct manifest using the real
// committed policy document's text content, and writes it to dir.
func buildValidManifest(t *testing.T, dir string) string {
	t.Helper()
	text, err := os.ReadFile(filepath.Join(repoRoot, "test/fixtures/rag/documents/approved-policy.md"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{
		"schema_version": "openwatchlist.rag-corpus-manifest.v1",
		"corpus_id":      "test-corpus",
		"version":        "r1",
		"built_at":       "2026-07-14T12:00:00Z",
		"documents": []map[string]any{
			{
				"document_id":  "doc-1",
				"tenant_id":    "tenant-a",
				"kind":         "policy",
				"title":        "Transaction Screening Policy",
				"source_ref":   "approved-policy.md",
				"effective_at": "2026-07-01T00:00:00Z",
				"text":         string(text),
			},
		},
	}
	path := filepath.Join(dir, "manifest.json")
	raw, _ := json.Marshal(manifest)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func compileFixtureSnapshot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	manifestPath := buildValidManifest(t, dir)
	outputPath := filepath.Join(dir, "snapshot.json")
	_, stderr, code := run("compile", "-manifest", manifestPath, "-output", outputPath)
	if code != 0 {
		t.Fatalf("setup compile failed: exit %d (stderr: %q)", code, stderr)
	}
	return outputPath
}

func TestHappyPath_CompileThenVerify(t *testing.T) {
	snapshotPath := compileFixtureSnapshot(t)
	stdout, stderr, code := run("verify", "-snapshot", snapshotPath)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"corpus_id":"test-corpus"`)) {
		t.Fatalf("expected corpus_id test-corpus, got: %s", stdout)
	}
}

func TestHappyPath_Query(t *testing.T) {
	snapshotPath := compileFixtureSnapshot(t)
	queryPath := filepath.Join(t.TempDir(), "query.json")
	query := `{"tenant_id": "tenant-a", "terms": ["policy", "screening"], "top_k": 5}`
	if err := os.WriteFile(queryPath, []byte(query), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := run("query", "-snapshot", snapshotPath, "-input", queryPath)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"passages"`)) {
		t.Fatalf("expected a passages array in the retrieval result, got: %s", stdout)
	}
}

func TestNoArgsFailsWithUsageMessage(t *testing.T) {
	_, stderr, code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: rag-corpus")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnknownCommandFailsCleanly(t *testing.T) {
	_, stderr, code := run("bogus-command")
	if code != 1 {
		t.Fatalf("expected exit code 1 for an unknown command, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte(`unknown command "bogus-command"`)) {
		t.Fatalf("expected an 'unknown command' message, got %q", stderr)
	}
}

func TestCompileWithMissingManifestFailsCleanly(t *testing.T) {
	_, stderr, code := run("compile", "-manifest", "/definitely/does/not/exist.json", "-output", filepath.Join(t.TempDir(), "out.json"))
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing manifest file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing manifest file: %s", stderr)
	}
}

func TestQueryWithoutTermsFailsCleanly(t *testing.T) {
	// The specific finding noted at the top of this file: a query using
	// the OLDER query_text-style schema (like the committed
	// test/fixtures/rag/entity-type-query.json) is missing the required
	// "terms" field and is correctly rejected, not silently accepted.
	snapshotPath := compileFixtureSnapshot(t)
	queryPath := filepath.Join(t.TempDir(), "query.json")
	if err := os.WriteFile(queryPath, []byte(`{"tenant_id": "tenant-a"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := run("query", "-snapshot", snapshotPath, "-input", queryPath)
	if code != 1 {
		t.Fatalf("expected exit code 1 for a query with no terms, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("query terms are required")) {
		t.Fatalf("expected a 'query terms are required' message, got %q", stderr)
	}
}
