// See cmd/platform-api/main_test.go for the black-box subprocess pattern,
// and cmd/rag-index/main_test.go for why internal/rag (this package's
// dependency) is the correct consumer of the original committed RAG
// fixtures - unlike internal/assistancerag (cmd/rag-corpus).
//
// Covers both of this binary's mutually-exclusive input modes: --query
// (a structured retrieval query fixture) and --decision-batch (adapting
// a real policyengine.DecisionBatch - generated here by actually running
// cmd/policy-evaluate against its own known-working fixture, chaining
// two already-tested tools together rather than hand-authoring a
// decision batch).
package main_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var (
	binaryPath            string
	policyEvaluateBinPath string
	decisionBatchPath     string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "rag-query-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "rag-query")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/rag-query for testing: " + err.Error() + "\n" + string(out))
	}

	policyEvaluateBinPath = filepath.Join(dir, "policy-evaluate")
	build = exec.Command("go", "build", "-o", policyEvaluateBinPath, "../policy-evaluate")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/policy-evaluate (test prerequisite) for testing: " + err.Error() + "\n" + string(out))
	}

	// Generate a real decision batch by actually running policy-evaluate
	// against its own known-working golden fixture (see
	// cmd/policy-evaluate/main_test.go), rather than hand-authoring one -
	// this is a real DecisionBatch, not synthetic test data shaped to fit.
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		panic(err)
	}
	peCmd := exec.Command(policyEvaluateBinPath, "test/golden/false-positive/pattern-classifications.json")
	peCmd.Dir = repoRoot
	out, err := peCmd.Output()
	if err != nil {
		panic("failed to generate prerequisite decision batch via policy-evaluate: " + err.Error())
	}
	decisionBatchPath = filepath.Join(dir, "decision-batch.json")
	if err := os.WriteFile(decisionBatchPath, out, 0o644); err != nil {
		panic(err)
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
	panic("rag-query did not run at all (not just a nonzero exit): " + err.Error())
}

const (
	snapshotFixture = "test/golden/rag/corpus-snapshot.json"
	policyFixture   = "configs/rag/retrieval-policy-r1.json"
	queryFixture    = "test/fixtures/rag/entity-type-query.json"
	realCaseID      = "fp-01-substring-scuba-cuba" // a real case_id from the generated decision batch
)

func TestHappyPath_QueryMode(t *testing.T) {
	stdout, stderr, code := run("-snapshot", snapshotFixture, "-retrieval-policy", policyFixture, "-query", queryFixture)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version": "rag-citation-package/v1alpha1"`)) {
		t.Fatalf("expected a rag-citation-package result, got: %s", stdout)
	}
}

func TestHappyPath_DecisionBatchMode(t *testing.T) {
	stdout, stderr, code := run("-snapshot", snapshotFixture, "-retrieval-policy", policyFixture,
		"-decision-batch", decisionBatchPath, "-case-id", realCaseID)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version": "rag-citation-package/v1alpha1"`)) {
		t.Fatalf("expected a rag-citation-package result, got: %s", stdout)
	}
}

func TestMissingRequiredFlagsFailsCleanly(t *testing.T) {
	_, stderr, code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1 with no flags, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("--snapshot and --retrieval-policy are required")) {
		t.Fatalf("expected a required-flags message, got %q", stderr)
	}
}

func TestBothQueryAndDecisionBatchFailsCleanly(t *testing.T) {
	_, stderr, code := run("-snapshot", snapshotFixture, "-retrieval-policy", policyFixture,
		"-query", queryFixture, "-decision-batch", decisionBatchPath, "-case-id", realCaseID)
	if code != 1 {
		t.Fatalf("expected exit code 1 when both --query and --decision-batch are given, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("provide exactly one of --query or --decision-batch")) {
		t.Fatalf("expected a mutually-exclusive-flags message, got %q", stderr)
	}
}

func TestNeitherQueryNorDecisionBatchFailsCleanly(t *testing.T) {
	_, stderr, code := run("-snapshot", snapshotFixture, "-retrieval-policy", policyFixture)
	if code != 1 {
		t.Fatalf("expected exit code 1 when neither --query nor --decision-batch is given, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("provide exactly one of --query or --decision-batch")) {
		t.Fatalf("expected a mutually-exclusive-flags message, got %q", stderr)
	}
}

func TestUnknownCaseIDFailsCleanly(t *testing.T) {
	_, stderr, code := run("-snapshot", snapshotFixture, "-retrieval-policy", policyFixture,
		"-decision-batch", decisionBatchPath, "-case-id", "case-that-does-not-exist")
	if code != 1 {
		t.Fatalf("expected exit code 1 for an unknown --case-id, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("not found")) {
		t.Fatalf("expected a 'not found' message, got %q", stderr)
	}
}
