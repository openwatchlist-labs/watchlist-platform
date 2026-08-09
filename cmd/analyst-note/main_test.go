// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// The default --provider "fixture" avoids needing a live Ollama instance
// entirely - internal/analystnote.NewFixtureProvider generates a
// deterministic note without any external model call.
//
// The full input chain is built from real, already-verified tools rather
// than hand-authored: --decision-batch comes from actually running
// cmd/policy-evaluate (see its own tests), --citations comes from
// actually running cmd/rag-query (see its own tests). --profile is built
// programmatically using internal/analystnote's own exported
// ProfileChecksum function - NOT a hardcoded checksum string. An earlier
// version of this test used a checksum value read off a "wrong checksum,
// expected X" error message, which works but is fragile (it silently
// breaks if the Profile struct's fields ever change); computing it
// properly via the real function is both more honest and more durable.
package main_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/analystnote"
)

var (
	binaryPath          string
	decisionBatchPath   string
	citationPackagePath string
	profilePath         string
)

const realCaseID = "fp-01-substring-scuba-cuba"

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "analyst-note-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "analyst-note")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/analyst-note for testing: " + err.Error() + "\n" + string(out))
	}

	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		panic(err)
	}

	// Build the decision batch by actually running cmd/policy-evaluate.
	policyEvaluateBin := filepath.Join(dir, "policy-evaluate")
	build = exec.Command("go", "build", "-o", policyEvaluateBin, "../policy-evaluate")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/policy-evaluate (prerequisite): " + err.Error() + "\n" + string(out))
	}
	peCmd := exec.Command(policyEvaluateBin, "test/golden/false-positive/pattern-classifications.json")
	peCmd.Dir = repoRoot
	decisionBatch, err := peCmd.Output()
	if err != nil {
		panic("failed to generate prerequisite decision batch: " + err.Error())
	}
	decisionBatchPath = filepath.Join(dir, "decision-batch.json")
	if err := os.WriteFile(decisionBatchPath, decisionBatch, 0o644); err != nil {
		panic(err)
	}

	// Build the citation package by actually running cmd/rag-query.
	ragQueryBin := filepath.Join(dir, "rag-query")
	build = exec.Command("go", "build", "-o", ragQueryBin, "../rag-query")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/rag-query (prerequisite): " + err.Error() + "\n" + string(out))
	}
	rqCmd := exec.Command(ragQueryBin,
		"-snapshot", "test/golden/rag/corpus-snapshot.json",
		"-retrieval-policy", "configs/rag/retrieval-policy-r1.json",
		"-decision-batch", decisionBatchPath,
		"-case-id", realCaseID)
	rqCmd.Dir = repoRoot
	citations, err := rqCmd.Output()
	if err != nil {
		panic("failed to generate prerequisite citation package: " + err.Error())
	}
	citationPackagePath = filepath.Join(dir, "citations.json")
	if err := os.WriteFile(citationPackagePath, citations, 0o644); err != nil {
		panic(err)
	}

	// Build a minimal, schema-correct profile with a properly computed
	// checksum (via internal/analystnote.ProfileChecksum), not a
	// hardcoded magic value.
	profile := analystnote.Profile{
		SchemaVersion:          analystnote.ProfileSchema,
		ProfileID:              "test-profile",
		ProfileVersion:         "r1",
		PromptVersion:          "v1",
		DefaultModelID:         "test-model",
		TemperatureBasisPoints: 200,
		MaximumCitations:       5,
		ProhibitedPhrases:      []string{"guaranteed", "certain to be"},
	}
	profile.ProfileChecksum = analystnote.ProfileChecksum(profile)
	profileBytes, err := json.Marshal(profile)
	if err != nil {
		panic(err)
	}
	profilePath = filepath.Join(dir, "profile.json")
	if err := os.WriteFile(profilePath, profileBytes, 0o644); err != nil {
		panic(err)
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
	panic("analyst-note did not run at all (not just a nonzero exit): " + err.Error())
}

func TestHappyPath_FixtureProvider(t *testing.T) {
	stdout, stderr, code := run(
		"-decision-batch", decisionBatchPath, "-case-id", realCaseID,
		"-citations", citationPackagePath, "-profile", profilePath)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version": "analyst-note-invocation/v1alpha1"`)) {
		t.Fatalf("expected an analyst-note-invocation result, got: %s", stdout)
	}
}

func TestMissingRequiredFlagsFailsCleanly(t *testing.T) {
	_, stderr, code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1 with no flags, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("are required")) {
		t.Fatalf("expected a required-flags message, got %q", stderr)
	}
}

func TestUnknownProviderFailsCleanly(t *testing.T) {
	_, stderr, code := run(
		"-decision-batch", decisionBatchPath, "-case-id", realCaseID,
		"-citations", citationPackagePath, "-profile", profilePath, "-provider", "bogus-provider")
	if code != 1 {
		t.Fatalf("expected exit code 1 for an unknown --provider, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte(`unknown provider "bogus-provider"`)) {
		t.Fatalf("expected an 'unknown provider' message, got %q", stderr)
	}
}

func TestUnknownCaseIDFailsCleanly(t *testing.T) {
	_, stderr, code := run(
		"-decision-batch", decisionBatchPath, "-case-id", "case-that-does-not-exist",
		"-citations", citationPackagePath, "-profile", profilePath)
	if code != 1 {
		t.Fatalf("expected exit code 1 for an unknown --case-id, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("not found")) {
		t.Fatalf("expected a 'not found' message, got %q", stderr)
	}
}

func TestMissingProfileFileFailsCleanly(t *testing.T) {
	_, stderr, code := run(
		"-decision-batch", decisionBatchPath, "-case-id", realCaseID,
		"-citations", citationPackagePath, "-profile", "/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing profile file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing profile file: %s", stderr)
	}
}
