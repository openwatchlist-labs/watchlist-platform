// See cmd/platform-api/main_test.go for the black-box subprocess pattern
// this follows. Unlike cmd/platform-api and cmd/screening-api,
// cmd/matcher-run has NO Rust dependency at all (ofac-baseline/
// ofac-runtime load a pure-Go-compiled .owpcat package via
// internal/ofacruntime; fixture/provider-entity read plain JSON directly)
// - so this file includes two genuine, verified happy-path tests, not
// just failure modes.
package main_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "matcher-run-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "matcher-run")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/matcher-run for testing: " + err.Error() + "\n" + string(out))
	}

	os.Exit(m.Run())
}

func run(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
	// Run from the repo root (two levels up from cmd/matcher-run), since
	// default flag values (-catalog, -matcher-profiles) and the request
	// file paths used below are relative to the repo root, matching how
	// this binary is actually invoked in practice and in this project's
	// own documentation (docs/TEST_DATA.md's quickstart example).
	cmd.Dir = "../.."
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
	panic("matcher-run did not run at all (not just a nonzero exit): " + err.Error())
}

// countStatuses does a simple substring count of `"status": "X"` occurrences
// in the compact-enough JSON output, without needing to model the full
// result-batch schema just to check outcomes for this test.
func countStatuses(output, status string) int {
	return bytes.Count([]byte(output), []byte(`"status": "`+status+`"`))
}

func TestHappyPath_OfacBaseline_RealFuzzyMatching(t *testing.T) {
	// This is the same command documented (and independently verified) in
	// docs/TEST_DATA.md's "reproduce a golden result yourself" quickstart.
	stdout, stderr, code := run(
		"-provider", "ofac-baseline",
		"-catalog", "test/golden/ofac/ofac-sdn-fixture.runtime.owpcat",
		"-matcher-profiles", "configs/matcher-profiles/ofac-name-baseline-r1.json",
		"-input", "requests", "-output", "results",
		"test/golden/iso20022/pacs008/pacs008-basic.matcher-requests.json",
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if matched := countStatuses(stdout, "matched"); matched == 0 {
		t.Fatalf("expected at least one \"status\": \"matched\" result, got none. output: %s", stdout)
	}
}

func TestHappyPath_FixtureProvider_ExactMatchOnly(t *testing.T) {
	// Deliberately the OTHER provider mode, against a DIFFERENT catalog
	// (the provider-entity synthetic catalog, not the OFAC direct-list
	// fixture) - proves the two most commonly used provider modes both
	// work, not just one.
	stdout, stderr, code := run(
		"-provider", "fixture",
		"-catalog", "test/fixtures/providers/synthetic/synthetic-catalog-v1.json",
		"test/golden/iso20022/pacs008/pacs008-basic.matcher-requests.json",
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if matched := countStatuses(stdout, "matched"); matched == 0 {
		t.Fatalf("expected at least one \"status\": \"matched\" result, got none. output: %s", stdout)
	}

	var decoded map[string]any
	if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
		t.Fatalf("output was not valid JSON: %v", err)
	}
}

func TestNoArgsPrintsUsageAndExitsWithCode2(t *testing.T) {
	_, stderr, code := run()
	if code != 2 {
		t.Fatalf("expected exit code 2 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: matcher-run")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnsupportedProviderExitsWithCode2(t *testing.T) {
	_, stderr, code := run("-provider", "bogus-provider", "test/golden/iso20022/pacs008/pacs008-basic.matcher-requests.json")
	if code != 2 {
		t.Fatalf("expected exit code 2 for an unsupported --provider value, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("unsupported --provider")) {
		t.Fatalf("expected an 'unsupported --provider' message, got %q", stderr)
	}
}

func TestMissingRequestFileFailsCleanlyWithCode1(t *testing.T) {
	_, stderr, code := run("/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing request file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing request file: %s", stderr)
	}
}

func TestMissingCatalogFailsCleanlyWithCode1(t *testing.T) {
	_, stderr, code := run(
		"-catalog", "/definitely/does/not/exist.json",
		"test/golden/iso20022/pacs008/pacs008-basic.matcher-requests.json",
	)
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing catalog file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing catalog file: %s", stderr)
	}
}
