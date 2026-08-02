// See cmd/platform-api/main_test.go for the pattern this follows: build
// the actual binary once, exec it as a subprocess per test case. Unlike
// platform-api, this package has an existing, real, committed fixture
// that already produces valid output end to end
// (test/golden/false-positive/pattern-classifications.json against the
// repo's default configs/policies/transaction-screening-r1.yaml) - so
// this test file includes a genuine happy-path case, verified by actually
// running it before writing the assertion, not assumed.
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
	dir, err := os.MkdirTemp("", "policy-evaluate-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "policy-evaluate")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/policy-evaluate for testing: " + err.Error() + "\n" + string(out))
	}

	os.Exit(m.Run())
}

func run(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
	// Run from the repo root (two levels up from cmd/policy-evaluate), since
	// the default -policy flag value is a relative path
	// (configs/policies/transaction-screening-r1.yaml) resolved from the
	// working directory, matching how this binary is actually invoked in
	// practice.
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
	panic("policy-evaluate did not run at all (not just a nonzero exit): " + err.Error())
}

func TestHappyPathAgainstRealFixture(t *testing.T) {
	stdout, stderr, code := run("test/golden/false-positive/pattern-classifications.json")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	var output struct {
		Summary struct {
			TotalDecisions int `json:"total_decisions"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("output was not valid JSON: %v\noutput: %s", err, stdout)
	}
	if output.Summary.TotalDecisions == 0 {
		t.Fatalf("expected a nonzero total_decisions count, got 0 - output: %s", stdout)
	}
}

func TestNoArgsPrintsUsageAndExitsNonzero(t *testing.T) {
	_, stderr, code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: policy-evaluate")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestMissingInputFileFailsCleanly(t *testing.T) {
	_, stderr, code := run("/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing input file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing input file: %s", stderr)
	}
}

func TestMalformedJSONFailsCleanly(t *testing.T) {
	tmp, err := os.CreateTemp("", "policy-evaluate-malformed-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(`{"this is not valid": `); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	_, stderr, code := run(tmp.Name())
	if code != 1 {
		t.Fatalf("expected exit code 1 for malformed JSON, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for malformed JSON: %s", stderr)
	}
}

func TestUnknownFieldRejectedByStrictDecoding(t *testing.T) {
	// decodeStrict in main.go explicitly uses json.Decoder.DisallowUnknownFields.
	// This confirms that behavior actually holds for the compiled binary,
	// not just that the source code calls the right function.
	tmp, err := os.CreateTemp("", "policy-evaluate-unknown-field-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(`{"schema_version": "x", "classification_batch_id": "x", "input_observation_batch_id": "x", "classifier_version": "x", "pattern_library": {}, "countervailing_policy": {}, "summary": {}, "classifications": [], "unexpected_extra_field": true}`); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	_, stderr, code := run(tmp.Name())
	if code != 1 {
		t.Fatalf("expected exit code 1 for a JSON payload with an unrecognized field, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for an unrecognized field: %s", stderr)
	}
	// Verified this is genuinely the unknown-field rejection firing, not a
	// coincidental failure for some other reason (e.g. this payload's
	// schema_version is also deliberately invalid) - checked manually
	// before writing this assertion that the error message is specifically
	// about the unknown field, and that it fires at the decode stage
	// before schema_version validation would even run.
	if !bytes.Contains([]byte(stderr), []byte("unknown field")) {
		t.Fatalf("expected the error to specifically mention an unknown field (proving DisallowUnknownFields actually fired), got: %s", stderr)
	}
}
