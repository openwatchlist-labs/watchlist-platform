// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// This tool always makes real HTTP requests - no fixture/dry-run mode
// exists at all, verified by reading main.go before writing anything.
// Every test here points --url at 127.0.0.1:1, a reserved port nothing
// ever listens on, so the connection is refused immediately and
// deterministically - this is NOT a live external dependency, just a
// fast, guaranteed-failing local connection, which still exercises the
// real benchmark runner, JSON report shape, and the
// qualified/exit-code-1 logic end to end. A genuinely successful
// benchmark run against a live target is not covered here - that's an
// integration test against a running server, not a unit-level black-box
// test like the rest of this file.
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
	dir, err := os.MkdirTemp("", "release-benchmark-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "release-benchmark")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/release-benchmark for testing: " + err.Error() + "\n" + string(out))
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
	panic("release-benchmark did not run at all (not just a nonzero exit): " + err.Error())
}

// refusedTargetArgs returns flags pointing at a fast, deterministic,
// always-refused local connection, keeping the whole run near-instant.
func refusedTargetArgs() []string {
	return []string{"-url", "http://127.0.0.1:1", "-requests", "1", "-warmup-requests", "0", "-concurrency", "1", "-timeout", "1s"}
}

func TestUnreachableTargetProducesRealReportAndExitsWithCode1(t *testing.T) {
	stdout, stderr, code := run(refusedTargetArgs()...)
	if code != 1 {
		t.Fatalf("expected exit code 1 for an unqualified (failed) run, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version": "openwatchlist.target-benchmark.v1"`)) {
		t.Fatalf("expected a target-benchmark report even though every request failed, got: %s", stdout)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"qualified": false`)) {
		t.Fatalf("expected qualified: false, got: %s", stdout)
	}
}

func TestOutputToFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.json")
	args := append(refusedTargetArgs(), "-output", out)
	_, stderr, code := run(args...)
	if code != 1 {
		t.Fatalf("expected exit code 1 (still an unqualified run), got %d (stderr: %q)", code, stderr)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("expected output file to exist: %v", err)
	}
	if !bytes.Contains(data, []byte(`"schema_version": "openwatchlist.target-benchmark.v1"`)) {
		t.Fatalf("expected a target-benchmark report in the written file, got: %s", data)
	}
}

func TestMissingTokenFileFailsCleanly(t *testing.T) {
	_, stderr, code := run("-token-file", "/definitely/does/not/exist.txt", "-requests", "1")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing token file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing token file: %s", stderr)
	}
}
