// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// No Rust dependency. Unlike most other cmd/ packages tested so far,
// every failure mode here exits with code 1, not 2 - fatalf() in main.go
// is used for both usage errors and operational errors, with no separate
// usage-specific exit code. Verified this by running the binary directly
// before writing assertions, since exit-code conventions are NOT
// consistent across this project's cmd/ packages (see
// cmd/screening-api/main_test.go and cmd/matcher-run/main_test.go for
// packages that DO use exit 2 for usage errors).
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
	dir, err := os.MkdirTemp("", "false-positive-classify-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "false-positive-classify")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/false-positive-classify for testing: " + err.Error() + "\n" + string(out))
	}

	os.Exit(m.Run())
}

func run(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = "../.." // repo root, so default config flags and fixture paths resolve
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
	panic("false-positive-classify did not run at all (not just a nonzero exit): " + err.Error())
}

func TestHappyPathAgainstRealFixture(t *testing.T) {
	stdout, stderr, code := run("test/fixtures/false-positive/pattern-observations.json")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	var output struct {
		Classifications []any `json:"classifications"`
	}
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("output was not valid JSON: %v\noutput: %s", err, stdout)
	}
	if len(output.Classifications) == 0 {
		t.Fatalf("expected at least one classification, got none. output: %s", stdout)
	}
}

func TestNoArgsFailsWithUsageMessage(t *testing.T) {
	_, stderr, code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1 with no args (this binary uses exit 1 for usage errors too, not exit 2), got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: false-positive-classify")) {
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

func TestUnsupportedInputKindFailsCleanly(t *testing.T) {
	_, stderr, code := run("-input", "bogus-kind", "test/fixtures/false-positive/pattern-observations.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for an unsupported --input value, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("unsupported --input")) {
		t.Fatalf("expected an 'unsupported --input' message, got %q", stderr)
	}
}

func TestMissingPatternLibraryFailsCleanly(t *testing.T) {
	_, stderr, code := run("-pattern-library", "/definitely/does/not/exist.json",
		"test/fixtures/false-positive/pattern-observations.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing pattern library, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing pattern library: %s", stderr)
	}
}
