// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// This binary's own flag defaults already point at real committed
// fixtures (test/fixtures/ofac/sdn/sdn-fixture{,-v2}.xml), so the happy
// path needs only fresh --state-dir/--archive-dir per test (via
// t.TempDir()) to avoid state collisions between test runs and with any
// real /tmp/openwatchlist-phase2c-* directories a manual run might leave
// behind - verified this isolation is necessary by reading the default
// flag values in main.go before writing tests.
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
	dir, err := os.MkdirTemp("", "update-manager-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "update-manager")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/update-manager for testing: " + err.Error() + "\n" + string(out))
	}

	os.Exit(m.Run())
}

func run(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = "../.." // repo root, so the default source-v1/source-v2 fixture paths resolve
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
	panic("update-manager did not run at all (not just a nonzero exit): " + err.Error())
}

func freshDirs(t *testing.T) (stateDir, archiveDir string) {
	t.Helper()
	return t.TempDir(), t.TempDir()
}

func TestHappyPath_Simulate(t *testing.T) {
	stateDir, archiveDir := freshDirs(t)
	stdout, stderr, code := run("-command", "simulate", "-state-dir", stateDir, "-archive-dir", archiveDir)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version": "distributed-update-replay/v1alpha1"`)) {
		t.Fatalf("expected a distributed-update-replay result, got: %s", stdout)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"rollback"`)) {
		t.Fatalf("expected the simulated scenario to include a rollback (it deliberately exercises one), got: %s", stdout)
	}
}

func TestHistoryCommandExitsWithCode2(t *testing.T) {
	// main.go's "history" command deliberately just points at persisted
	// audit files and exits 2 - it doesn't read/print anything itself.
	// Verified this by running the binary directly before writing this
	// assertion.
	stateDir, archiveDir := freshDirs(t)
	_, stderr, code := run("-command", "history", "-state-dir", stateDir, "-archive-dir", archiveDir)
	if code != 2 {
		t.Fatalf("expected exit code 2 for the history command, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("persisted audit")) {
		t.Fatalf("expected a message pointing at persisted audit files, got %q", stderr)
	}
}

func TestUnknownCommandExitsWithCode2(t *testing.T) {
	stateDir, archiveDir := freshDirs(t)
	_, stderr, code := run("-command", "bogus", "-state-dir", stateDir, "-archive-dir", archiveDir)
	if code != 2 {
		t.Fatalf("expected exit code 2 for an unknown command, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: update-manager")) {
		t.Fatalf("expected usage message, got %q", stderr)
	}
}

func TestInvalidWorkersFailsCleanlyWithCode1(t *testing.T) {
	stateDir, archiveDir := freshDirs(t)
	_, stderr, code := run("-workers", "bad-worker-format", "-state-dir", stateDir, "-archive-dir", archiveDir)
	if code != 1 {
		t.Fatalf("expected exit code 1 for a malformed --workers value, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("invalid worker")) {
		t.Fatalf("expected an 'invalid worker' message, got %q", stderr)
	}
}

func TestInvalidBaseTimeFailsCleanlyWithCode1(t *testing.T) {
	stateDir, archiveDir := freshDirs(t)
	_, stderr, code := run("-base-time", "not-a-valid-time", "-state-dir", stateDir, "-archive-dir", archiveDir)
	if code != 1 {
		t.Fatalf("expected exit code 1 for an invalid --base-time value, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for an invalid --base-time value: %s", stderr)
	}
}
