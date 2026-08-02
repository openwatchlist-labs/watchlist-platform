// Package main_test exercises the cmd/platform-api binary as a black box:
// build it once, then invoke it as a real subprocess with different
// arguments and check its exit code and output. This is deliberate, not
// an accident of convenience - main() here calls os.Exit directly (via
// fatal()), so testing its logic in-process would kill the test runner
// itself. Building the actual binary and exec'ing it also tests something
// arguably more valuable than an in-process unit test would: the actual
// artifact that gets deployed, flag parsing included.
//
// This is the first package addressed under issue #15 (46 of 49 cmd/
// packages had zero test coverage). The pattern here - TestMain builds
// once to a temp binary, individual tests exec it with different args -
// is meant to be copied to the remaining cmd/ packages, not reinvented
// per package.
//
// Scope, stated honestly: this covers the failure-mode / crash-safety
// behaviors that need no fixture setup (no args, invalid config path).
// It deliberately does NOT cover a full happy-path "check succeeds
// against a valid config" run, because platformapi.New requires a
// working chain of RuntimeConfig -> QuotaRegistry ->
// reviewconsoleapi config -> outbox directory, none of which has an
// existing committed fixture to build on (checked before writing this -
// see test/fixtures/production, which has exactly one unrelated file).
// Constructing that chain from scratch risks the same "guess the strict
// schema wrong" trap encountered elsewhere in this project's adversarial
// testing work. Left as tracked follow-up rather than guessed at here.
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
	dir, err := os.MkdirTemp("", "platform-api-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "platform-api")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/platform-api for testing: " + err.Error() + "\n" + string(out))
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
	panic("platform-api did not run at all (not just a nonzero exit): " + err.Error())
}

func TestNoArgsPrintsUsageAndExitsNonzero(t *testing.T) {
	_, stderr, code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: platform-api")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnknownCommandBeforeConfigStillFailsCleanly(t *testing.T) {
	// Note: platformapi.New(*cfg) runs BEFORE the command switch in main(),
	// so an unknown command with no valid config fails at config loading,
	// not at command dispatch. This test documents that actual order, not
	// an idealized one - a config error is still an error either way, and
	// the important property being tested is "doesn't panic, exits
	// nonzero, says something on stderr", not which specific message wins.
	_, stderr, code := run("bogus-command", "--config", "/nonexistent/path/config.json")
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d (stderr: %q)", code, stderr)
	}
	if stderr == "" {
		t.Fatal("expected a non-empty error message on stderr")
	}
}

func TestMissingConfigFileFailsCleanlyNotPanics(t *testing.T) {
	_, stderr, code := run("check", "--config", "/definitely/does/not/exist/config.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing config file, got %d (stderr: %q)", code, stderr)
	}
	if stderr == "" {
		t.Fatal("expected a non-empty error message on stderr for a missing config file")
	}
	// The important property: no panic, no stack trace, no hang - just a
	// clean nonzero exit with a message. A Go panic's stack trace would
	// contain "goroutine" and "panic:", neither of which should appear.
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing config file: %s", stderr)
	}
}

func TestEmptyConfigPathFailsCleanly(t *testing.T) {
	_, stderr, code := run("check", "--config", "")
	if code != 1 {
		t.Fatalf("expected exit code 1 for an empty --config value, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for an empty config path: %s", stderr)
	}
}
