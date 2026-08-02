// See cmd/platform-api/main_test.go for the black-box subprocess pattern
// this follows (main() calls os.Exit directly via fatalf/usage, so
// in-process testing isn't viable).
//
// Scope, stated honestly: this covers failure-mode behaviors only (no
// args, unknown command, missing/malformed config). A happy-path test
// (serve or check against a real, working runtime) is NOT attempted here,
// and this is a hard blocker, not a choice: load() in main.go
// unconditionally calls screeningapi.StartRuntimeManager, which
// unconditionally calls runtimemmapclient.StartPool, which spawns the
// real Rust catalog-mmap binary as a subprocess. This is exactly the same
// Rust-toolchain dependency documented as unverified in issue #13 - the
// internal/screeningapi package's OWN tests avoid this entirely via a
// Go-level fakeRuntime interface mock (see
// internal/screeningapi/service_test.go), which is only possible because
// Service/Handler accept an injectable Runtime interface in Go tests -
// there is no equivalent injection point at the compiled-CLI level.
// A real happy-path test for this specific binary should be added once
// issue #13's Rust toolchain question is resolved, not guessed at here.
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
	dir, err := os.MkdirTemp("", "screening-api-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "screening-api")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/screening-api for testing: " + err.Error() + "\n" + string(out))
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
	panic("screening-api did not run at all (not just a nonzero exit): " + err.Error())
}

func TestNoArgsPrintsUsageAndExitsWithCode2(t *testing.T) {
	// Note: exit code 2 here, not 1 - usage() in main.go calls os.Exit(2)
	// directly, unlike cmd/platform-api and cmd/policy-evaluate's
	// convention of exit 1 for usage errors. Verified this by running the
	// actual binary before writing the assertion - don't assume every
	// cmd/ package shares the same exit-code convention.
	_, stderr, code := run()
	if code != 2 {
		t.Fatalf("expected exit code 2 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: screening-api")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnknownCommandPrintsUsageAndExitsWithCode2(t *testing.T) {
	_, stderr, code := run("bogus-command")
	if code != 2 {
		t.Fatalf("expected exit code 2 for an unknown command, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: screening-api")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestCheckWithMissingConfigFailsCleanlyWithCode1(t *testing.T) {
	_, stderr, code := run("check", "--config", "/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing config file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing config file: %s", stderr)
	}
}

func TestServeWithMissingConfigFailsCleanlyWithCode1(t *testing.T) {
	// Same failure point as "check" - LoadConfig runs before serve() does
	// anything server-related, so this doesn't start listening on any port.
	_, stderr, code := run("serve", "--config", "/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing config file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing config file: %s", stderr)
	}
}

func TestCheckWithMalformedConfigFailsCleanly(t *testing.T) {
	tmp, err := os.CreateTemp("", "screening-api-malformed-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(`{"not valid json`); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	_, stderr, code := run("check", "--config", tmp.Name())
	if code != 1 {
		t.Fatalf("expected exit code 1 for malformed config JSON, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for malformed config: %s", stderr)
	}
}
