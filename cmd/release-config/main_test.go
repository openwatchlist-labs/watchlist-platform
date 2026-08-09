// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// Reuses real committed production config examples
// (configs/production/phase9g-example.json,
// configs/production/tenant-quotas-r1.json) rather than hand-authoring
// runtime/quota configs, which - based on this project's history with
// internal/reviewconsoleapi's similarly-shaped config chain - carries
// real risk of getting a strict, DisallowUnknownFields schema wrong.
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
	dir, err := os.MkdirTemp("", "release-config-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "release-config")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/release-config for testing: " + err.Error() + "\n" + string(out))
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
	panic("release-config did not run at all (not just a nonzero exit): " + err.Error())
}

const (
	runtimeConfigFixture = "configs/production/phase9g-example.json"
	quotaConfigFixture   = "configs/production/tenant-quotas-r1.json"
)

func TestHappyPath_SealRuntime(t *testing.T) {
	stdout, stderr, code := run("seal-runtime", "-input", runtimeConfigFixture)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version": "openwatchlist.production-runtime-config.v1"`)) {
		t.Fatalf("expected a sealed production-runtime-config result, got: %s", stdout)
	}
}

func TestHappyPath_SealQuotas(t *testing.T) {
	stdout, stderr, code := run("seal-quotas", "-input", quotaConfigFixture)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version": "openwatchlist.tenant-quota-registry.v1"`)) {
		t.Fatalf("expected a sealed tenant-quota-registry result, got: %s", stdout)
	}
}

func TestHappyPath_OutputToFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "sealed.json")
	_, stderr, code := run("seal-runtime", "-input", runtimeConfigFixture, "-output", out)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("expected output file to exist: %v", err)
	}
	if !bytes.Contains(data, []byte(`"schema_version": "openwatchlist.production-runtime-config.v1"`)) {
		t.Fatalf("expected sealed config in the written file, got: %s", data)
	}
}

func TestNoArgsFailsWithUsageMessage(t *testing.T) {
	_, stderr, code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: release-config")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnknownCommandFailsCleanly(t *testing.T) {
	_, stderr, code := run("bogus-command", "-input", runtimeConfigFixture)
	if code != 1 {
		t.Fatalf("expected exit code 1 for an unknown command, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte(`unknown command "bogus-command"`)) {
		t.Fatalf("expected an 'unknown command' message, got %q", stderr)
	}
}

func TestMissingInputFileFailsCleanly(t *testing.T) {
	_, stderr, code := run("seal-runtime", "-input", "/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing input file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing input file: %s", stderr)
	}
}
