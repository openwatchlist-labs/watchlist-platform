// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// The default --plan flag already points at a real committed config
// (configs/screening-plans/iso20022-pacs008-cbprplus-v1.json), and real
// pacs.008 XML fixtures exist under test/fixtures/iso20022/ - no
// synthetic data needed. Covers all 5 --output modes (canonical is the
// default; evidence, inspection, matcher-requests, and replay all run
// the full screening-plan executor).
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
	dir, err := os.MkdirTemp("", "iso20022-inspect-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "iso20022-inspect")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/iso20022-inspect for testing: " + err.Error() + "\n" + string(out))
	}

	os.Exit(m.Run())
}

func run(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = "../.." // repo root, so the default --plan path and fixture paths resolve
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
	panic("iso20022-inspect did not run at all (not just a nonzero exit): " + err.Error())
}

const pacs008Basic = "test/fixtures/iso20022/pacs008/pacs008-basic.xml"

func TestHappyPath_Canonical(t *testing.T) {
	stdout, stderr, code := run(pacs008Basic)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version": "canonical-message/v1alpha1"`)) {
		t.Fatalf("expected a canonical-message result (the default output), got: %s", stdout)
	}
}

func TestHappyPath_Evidence(t *testing.T) {
	stdout, stderr, code := run("-output", "evidence", pacs008Basic)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if len(stdout) == 0 {
		t.Fatal("expected non-empty evidence output")
	}
}

func TestHappyPath_Inspection(t *testing.T) {
	stdout, stderr, code := run("-output", "inspection", pacs008Basic)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"canonical"`)) || !bytes.Contains([]byte(stdout), []byte(`"evidence"`)) {
		t.Fatalf("expected inspection output to bundle both canonical and evidence, got: %s", stdout)
	}
}

func TestHappyPath_MatcherRequests(t *testing.T) {
	stdout, stderr, code := run("-output", "matcher-requests", pacs008Basic)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version": "candidate-search-request-batch/v1alpha1"`)) {
		t.Fatalf("expected a candidate-search-request-batch result, got: %s", stdout)
	}
}

func TestHappyPath_Replay(t *testing.T) {
	stdout, stderr, code := run("-output", "replay", pacs008Basic)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if len(stdout) == 0 {
		t.Fatal("expected non-empty replay output")
	}
}

func TestNoArgsExitsWithCode2(t *testing.T) {
	_, stderr, code := run()
	if code != 2 {
		t.Fatalf("expected exit code 2 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: iso20022-inspect")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnsupportedOutputExitsWithCode2(t *testing.T) {
	_, stderr, code := run("-output", "bogus", pacs008Basic)
	if code != 2 {
		t.Fatalf("expected exit code 2 for an unsupported --output value, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("unsupported --output")) {
		t.Fatalf("expected an 'unsupported --output' message, got %q", stderr)
	}
}

func TestMissingXMLFileFailsCleanlyWithCode1(t *testing.T) {
	_, stderr, code := run("/definitely/does/not/exist.xml")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing XML file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing XML file: %s", stderr)
	}
}
