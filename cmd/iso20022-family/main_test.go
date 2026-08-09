// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// Every subcommand's default --matrix flag already points at a real
// committed config (configs/iso20022/family-matrix-r1.json), and there's
// extensive real pacs.008 XML fixture data under test/fixtures/iso20022/ -
// no synthetic data needed anywhere in this file.
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
	dir, err := os.MkdirTemp("", "iso20022-family-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "iso20022-family")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/iso20022-family for testing: " + err.Error() + "\n" + string(out))
	}

	os.Exit(m.Run())
}

func run(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = "../.." // repo root, so default/relative fixture paths resolve
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
	panic("iso20022-family did not run at all (not just a nonzero exit): " + err.Error())
}

const pacs008Basic = "test/fixtures/iso20022/pacs008/pacs008-basic.xml"
const pacs008Fuzzy = "test/fixtures/iso20022/pacs008/pacs008-fuzzy-names.xml"

func TestHappyPath_Matrix(t *testing.T) {
	stdout, stderr, code := run("matrix")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version":"openwatchlist.iso20022-support-matrix.v1"`)) {
		t.Fatalf("expected a support-matrix result, got: %s", stdout)
	}
}

func TestHappyPath_Inspect(t *testing.T) {
	stdout, stderr, code := run("inspect", pacs008Basic)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version":"openwatchlist.iso20022-family-evidence.v1"`)) {
		t.Fatalf("expected a family-evidence result, got: %s", stdout)
	}
}

func TestHappyPath_Project(t *testing.T) {
	stdout, stderr, code := run("project", pacs008Basic)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version":"openwatchlist.iso20022-screening-projection.v1"`)) {
		t.Fatalf("expected a screening-projection result, got: %s", stdout)
	}
}

func TestHappyPath_Batch(t *testing.T) {
	stdout, stderr, code := run("batch", pacs008Basic, pacs008Fuzzy)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version":"openwatchlist.iso20022-family-batch.v1"`)) {
		t.Fatalf("expected a family-batch result, got: %s", stdout)
	}
}

func TestHappyPath_InspectThenVerify(t *testing.T) {
	evidencePath := filepath.Join(t.TempDir(), "evidence.json")
	stdout, stderr, code := run("inspect", pacs008Basic)
	if code != 0 {
		t.Fatalf("setup inspect failed: exit %d (stderr: %q)", code, stderr)
	}
	if err := os.WriteFile(evidencePath, []byte(stdout), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code = run("verify", "-input", evidencePath)
	if code != 0 {
		t.Fatalf("verify: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"status":"ok"`)) {
		t.Fatalf("expected status ok, got: %s", stdout)
	}
}

func TestNoArgsExitsWithCode2(t *testing.T) {
	_, stderr, code := run()
	if code != 2 {
		t.Fatalf("expected exit code 2 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: iso20022-family")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestInspectMissingXMLArgFailsCleanly(t *testing.T) {
	_, stderr, code := run("inspect")
	if code != 1 {
		t.Fatalf("expected exit code 1 when no XML file is given, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("exactly one XML file is required")) {
		t.Fatalf("expected an 'exactly one XML file is required' message, got %q", stderr)
	}
}

func TestVerifyMissingInputFlagFailsCleanly(t *testing.T) {
	_, stderr, code := run("verify")
	if code != 1 {
		t.Fatalf("expected exit code 1 when --input is missing, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("--input is required")) {
		t.Fatalf("expected an '--input is required' message, got %q", stderr)
	}
}
