// Ported from cmd/homelab-testdata-validate (see test/corpus/false-positive-archetypes/README.md).
// See cmd/release-artifact/main_test.go for the black-box subprocess pattern.
package main_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var binaryPath, repoRoot string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "corpus-validate-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "corpus-validate")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/corpus-validate for testing: " + err.Error() + "\n" + string(out))
	}

	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	repoRoot = filepath.Join(wd, "..", "..")

	os.Exit(m.Run())
}

func run(dir string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath)
	cmd.Dir = dir
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
	panic("corpus-validate did not run at all (not just a nonzero exit): " + err.Error())
}

// TestValidatesPortedRegistry runs the validator against the real, ported
// test/corpus/false-positive-archetypes registry, exercising the exact path
// CI and `go run ./cmd/corpus-validate` use.
func TestValidatesPortedRegistry(t *testing.T) {
	stdout, stderr, code := run(repoRoot)
	if code != 0 {
		t.Fatalf("expected exit 0 against the ported registry, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte("PASS")) {
		t.Fatalf("expected PASS in stdout, got: %q", stdout)
	}
	if !bytes.Contains([]byte(stdout), []byte("Archetypes: 35")) {
		t.Fatalf("expected all 35 archetypes reported, got: %q", stdout)
	}
}

// TestRejectsCorruptedRegistry proves the validator actually enforces the
// schema - not just that it happens to pass against known-good data - by
// running it against a corrupted copy of the registry in an isolated temp
// directory (the real, tracked corpus is never touched).
func TestRejectsCorruptedRegistry(t *testing.T) {
	tmp := t.TempDir()
	corpusDir := filepath.Join(tmp, "test", "corpus", "false-positive-archetypes")
	if err := os.MkdirAll(filepath.Join(corpusDir, "bindings"), 0o755); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(repoRoot, "test", "corpus", "false-positive-archetypes", "archetypes.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	corrupted := bytes.Replace(raw, []byte("openwatchlist.homelab.false-positive-archetypes.v1"), []byte("corrupted"), 1)
	if bytes.Equal(corrupted, raw) {
		t.Fatal("test setup failed: schema_version marker not found in the real registry")
	}
	if err := os.WriteFile(filepath.Join(corpusDir, "archetypes.v1.json"), corrupted, 0o644); err != nil {
		t.Fatal(err)
	}

	bindings, err := os.ReadFile(filepath.Join(repoRoot, "test", "corpus", "false-positive-archetypes", "bindings", "real-ofac-bindings.v1.template.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(corpusDir, "bindings", "real-ofac-bindings.v1.template.json"), bindings, 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := run(tmp)
	if code == 0 {
		t.Fatalf("expected nonzero exit against a corrupted registry, got 0 (stdout: %q)", stdout)
	}
	if !bytes.Contains([]byte(stderr), []byte("FAIL")) {
		t.Fatalf("expected FAIL in stderr, got: %q", stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("schema_version")) {
		t.Fatalf("expected schema_version violation in stderr, got: %q", stderr)
	}
}
