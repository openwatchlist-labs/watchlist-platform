// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// IMPORTANT: this tool MUTATES its input file in place (it computes and
// rewrites catalog_checksum and source_manifest.manifest_id directly onto
// the given path) - verified this by reading main.go before writing
// anything. Every test here copies the real committed adversarial
// catalog fixture into a fresh temp file first; none of them ever point
// this binary at a file under test/fixtures/ directly.
package main_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var (
	binaryPath string
	repoRoot   string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "adversarial-checksum-fix-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "adversarial-checksum-fix")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/adversarial-checksum-fix for testing: " + err.Error() + "\n" + string(out))
	}

	root, err := filepath.Abs("../..")
	if err != nil {
		panic(err)
	}
	repoRoot = root

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
	panic("adversarial-checksum-fix did not run at all (not just a nonzero exit): " + err.Error())
}

// copyOfRealCatalog copies the real committed adversarial catalog
// fixture into a fresh temp file, so this tool's in-place mutation never
// touches the actual committed fixture.
func copyOfRealCatalog(t *testing.T) string {
	t.Helper()
	src := filepath.Join(repoRoot, "test/fixtures/adversarial/adversarial-catalog.direct-list.json")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestHappyPath_RecomputesChecksumInPlace(t *testing.T) {
	catalogPath := copyOfRealCatalog(t)

	stdout, stderr, code := run(catalogPath)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte("computed checksum:")) {
		t.Fatalf("expected a 'computed checksum:' line, got: %s", stdout)
	}

	// Running it again on the same (already-correct) file should be a
	// stable no-op, producing the identical checksum/manifest_id both
	// times - proving determinism. NOTE: the real committed fixture is
	// itself already checksum-correct (this is the tool that originally
	// produced it), so the file's bytes are NOT expected to change on
	// this first run - an earlier version of this test wrongly asserted
	// they must, which failed against the real fixture and was corrected
	// before committing. See TestFixesADeliberatelyWrongChecksum below
	// for the actual "does this tool correct a wrong value" proof.
	stdout2, stderr2, code2 := run(catalogPath)
	if code2 != 0 {
		t.Fatalf("second run: expected exit code 0, got %d (stderr: %q)", code2, stderr2)
	}
	if stdout != stdout2 {
		t.Fatalf("expected the same computed checksum/manifest_id on a second run, got different output:\nfirst:  %s\nsecond: %s", stdout, stdout2)
	}
}

func TestFixesADeliberatelyWrongChecksum(t *testing.T) {
	catalogPath := copyOfRealCatalog(t)
	data, err := os.ReadFile(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the checksum field with an obviously-wrong value, then
	// confirm the tool actually corrects it back - this is the real
	// proof that the tool does its job, not just that it runs without
	// error against already-correct input.
	corrupted := bytes.Replace(data,
		[]byte(`"catalog_checksum": "`),
		[]byte(`"catalog_checksum": "0000000000000000000000000000000000000000000000000000000000000000_WRONG_`),
		1)
	if bytes.Equal(corrupted, data) {
		t.Fatal("test setup failed: did not find catalog_checksum field to corrupt - fixture format may have changed")
	}
	if err := os.WriteFile(catalogPath, corrupted, 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := run(catalogPath)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}

	fixed, err := os.ReadFile(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(fixed, []byte("_WRONG_")) {
		t.Fatalf("expected the corrupted checksum to be corrected, but the marker is still present after running: %s", stdout)
	}
}

func TestWrongArgCountExitsWithCode2(t *testing.T) {
	_, stderr, code := run()
	if code != 2 {
		t.Fatalf("expected exit code 2 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: adversarial-checksum-fix")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestMissingFileFailsCleanlyWithCode1(t *testing.T) {
	_, stderr, code := run("/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing file: %s", stderr)
	}
}

func TestMalformedJSONFailsCleanlyWithCode1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "malformed.json")
	if err := os.WriteFile(path, []byte(`{"not valid`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := run(path)
	if code != 1 {
		t.Fatalf("expected exit code 1 for malformed JSON, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for malformed JSON: %s", stderr)
	}
}
