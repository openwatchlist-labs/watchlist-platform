// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// Deliberately uses a small, synthetic directory tree (a couple of files
// in t.TempDir()) rather than pointing --root at this actual repo - that
// would be slow, fragile against unrelated repo changes, and isn't
// necessary since this command's job (build/verify a manifest+bundle of
// an arbitrary directory) doesn't depend on real release content to
// exercise meaningfully.
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
	dir, err := os.MkdirTemp("", "release-artifact-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "release-artifact")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/release-artifact for testing: " + err.Error() + "\n" + string(out))
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
	panic("release-artifact did not run at all (not just a nonzero exit): " + err.Error())
}

// syntheticTree creates a small directory tree with a couple of files,
// returning its root path.
func syntheticTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "file1.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "subdir", "file2.txt"), []byte("world\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestHappyPath_FullWorkflow(t *testing.T) {
	root := syntheticTree(t)
	manifest := filepath.Join(t.TempDir(), "manifest.json")
	bundle := filepath.Join(t.TempDir(), "bundle.zip")

	stdout, stderr, code := run("manifest", "-root", root, "-manifest", manifest, "-version", "1.0.0-test", "-vcs-ref", "abc123")
	if code != 0 {
		t.Fatalf("manifest: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if stdout == "" {
		t.Fatal("manifest: expected a checksum printed to stdout")
	}

	_, stderr, code = run("verify", "-root", root, "-manifest", manifest)
	if code != 0 {
		t.Fatalf("verify: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}

	stdout, stderr, code = run("bundle", "-root", root, "-manifest", manifest, "-output", bundle)
	if code != 0 {
		t.Fatalf("bundle: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if _, err := os.Stat(bundle); err != nil {
		t.Fatalf("expected bundle file to exist: %v", err)
	}

	_, stderr, code = run("verify-bundle", "-manifest", manifest, "-output", bundle)
	if code != 0 {
		t.Fatalf("verify-bundle: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	root := syntheticTree(t)
	manifest := filepath.Join(t.TempDir(), "manifest.json")

	_, stderr, code := run("manifest", "-root", root, "-manifest", manifest, "-version", "1.0.0-test", "-vcs-ref", "abc123")
	if code != 0 {
		t.Fatalf("setup manifest failed: exit %d (stderr: %q)", code, stderr)
	}

	// Tamper with a file after the manifest was built.
	if err := os.WriteFile(filepath.Join(root, "file1.txt"), []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, stderr, code = run("verify", "-root", root, "-manifest", manifest)
	if code != 1 {
		t.Fatalf("expected exit code 1 for tampered content, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("mismatch")) {
		t.Fatalf("expected a content-mismatch message, got %q", stderr)
	}
}

func TestNoArgsFailsWithUsageMessage(t *testing.T) {
	_, stderr, code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: release-artifact")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnknownCommandFailsCleanly(t *testing.T) {
	_, stderr, code := run("bogus-command")
	if code != 1 {
		t.Fatalf("expected exit code 1 for an unknown command, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte(`unknown command "bogus-command"`)) {
		t.Fatalf("expected an 'unknown command' message, got %q", stderr)
	}
}

func TestVerifyMissingManifestFailsCleanly(t *testing.T) {
	root := syntheticTree(t)
	_, stderr, code := run("verify", "-root", root, "-manifest", "/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing manifest file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing manifest file: %s", stderr)
	}
}
