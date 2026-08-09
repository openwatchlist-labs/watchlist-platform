// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// Uses a real local httptest.Server (not a live external dependency) to
// exercise a genuine 2xx happy path and a genuine non-2xx failure path,
// plus a guaranteed-refused local port for the connection-error case -
// same "fast, deterministic, local-only" approach as
// cmd/release-benchmark/main_test.go.
package main_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "container-healthcheck-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "container-healthcheck")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/container-healthcheck for testing: " + err.Error() + "\n" + string(out))
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
	panic("container-healthcheck did not run at all (not just a nonzero exit): " + err.Error())
}

func TestHappyPath_200OK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	_, stderr, code := run(server.URL)
	if code != 0 {
		t.Fatalf("expected exit code 0 for a 200 response, got %d (stderr: %q)", code, stderr)
	}
}

func TestNon2xxStatusFailsWithCode1(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, stderr, code := run(server.URL)
	if code != 1 {
		t.Fatalf("expected exit code 1 for a 503 response, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("unexpected HTTP status")) {
		t.Fatalf("expected an 'unexpected HTTP status' message, got %q", stderr)
	}
}

func TestConnectionRefusedFailsWithCode1(t *testing.T) {
	_, stderr, code := run("http://127.0.0.1:1")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a refused connection, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a refused connection: %s", stderr)
	}
}

func TestWrongArgCountExitsWithCode2(t *testing.T) {
	_, stderr, code := run()
	if code != 2 {
		t.Fatalf("expected exit code 2 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: container-healthcheck")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestTooManyArgsExitsWithCode2(t *testing.T) {
	_, stderr, code := run("http://example.com", "extra-arg")
	if code != 2 {
		t.Fatalf("expected exit code 2 with too many args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: container-healthcheck")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}
