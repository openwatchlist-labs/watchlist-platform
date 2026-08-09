// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// Important: this binary uses a hand-rolled flag parser requiring
// double-dash "--config" specifically ("-config" is NOT recognized and
// produces "--config is required") - discovered by reading option() in
// main.go, not assumed consistent with other cmd/ packages' flag.Parse-
// based single-or-double-dash handling. Also: every error path here
// exits with code 1, including no-args and unknown-command - different
// from cmd/screening-api-v8e/v8f's exit-2 convention for those same
// cases, verified directly rather than assumed.
//
// Uses internal/screeningledger (the same package with real fixtures at
// test/fixtures/screening-ledger/ - see cmd/screening-ledger/main_test.go)
// for the ledger directory and snapshot key, and reuses
// cmd/screening-api-v8d's own "fixture-upstream" subcommand for the
// upstream, the same cross-package reuse already proven in
// cmd/screening-api-v8e/main_test.go.
package main_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

var (
	binaryPath string
	v8dBinary  string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "screening-api-v8g-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "screening-api-v8g")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/screening-api-v8g for testing: " + err.Error() + "\n" + string(out))
	}

	v8dBinary = filepath.Join(dir, "screening-api-v8d")
	build = exec.Command("go", "build", "-o", v8dBinary, "../screening-api-v8d")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/screening-api-v8d (prerequisite, for its fixture-upstream subcommand) for testing: " + err.Error() + "\n" + string(out))
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
	panic("screening-api-v8g did not run at all (not just a nonzero exit): " + err.Error())
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func waitReady(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to become ready", url)
}

func startFixtureUpstream(t *testing.T) (baseURL string, cleanup func()) {
	t.Helper()
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	addr := freeAddr(t)
	cmd := exec.Command(v8dBinary, "fixture-upstream",
		"-listen", addr,
		"-single-response", "test/fixtures/screening-api-v8d/upstream-realtime.response.json",
		"-batch-response", "test/fixtures/screening-api-v8d/upstream-batch.response.json")
	cmd.Dir = repoRoot
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start fixture-upstream: %v", err)
	}
	baseURL = "http://" + addr
	waitReady(t, baseURL+"/readyz", 5*time.Second)
	return baseURL, func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
}

func buildConfig(t *testing.T, listenAddr, upstreamBaseURL string) string {
	t.Helper()
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	config := map[string]any{
		"listen_address":         listenAddr,
		"upstream_base_url":      upstreamBaseURL,
		"ledger_directory":       t.TempDir(),
		"idempotency_directory":  t.TempDir(),
		"instance_id":            "test-instance",
		"snapshot_key_file":      filepath.Join(repoRoot, "test/fixtures/screening-ledger/snapshot-key.hex"),
		"max_body_bytes":         1048576,
		"request_timeout_millis": 5000,
		"retention": map[string]any{
			"class":              "standard",
			"retention_days":     365,
			"max_snapshot_bytes": 1048576,
		},
		"require_postgres": false,
	}
	configBytes, _ := json.Marshal(config)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, configBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHappyPath_Check(t *testing.T) {
	upstreamURL, cleanup := startFixtureUpstream(t)
	defer cleanup()

	config := buildConfig(t, "127.0.0.1:0", upstreamURL)
	stdout, stderr, code := run("check", "--config", config)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"status":"ok"`)) {
		t.Fatalf("expected status ok, got: %s", stdout)
	}
}

func TestHappyPath_FullHTTPRoundTrip(t *testing.T) {
	upstreamURL, cleanupUpstream := startFixtureUpstream(t)
	defer cleanupUpstream()

	serverAddr := freeAddr(t)
	config := buildConfig(t, serverAddr, upstreamURL)

	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	serveCmd := exec.Command(binaryPath, "serve", "--config", config)
	serveCmd.Dir = repoRoot
	if err := serveCmd.Start(); err != nil {
		t.Fatalf("failed to start serve: %v", err)
	}
	defer func() {
		_ = serveCmd.Process.Kill()
		_, _ = serveCmd.Process.Wait()
	}()

	requestBody, err := os.ReadFile(filepath.Join(repoRoot, "test/fixtures/screening-api-v8d/realtime.request.json"))
	if err != nil {
		t.Fatal(err)
	}

	// No dedicated readiness endpoint confirmed for this version - poll
	// the screening endpoint itself with a short client timeout until the
	// server accepts connections.
	var responseBody []byte
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, postErr := http.Post("http://"+serverAddr+"/v1/screenings", "application/json", bytes.NewReader(requestBody))
		if postErr == nil {
			defer resp.Body.Close()
			responseBody, err = io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("expected HTTP 200, got %d (body: %s)", resp.StatusCode, responseBody)
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if responseBody == nil {
		t.Fatal("timed out waiting for the server to become reachable")
	}
	if !bytes.Contains(responseBody, []byte(`"status": "candidates_retrieved"`)) {
		t.Fatalf("expected status candidates_retrieved, got: %s", responseBody)
	}
}

func TestNoArgsFailsCleanlyWithCode1(t *testing.T) {
	_, stderr, code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: screening-api-v8g")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnknownCommandFailsCleanlyWithCode1(t *testing.T) {
	upstreamURL, cleanup := startFixtureUpstream(t)
	defer cleanup()
	config := buildConfig(t, "127.0.0.1:0", upstreamURL)

	_, stderr, code := run("bogus-command", "--config", config)
	if code != 1 {
		t.Fatalf("expected exit code 1 for an unknown command, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("unknown command")) {
		t.Fatalf("expected an 'unknown command' message, got %q", stderr)
	}
}

func TestSingleDashConfigFlagIsNotRecognized(t *testing.T) {
	// The specific finding noted at the top of this file: this binary's
	// hand-rolled option() parser only matches the literal string
	// "--config", so "-config" (single dash, which flag.Parse-based
	// binaries elsewhere in this project accept) is silently NOT
	// recognized and treated as if --config were never given at all.
	upstreamURL, cleanup := startFixtureUpstream(t)
	defer cleanup()
	config := buildConfig(t, "127.0.0.1:0", upstreamURL)

	_, stderr, code := run("check", "-config", config)
	if code != 1 {
		t.Fatalf("expected exit code 1 for a single-dash -config flag, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("--config is required")) {
		t.Fatalf("expected '--config is required' (proving -config was NOT recognized), got %q", stderr)
	}
}

func TestMissingConfigFileFailsCleanly(t *testing.T) {
	_, stderr, code := run("check", "--config", "/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing config file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing config file: %s", stderr)
	}
}
