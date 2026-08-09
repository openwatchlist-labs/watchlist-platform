// See cmd/platform-api/main_test.go for the black-box subprocess pattern,
// and cmd/screening-api-v8d/main_test.go for the fixture-upstream
// approach this reuses. Important finding: internal/screeningapiv8e
// wraps internal/screeningapiv8d.NewHTTPUpstream and
// internal/screeningapiv8d.NewServer directly, so it speaks the exact
// same upstream protocol - this test starts v8d's OWN "fixture-upstream"
// subcommand as v8e's upstream, rather than building a separate mock,
// since they're genuinely the same protocol (confirmed by reading
// internal/screeningapiv8e/server.go before assuming this would work).
//
// The other real difference from v8d: this version needs a genuine
// scoring-activation state (internal/scoringactivation.NewManager),
// built here the same way cmd/scoring-activation/main_test.go's happy
// path does - the exact same projection-package fixture pair
// independently verified during the #13 investigation.
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
	binaryPath              string
	scoringActivationBinary string
	v8dBinary               string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "screening-api-v8e-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "screening-api-v8e")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/screening-api-v8e for testing: " + err.Error() + "\n" + string(out))
	}

	scoringActivationBinary = filepath.Join(dir, "scoring-activation")
	build = exec.Command("go", "build", "-o", scoringActivationBinary, "../scoring-activation")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/scoring-activation (prerequisite) for testing: " + err.Error() + "\n" + string(out))
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
	panic("screening-api-v8e did not run at all (not just a nonzero exit): " + err.Error())
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

// freshActivationState builds a real scoring-activation state using the
// same fixture pair independently verified during the #13 investigation.
// The activation ID MUST be "activation-phase8d-fixture" - not an
// arbitrary value - because v8e cross-checks the local activation's ID
// against the activation_id embedded in the upstream response fixture
// (test/fixtures/screening-api-v8d/upstream-realtime.response.json) and
// blocks with "active_catalog_lineage_mismatch" if they disagree.
// Discovered this via a real HTTP 502 with that exact blocker code when
// an arbitrary activation ID was used first - fixed by reading the
// error, not guessed at.
func freshActivationState(t *testing.T) string {
	t.Helper()
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	cmd := exec.Command(scoringActivationBinary, "activate",
		"-state-dir", stateDir, "-activation-id", "activation-phase8d-fixture",
		"-catalog-descriptor", "test/fixtures/projection-package/catalog-descriptor.json",
		"-projection-package", "test/fixtures/projection-package/packages/b652a63ffd2c8ed73dd40e8fb3530670ad49798fb3140fe3de8ac02ec12f7167",
		"-policy", "configs/scoring/candidate-scoring-r1.json")
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build prerequisite scoring-activation state: %v\n%s", err, out)
	}
	return stateDir
}

func buildConfig(t *testing.T, listenAddr, upstreamBaseURL, activationStateDir string) string {
	t.Helper()
	config := map[string]any{
		"listen_address":             listenAddr,
		"upstream_base_url":          upstreamBaseURL,
		"activation_state_directory": activationStateDir,
		"idempotency_directory":      filepath.Join(t.TempDir(), "idempotency"),
		"max_body_bytes":             1048576,
		"max_batch_items":            100,
		"request_timeout_millis":     5000,
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
	activationState := freshActivationState(t)

	config := buildConfig(t, "127.0.0.1:0", upstreamURL, activationState)
	stdout, stderr, code := run("check", "-config", config)
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
	activationState := freshActivationState(t)

	serverAddr := freeAddr(t)
	config := buildConfig(t, serverAddr, upstreamURL, activationState)

	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	serveCmd := exec.Command(binaryPath, "serve", "-config", config)
	serveCmd.Dir = repoRoot
	if err := serveCmd.Start(); err != nil {
		t.Fatalf("failed to start serve: %v", err)
	}
	defer func() {
		_ = serveCmd.Process.Kill()
		_, _ = serveCmd.Process.Wait()
	}()
	waitReady(t, "http://"+serverAddr+"/healthz", 5*time.Second)

	requestBody, err := os.ReadFile(filepath.Join(repoRoot, "test/fixtures/screening-api-v8d/realtime.request.json"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post("http://"+serverAddr+"/v1/screenings", "application/json", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatalf("POST /v1/screenings failed: %v", err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d (body: %s)", resp.StatusCode, responseBody)
	}
	if !bytes.Contains(responseBody, []byte(`"status":"candidates_retrieved"`)) {
		t.Fatalf("expected status candidates_retrieved (not blocked), got: %s", responseBody)
	}
}

func TestNoArgsExitsWithCode2(t *testing.T) {
	_, stderr, code := run()
	if code != 2 {
		t.Fatalf("expected exit code 2 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: screening-api-v8e")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnknownCommandExitsWithCode2(t *testing.T) {
	_, stderr, code := run("bogus-command")
	if code != 2 {
		t.Fatalf("expected exit code 2 for an unknown command, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: screening-api-v8e")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestCheckWithoutActivationFailsCleanlyWithCode1(t *testing.T) {
	upstreamURL, cleanup := startFixtureUpstream(t)
	defer cleanup()

	config := buildConfig(t, "127.0.0.1:0", upstreamURL, t.TempDir()) // fresh, never-activated state dir
	_, stderr, code := run("check", "-config", config)
	if code != 1 {
		t.Fatalf("expected exit code 1 for a never-activated state directory, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a never-activated state directory: %s", stderr)
	}
}

func TestMissingConfigFileFailsCleanly(t *testing.T) {
	_, stderr, code := run("check", "-config", "/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing config file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing config file: %s", stderr)
	}
}
