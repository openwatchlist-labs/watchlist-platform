// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// Deliberately deferred throughout the #15 work pending the #14 decision
// on whether these retired versions are worth further investment - added
// now on explicit request.
//
// Important architectural finding, different from current
// cmd/screening-api: this version talks to its candidate source via an
// HTTP upstream client (screeningapi.NewPhase8DHTTPUpstream), not the
// Rust catalog-mmap runtime. It even ships its own "fixture-upstream"
// subcommand - a minimal HTTP server backed by static response
// fixtures - which test/golden/screening-api-v8d/README.md confirms is
// exactly how this package's own internal tests work ("the readiness
// upstream URL is dynamically allocated during the test"). That means,
// unlike current screening-api (failure modes only, blocked on #13's
// Rust question), this version gets a genuine full HTTP round trip:
// spin up fixture-upstream, spin up "serve" pointed at it, POST a real
// request, and confirm the response matches the committed golden file
// exactly (aside from randomly-generated correlation_id/request_sha256
// fields).
//
// Ports are allocated dynamically via net.Listen("tcp", "127.0.0.1:0")
// and immediately released before handing the address to each
// subprocess, rather than hardcoded - avoids any conflict with other
// processes or parallel test runs, consistent with best practice for
// subprocess-based HTTP tests.
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

var binaryPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "screening-api-v8d-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "screening-api-v8d")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/screening-api-v8d for testing: " + err.Error() + "\n" + string(out))
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
	panic("screening-api-v8d did not run at all (not just a nonzero exit): " + err.Error())
}

// freeAddr allocates an OS-assigned free port on 127.0.0.1 and releases
// it immediately, returning the address string to hand to a subprocess.
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

// waitReady polls the given URL until it responds or the timeout elapses.
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

// startFixtureUpstream launches the binary's own "fixture-upstream"
// subcommand as a background process and returns its base URL plus a
// cleanup function.
func startFixtureUpstream(t *testing.T) (baseURL string, cleanup func()) {
	t.Helper()
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	addr := freeAddr(t)
	cmd := exec.Command(binaryPath, "fixture-upstream",
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

// buildConfig writes a config JSON pointed at the given upstream, using
// real committed fixtures for the scoring policy and projection
// registry.
func buildConfig(t *testing.T, listenAddr, upstreamBaseURL string) string {
	t.Helper()
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	config := map[string]any{
		"listen_address":           listenAddr,
		"upstream_base_url":        upstreamBaseURL,
		"scoring_policy_path":      filepath.Join(repoRoot, "configs/scoring/candidate-scoring-r1.json"),
		"projection_registry_path": filepath.Join(repoRoot, "test/fixtures/screening-api-v8d/projection-registry.json"),
		"idempotency_directory":    filepath.Join(t.TempDir(), "idempotency"),
		"max_body_bytes":           1048576,
		"max_batch_items":          100,
		"request_timeout_millis":   5000,
		"default_lineage": map[string]any{
			"provider":          "test",
			"catalog_id":        "test-catalog",
			"component_id":      "test-component",
			"component_version": "v1",
			"activation_id":     "test-activation",
			// Must match the scoring policy's own normalization profile
			// (unicode-upper-alnum-space-v1) - verified this requirement
			// by running "check" first and reading the actual mismatch
			// error, not assumed.
			"normalization_profile": "unicode-upper-alnum-space-v1",
		},
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
	stdout, stderr, code := run("check", "-config", config)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"status": "ok"`)) {
		t.Fatalf("expected status ok, got: %s", stdout)
	}
}

// TestHappyPath_FullHTTPRoundTrip is the real proof: fixture-upstream up,
// serve pointed at it, POST a real request, and confirm the response
// matches the committed golden file exactly (aside from
// randomly-generated correlation_id/request_sha256).
func TestHappyPath_FullHTTPRoundTrip(t *testing.T) {
	upstreamURL, cleanupUpstream := startFixtureUpstream(t)
	defer cleanupUpstream()

	serverAddr := freeAddr(t)
	config := buildConfig(t, serverAddr, upstreamURL)

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
	waitReady(t, "http://"+serverAddr+"/readyz", 5*time.Second)

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

	var got map[string]any
	if err := json.Unmarshal(responseBody, &got); err != nil {
		t.Fatalf("response was not valid JSON: %v\nbody: %s", err, responseBody)
	}
	goldenBytes, err := os.ReadFile(filepath.Join(repoRoot, "test/golden/screening-api-v8d/realtime.response.json"))
	if err != nil {
		t.Fatal(err)
	}
	var golden map[string]any
	if err := json.Unmarshal(goldenBytes, &golden); err != nil {
		t.Fatal(err)
	}

	// correlation_id and request_sha256 are randomly generated per run -
	// exclude them from the comparison, matching the golden README's own
	// stated exception ("except that the readiness upstream URL is
	// dynamically allocated during the test and is checked separately").
	for _, field := range []string{"correlation_id", "request_sha256"} {
		delete(got, field)
		delete(golden, field)
	}
	gotJSON, _ := json.Marshal(got)
	goldenJSON, _ := json.Marshal(golden)
	if string(gotJSON) != string(goldenJSON) {
		t.Fatalf("response does not match golden fixture (aside from excluded random fields)\ngot:    %s\ngolden: %s", gotJSON, goldenJSON)
	}
}

func TestNoArgsFailsWithUsageMessage(t *testing.T) {
	_, stderr, code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: screening-api-v8d")) {
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

func TestCheckMissingConfigFlagFailsCleanly(t *testing.T) {
	_, stderr, code := run("check")
	if code != 1 {
		t.Fatalf("expected exit code 1 when --config is missing, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("--config is required")) {
		t.Fatalf("expected a '--config is required' message, got %q", stderr)
	}
}

func TestCheckMissingConfigFileFailsCleanly(t *testing.T) {
	_, stderr, code := run("check", "-config", "/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing config file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing config file: %s", stderr)
	}
}

func TestFixtureUpstreamMissingFlagsFailsCleanly(t *testing.T) {
	_, stderr, code := run("fixture-upstream")
	if code != 1 {
		t.Fatalf("expected exit code 1 when --single-response/--batch-response are missing, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("--single-response and --batch-response are required")) {
		t.Fatalf("expected a required-flags message, got %q", stderr)
	}
}
