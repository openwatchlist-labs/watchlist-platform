// See cmd/platform-api/main_test.go for the black-box subprocess pattern,
// and cmd/alert-case/main_test.go for this project's other stateful
// command (this one follows the same replay pattern: a --state-dir that
// persists across invocations, verified by actually round-tripping the
// same input twice and checking replayed flips false -> true).
//
// No Rust dependency. "submit" is not covered - it makes a real HTTP
// call to an --alert-case-url, which would mean standing up a live
// alert-case HTTP server as test infrastructure; out of scope for this
// batch, consistent with skipping cmd/alert-case's "migrate" (which
// needs live PostgreSQL) for the same reason - both are real integration
// tests waiting to be written, not unit-level black-box tests like the
// rest of this file.
package main_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "vendor-adapter-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "vendor-adapter")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/vendor-adapter for testing: " + err.Error() + "\n" + string(out))
	}

	os.Exit(m.Run())
}

func run(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = "../.." // repo root, so relative fixture/profile paths resolve
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
	panic("vendor-adapter did not run at all (not just a nonzero exit): " + err.Error())
}

const actimizeProfile = "configs/vendor-adapters/actimize-reference-json-v1.json"
const actimizeAlert = "test/fixtures/vendor-adapters/actimize-alert.json"

func TestHappyPath_Profiles(t *testing.T) {
	stdout, stderr, code := run("profiles")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"adapter_id":"actimize-reference-json-v1"`)) {
		t.Fatalf("expected the actimize profile listed, got: %s", stdout)
	}
}

func TestHappyPath_CheckProfile(t *testing.T) {
	stdout, stderr, code := run("check-profile", "-profile", actimizeProfile)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	var out struct {
		AdapterID string `json:"adapter_id"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("output was not valid JSON: %v\noutput: %s", err, stdout)
	}
	if out.AdapterID != "actimize-reference-json-v1" || out.Status != "ok" {
		t.Fatalf("unexpected output: %s", stdout)
	}
}

func TestHappyPath_ConvertStateless(t *testing.T) {
	stdout, stderr, code := run("convert", "-profile", actimizeProfile, actimizeAlert)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"adapter_id":"actimize-reference-json-v1"`)) {
		t.Fatalf("expected the envelope to reference the adapter, got: %s", stdout)
	}
}

func TestHappyPath_ConvertBatch(t *testing.T) {
	stdout, stderr, code := run("batch", "-profile", actimizeProfile, actimizeAlert)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version":"openwatchlist.vendor-adapter-batch.v1"`)) {
		t.Fatalf("expected a batch envelope, got: %s", stdout)
	}
}

// TestHappyPath_IngestReplayVerify exercises the stateful path: ingest,
// then ingest the SAME input again against the same state dir (must
// replay, not double-process), then verify the store's own consistency
// check.
func TestHappyPath_IngestReplayVerify(t *testing.T) {
	stateDir := t.TempDir()

	stdout, stderr, code := run("ingest", "-profile", actimizeProfile, "-state-dir", stateDir, actimizeAlert)
	if code != 0 {
		t.Fatalf("ingest: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	var first struct {
		Replayed bool `json:"replayed"`
	}
	if err := json.Unmarshal([]byte(stdout), &first); err != nil {
		t.Fatalf("ingest output was not valid JSON: %v\noutput: %s", err, stdout)
	}
	if first.Replayed {
		t.Fatal("expected replayed=false on first ingest")
	}

	stdout, stderr, code = run("ingest", "-profile", actimizeProfile, "-state-dir", stateDir, actimizeAlert)
	if code != 0 {
		t.Fatalf("replay ingest: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	var second struct {
		Replayed bool `json:"replayed"`
	}
	_ = json.Unmarshal([]byte(stdout), &second)
	if !second.Replayed {
		t.Fatalf("expected replayed=true when the same input is ingested again with the same state dir, got: %s", stdout)
	}

	stdout, stderr, code = run("verify", "-state-dir", stateDir)
	if code != 0 {
		t.Fatalf("verify: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	var status struct {
		Status      string `json:"status"`
		RecordCount int    `json:"record_count"`
	}
	if err := json.Unmarshal([]byte(stdout), &status); err != nil {
		t.Fatalf("verify output was not valid JSON: %v\noutput: %s", err, stdout)
	}
	if status.Status != "ok" || status.RecordCount != 1 {
		t.Fatalf("expected status=ok and record_count=1 after one (replayed) ingest, got: %s", stdout)
	}
}

func TestNoArgsFailsWithUsageMessageAndCode2(t *testing.T) {
	_, stderr, code := run()
	if code != 2 {
		t.Fatalf("expected exit code 2 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("vendor-adapter profiles|check-profile")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnknownCommandExitsWithCode2(t *testing.T) {
	_, stderr, code := run("bogus-command")
	if code != 2 {
		t.Fatalf("expected exit code 2 for an unknown command, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("vendor-adapter profiles|check-profile")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestCheckProfileMissingFileFailsCleanlyWithCode1(t *testing.T) {
	_, stderr, code := run("check-profile", "-profile", "/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing profile file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing profile file: %s", stderr)
	}
}

func TestConvertMissingInputFileArgFailsCleanly(t *testing.T) {
	_, stderr, code := run("convert", "-profile", actimizeProfile)
	if code != 1 {
		t.Fatalf("expected exit code 1 when the input file argument is missing, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("input JSON file is required")) {
		t.Fatalf("expected an 'input JSON file is required' message, got %q", stderr)
	}
}

func TestIngestMissingStateDirFailsCleanly(t *testing.T) {
	_, stderr, code := run("ingest", "-profile", actimizeProfile, actimizeAlert)
	if code != 1 {
		t.Fatalf("expected exit code 1 when --state-dir is missing for ingest, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("--state-dir is required")) {
		t.Fatalf("expected a '--state-dir is required' message, got %q", stderr)
	}
}
