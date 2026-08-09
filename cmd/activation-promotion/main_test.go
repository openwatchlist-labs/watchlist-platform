// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// This is the most complex remaining cmd/ package (12 subcommands, a
// full canary/shadow-testing promotion lifecycle). Scope, stated
// honestly: this covers the read/record-oriented subcommands (status,
// verify-audit, compare-shadow, summarize-shadow) using the real,
// pre-populated promotion state committed at
// test/fixtures/activation-promotion/state/ - the golden README there
// explicitly says this fixture "is only a portable configuration/check
// fixture; it is never promoted in place", which matches this file's
// approach exactly.
//
// NOT covered: stage/prepare/evaluate/start-canary/ack/promote/rollback/
// recover - the full lifecycle mutation commands. Advancing the fixture's
// "prepared" phase forward through evaluate -> start-canary -> ack ->
// promote, or starting a fresh stage+prepare cycle from a real
// scoring-activation candidate, is a bigger, separate integration test
// worth writing deliberately - not forced into this pass.
//
// Every subcommand needs BOTH --activation-state-dir and
// --promotion-state-dir (promotionManager wraps a scoringactivation.Manager
// regardless of which command runs) - confirmed the promotion state
// fixture is self-contained and works fine against a completely empty,
// fresh --activation-state-dir before relying on that.
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
	dir, err := os.MkdirTemp("", "activation-promotion-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "activation-promotion")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/activation-promotion for testing: " + err.Error() + "\n" + string(out))
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
	panic("activation-promotion did not run at all (not just a nonzero exit): " + err.Error())
}

const (
	fixtureIntentID       = "promotion-phase8f-fixture"
	currentResponseFile   = "test/fixtures/activation-promotion/current.response.json"
	candidateResponseFile = "test/fixtures/activation-promotion/candidate.response.json"
)

// freshPromotionState copies the real, pre-populated promotion fixture
// state into a scratch temp dir so any (unlikely, given the subcommands
// tested here are read/record-oriented) mutation doesn't affect the
// committed fixture or other tests.
func freshPromotionState(t *testing.T) (activationState, promotionState string) {
	t.Helper()
	dst := t.TempDir()
	src, err := filepath.Abs("../../test/fixtures/activation-promotion/state")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cp", "-r", src+"/.", dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to copy fixture promotion state: %v\n%s", err, out)
	}
	return t.TempDir(), dst
}

func TestHappyPath_Status(t *testing.T) {
	activationState, promotionState := freshPromotionState(t)
	stdout, stderr, code := run("status", "-activation-state-dir", activationState, "-promotion-state-dir", promotionState)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"intent_id":"`+fixtureIntentID+`"`)) {
		t.Fatalf("expected the fixture's intent_id in status output, got: %s", stdout)
	}
}

func TestHappyPath_VerifyAudit(t *testing.T) {
	activationState, promotionState := freshPromotionState(t)
	stdout, stderr, code := run("verify-audit", "-activation-state-dir", activationState, "-promotion-state-dir", promotionState)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"status":"ok"`)) {
		t.Fatalf("expected status ok, got: %s", stdout)
	}
}

func TestHappyPath_CompareShadow(t *testing.T) {
	activationState, promotionState := freshPromotionState(t)
	stdout, stderr, code := run("compare-shadow",
		"-activation-state-dir", activationState, "-promotion-state-dir", promotionState,
		"-intent-id", fixtureIntentID, "-correlation-id", "test-corr-001",
		"-current-response", currentResponseFile, "-candidate-response", candidateResponseFile,
		"-observed-at", "2026-07-14T22:05:00Z")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"schema_version":"openwatchlist.activation-shadow-observation.v1"`)) {
		t.Fatalf("expected a shadow observation result, got: %s", stdout)
	}
}

func TestHappyPath_SummarizeShadowAfterObservation(t *testing.T) {
	// Chains compare-shadow (which records an observation) into
	// summarize-shadow reading it back, proving the two commands
	// genuinely interact through the shared promotion state, not just
	// that each runs in isolation without error.
	activationState, promotionState := freshPromotionState(t)
	_, stderr, code := run("compare-shadow",
		"-activation-state-dir", activationState, "-promotion-state-dir", promotionState,
		"-intent-id", fixtureIntentID, "-correlation-id", "test-corr-002",
		"-current-response", currentResponseFile, "-candidate-response", candidateResponseFile,
		"-observed-at", "2026-07-14T22:06:00Z")
	if code != 0 {
		t.Fatalf("setup compare-shadow failed: exit %d (stderr: %q)", code, stderr)
	}

	stdout, stderr, code := run("summarize-shadow", "-activation-state-dir", activationState, "-promotion-state-dir", promotionState, "-intent-id", fixtureIntentID)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"observation_count":1`)) {
		t.Fatalf("expected observation_count 1 after recording exactly one observation, got: %s", stdout)
	}
}

func TestNoArgsExitsWithCode2(t *testing.T) {
	_, stderr, code := run()
	if code != 2 {
		t.Fatalf("expected exit code 2 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: activation-promotion")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnknownCommandExitsWithCode2(t *testing.T) {
	_, stderr, code := run("bogus-command")
	if code != 2 {
		t.Fatalf("expected exit code 2 for an unknown command, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: activation-promotion")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestStatusWithMissingPromotionStateFailsCleanlyWithCode1(t *testing.T) {
	_, stderr, code := run("status", "-activation-state-dir", t.TempDir(), "-promotion-state-dir", t.TempDir())
	if code != 1 {
		t.Fatalf("expected exit code 1 for an empty/uninitialized promotion state dir, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for an uninitialized promotion state: %s", stderr)
	}
}

func TestCompareShadowMissingResponseFileFailsCleanlyWithCode1(t *testing.T) {
	activationState, promotionState := freshPromotionState(t)
	_, stderr, code := run("compare-shadow",
		"-activation-state-dir", activationState, "-promotion-state-dir", promotionState,
		"-intent-id", fixtureIntentID, "-correlation-id", "test-corr-003",
		"-current-response", "/definitely/does/not/exist.json", "-candidate-response", candidateResponseFile,
		"-observed-at", "2026-07-14T22:05:00Z")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing --current-response file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing response file: %s", stderr)
	}
}
