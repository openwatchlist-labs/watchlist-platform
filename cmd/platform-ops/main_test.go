// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// The real committed production config example
// (configs/production/phase9g-example.json) already resolves cleanly
// against this repo's committed fixtures - check-config, readiness, and
// quota all work directly against it with zero setup, verified by
// running each before writing assertions. The outbox-* subcommands are
// self-contained (just need a fresh --state directory) and get a real
// enqueue -> claim -> complete chain, proven end to end, not just each
// command run in isolation.
//
// Scope: backup-create/backup-verify/backup-restore and
// sync-vendor-adapter/sync-outbox are not covered - the former need a
// real backup target/restore flow and the latter integrate with live
// vendor-adapter/outbox HTTP endpoints, both a bigger integration-test
// surface than the rest of this file, consistent with skipping
// cmd/alert-case's "migrate" and cmd/vendor-adapter's "submit" for
// similar reasons.
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
	dir, err := os.MkdirTemp("", "platform-ops-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "platform-ops")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/platform-ops for testing: " + err.Error() + "\n" + string(out))
	}

	os.Exit(m.Run())
}

func run(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = "../.." // repo root, so the real production config's relative paths resolve
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
	panic("platform-ops did not run at all (not just a nonzero exit): " + err.Error())
}

const productionConfig = "configs/production/phase9g-example.json"

func TestHappyPath_CheckConfig(t *testing.T) {
	stdout, stderr, code := run("check-config", "-config", productionConfig)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"status":"ok"`)) {
		t.Fatalf("expected status ok, got: %s", stdout)
	}
}

func TestHappyPath_Readiness(t *testing.T) {
	stdout, stderr, code := run("readiness", "-config", productionConfig)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"status":"ok"`)) {
		t.Fatalf("expected status ok, got: %s", stdout)
	}
}

func TestHappyPath_Quota(t *testing.T) {
	stdout, stderr, code := run("quota", "-config", productionConfig, "-tenant", "tenant-a")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"tenant_id":"tenant-a"`)) {
		t.Fatalf("expected a tenant-a quota result, got: %s", stdout)
	}
}

func TestHappyPath_RenderConfig(t *testing.T) {
	out := filepath.Join(t.TempDir(), "rendered.json")
	stdout, stderr, code := run("render-config", "-input", productionConfig,
		"-runtime-root", t.TempDir(), "-output", out)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"status":"ok"`)) {
		t.Fatalf("expected status ok, got: %s", stdout)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("expected rendered config file to exist: %v", err)
	}
}

func TestHappyPath_RenderQuota(t *testing.T) {
	out := filepath.Join(t.TempDir(), "quota-out.json")
	stdout, stderr, code := run("render-quota", "-input", "configs/production/tenant-quotas-r1.json", "-output", out)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"status":"ok"`)) {
		t.Fatalf("expected status ok, got: %s", stdout)
	}
}

func TestHappyPath_FullOutboxLifecycle(t *testing.T) {
	state := t.TempDir()
	payload := filepath.Join(t.TempDir(), "payload.json")
	if err := os.WriteFile(payload, []byte(`{"hello": "world"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := run("outbox-enqueue", "-state", state, "-topic", "test-topic",
		"-tenant", "tenant-a", "-key", "msg-1", "-input", payload, "-now", "2026-07-14T22:00:00Z")
	if code != 0 {
		t.Fatalf("enqueue: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	var enqueued struct {
		Message struct {
			MessageID string `json:"message_id"`
		} `json:"message"`
	}
	if err := json.Unmarshal([]byte(stdout), &enqueued); err != nil {
		t.Fatalf("enqueue output was not valid JSON: %v\noutput: %s", err, stdout)
	}
	messageID := enqueued.Message.MessageID
	if messageID == "" {
		t.Fatal("expected a non-empty message_id")
	}

	stdout, stderr, code = run("outbox-claim", "-state", state, "-now", "2026-07-14T22:01:00Z")
	if code != 0 {
		t.Fatalf("claim: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	var claimed struct {
		LeaseToken string `json:"lease_token"`
	}
	if err := json.Unmarshal([]byte(stdout), &claimed); err != nil {
		t.Fatalf("claim output was not valid JSON: %v\noutput: %s", err, stdout)
	}
	if claimed.LeaseToken == "" {
		t.Fatal("expected a non-empty lease_token")
	}

	_, stderr, code = run("outbox-complete", "-state", state, "-id", messageID, "-token", claimed.LeaseToken, "-now", "2026-07-14T22:01:10Z")
	if code != 0 {
		t.Fatalf("complete: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}

	stdout, stderr, code = run("outbox-status", "-state", state)
	if code != 0 {
		t.Fatalf("status: expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"completed_count":1`)) {
		t.Fatalf("expected completed_count 1 after the full lifecycle, got: %s", stdout)
	}
}

func TestNoArgsFailsWithUsageMessage(t *testing.T) {
	_, stderr, code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: platform-ops")) {
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

func TestMissingConfigFileFailsCleanly(t *testing.T) {
	_, stderr, code := run("check-config", "-config", "/definitely/does/not/exist.json")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a missing config file, got %d (stderr: %q)", code, stderr)
	}
	if bytes.Contains([]byte(stderr), []byte("panic:")) {
		t.Fatalf("got a panic instead of a clean error for a missing config file: %s", stderr)
	}
}
