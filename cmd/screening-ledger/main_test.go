// See cmd/platform-api/main_test.go for the black-box subprocess pattern.
// Reuses the real, pre-populated ledger state committed at
// test/fixtures/screening-ledger/state/ (one real event, snapshots, and
// head.json) rather than trying to construct ledger state from scratch -
// but copies it into a fresh temp dir per test first, since some
// commands (purge, sync) mutate state and a shared fixture directory
// would make tests interfere with each other. The committed
// state/ledger-id file pins the expected --ledger-id
// ("screening-api-v8g-example") - discovered by reading that file rather
// than guessing, after an initial attempt without it failed with
// "configured ledger ID does not match durable ledger-id".
//
// "migrate"/"sync"/"import-audit" (need a live PostgreSQL DSN reachable
// via pgx) and "replay" (needs a live --backend-url HTTP endpoint) are
// not covered - the same category of real-infrastructure-dependent
// subcommand already skipped for cmd/alert-case's "migrate" and
// cmd/vendor-adapter's "submit". See internal/screeningledger/
// postgres_pgx_test.go for the PostgreSQL-backed coverage, gated on
// OWL_MIGRATOR_DATABASE_URL.
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
	dir, err := os.MkdirTemp("", "screening-ledger-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "screening-ledger")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build cmd/screening-ledger for testing: " + err.Error() + "\n" + string(out))
	}

	os.Exit(m.Run())
}

func run(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = "../.." // repo root, so relative fixture key paths resolve
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
	panic("screening-ledger did not run at all (not just a nonzero exit): " + err.Error())
}

const (
	keyFile         = "test/fixtures/screening-ledger/snapshot-key.hex"
	fixtureLedger   = "test/fixtures/screening-ledger/state"
	fixtureLedgerID = "screening-api-v8g-example"
	fixtureEventID  = "9c15117914fe574d9af9b89279417f1312537b55f8f7462d320e1179515b2236"
)

// freshLedgerCopy copies the real, pre-populated fixture ledger state
// into a scratch temp directory so mutating commands don't affect other
// tests or the committed fixture itself.
func freshLedgerCopy(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	src, err := filepath.Abs(filepath.Join("../..", fixtureLedger))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cp", "-r", src+"/.", dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to copy fixture ledger state: %v\n%s", err, out)
	}
	return dst
}

func TestHappyPath_Status(t *testing.T) {
	ledgerDir := freshLedgerCopy(t)
	stdout, stderr, code := run("status", "--ledger-dir", ledgerDir, "--key-file", keyFile, "--ledger-id", fixtureLedgerID)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	// ADR-0007 D4: the fixture was regenerated with a relabeled v2 event
	// plus a v2 genesis marker appended after it (event count 2), where
	// it used to be the single pre-D2 event (event count 1) -- see the
	// ADR-0007 §6 correction note. A green run here after regeneration is
	// evidence the migration executed, per the ADR's own "fixture is the
	// tripwire" framing.
	if !bytes.Contains([]byte(stdout), []byte(`"event_count":2`)) {
		t.Fatalf("expected event_count 2 from the regenerated v2 fixture state, got: %s", stdout)
	}
}

func TestHappyPath_Verify(t *testing.T) {
	ledgerDir := freshLedgerCopy(t)
	stdout, stderr, code := run("verify", "--ledger-dir", ledgerDir, "--key-file", keyFile, "--ledger-id", fixtureLedgerID)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	// ADR-0007 §5.3 point 4 / Consequences: verify without a database
	// configured (no --postgres-dsn-env here) is honestly reported as
	// "partial", not "ok" -- it fully checks the file chain (including
	// the frozen-prefix/genesis-boundary rules) but cannot cross-check
	// the anchor. See internal/screeningledger/anchor_pgx_test.go for the
	// anchor-aware "ok" case, which needs a real Postgres connection.
	if !bytes.Contains([]byte(stdout), []byte(`"status":"partial"`)) {
		t.Fatalf("expected status partial (no --postgres-dsn-env given), got: %s", stdout)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"anchor_status":"unavailable"`)) {
		t.Fatalf("expected anchor_status unavailable, got: %s", stdout)
	}
}

func TestHappyPath_Export(t *testing.T) {
	ledgerDir := freshLedgerCopy(t)
	outputPath := filepath.Join(t.TempDir(), "export.json")
	stdout, stderr, code := run("export",
		"--ledger-dir", ledgerDir, "--key-file", keyFile, "--ledger-id", fixtureLedgerID,
		"--event-id", fixtureEventID, "--output", outputPath)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"event_id":"`+fixtureEventID+`"`)) {
		t.Fatalf("expected the export manifest to reference the fixture event, got: %s", stdout)
	}
}

func TestNoArgsFailsWithUsageMessage(t *testing.T) {
	_, stderr, code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1 with no args, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("usage: screening-ledger")) {
		t.Fatalf("expected usage message on stderr, got %q", stderr)
	}
}

func TestUnknownCommandFailsCleanly(t *testing.T) {
	_, stderr, code := run("bogus-command")
	if code != 1 {
		t.Fatalf("expected exit code 1 for an unknown command, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("unknown command: bogus-command")) {
		t.Fatalf("expected an 'unknown command' message, got %q", stderr)
	}
}

func TestMissingRequiredFlagFailsCleanly(t *testing.T) {
	_, stderr, code := run("status", "--key-file", keyFile)
	if code != 1 {
		t.Fatalf("expected exit code 1 when --ledger-dir is missing, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("--ledger-dir is required")) {
		t.Fatalf("expected a '--ledger-dir is required' message, got %q", stderr)
	}
}

func TestWrongLedgerIDFailsCleanly(t *testing.T) {
	ledgerDir := freshLedgerCopy(t)
	_, stderr, code := run("status", "--ledger-dir", ledgerDir, "--key-file", keyFile, "--ledger-id", "wrong-ledger-id")
	if code != 1 {
		t.Fatalf("expected exit code 1 for a mismatched --ledger-id, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stderr), []byte("ledger ID")) {
		t.Fatalf("expected a ledger-ID-mismatch message, got %q", stderr)
	}
}
