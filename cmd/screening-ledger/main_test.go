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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningledger"
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

// policyFixture signs a verification policy for the real committed
// fixture ledger (ADR-0007 D10) and writes both the signed policy and
// the trust-root public key to fresh temp files, returning their paths.
// allowUnanchored controls the policy's own allow_unanchored field --
// D12's double gate also requires --verification-mode
// historical-unanchored on the command line, which callers pass
// separately.
//
// The real fixture's event chain has frozen-prefix length 0 (ADR-0007
// §6.1 correction note: Stage 1 regenerated its one event in place under
// v2 rather than preserving a genuine v1 prefix), so genesis sequence 1
// with a v2 floor is the correct policy for it, not a special case.
func policyFixture(t *testing.T, allowUnanchored bool) (policyPath, pubKeyPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := screeningledger.VerificationPolicy{
		SchemaVersion:        screeningledger.VerificationPolicySchemaV2,
		LedgerID:             fixtureLedgerID,
		MinEventSchema:       screeningledger.EventSchemaV2,
		MinAuditSchema:       screeningledger.AuditSchemaV2,
		GenesisEventSequence: 1,
		GenesisAuditSequence: 1,
		AllowUnanchored:      allowUnanchored,
	}
	signed, err := screeningledger.SignVerificationPolicy(policy, priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	policyPath = filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	pubKeyPath = filepath.Join(dir, "policy-public-key.hex")
	if err := os.WriteFile(pubKeyPath, []byte(hex.EncodeToString(pub)), 0o640); err != nil {
		t.Fatal(err)
	}
	return policyPath, pubKeyPath
}

func TestHappyPath_Status(t *testing.T) {
	ledgerDir := freshLedgerCopy(t)
	policyPath, pubKeyPath := policyFixture(t, true)
	stdout, stderr, code := run("status",
		"--ledger-dir", ledgerDir, "--key-file", keyFile, "--ledger-id", fixtureLedgerID,
		"--policy-file", policyPath, "--policy-public-key-file", pubKeyPath,
		// No --postgres-dsn-env: exercising the F1 defense the way
		// ADR-0007 D9 designed it to run, with no database at all.
		// That requires explicitly-selected historical-unanchored mode
		// (D12's double gate; the policy above sets allow_unanchored
		// too) -- the default `anchored` mode's no-database behavior is
		// TestVerifyNoDatabaseExitsNonZeroInAnchoredMode below.
		"--verification-mode", "historical-unanchored")
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

// TestHappyPath_Verify is the functioning no-database path: explicit
// historical-unanchored mode, a policy that permits it, and exit 0 --
// ADR-0007 D9's decisive property that the F1 defense (EA1-EA3, checked
// here) needs no Postgres. The DEFAULT (anchored) mode with no database
// is the opposite case, and is a hard failure -- see
// TestVerifyNoDatabaseExitsNonZeroInAnchoredMode.
//
// The top-level "status" field reads "unavailable", not "ok" --
// ADR-0007 Addendum 2 D24 (F-C): main.go no longer hard-codes "ok" for
// every nil-error outcome. This run genuinely did not check an anchor (no
// --postgres-dsn-env, explicit historical-unanchored mode), and the
// top-level field now says so, distinguishable from a genuinely verified
// anchor without a caller needing to read the sibling anchor_status
// field specifically.
func TestHappyPath_Verify(t *testing.T) {
	ledgerDir := freshLedgerCopy(t)
	policyPath, pubKeyPath := policyFixture(t, true)
	stdout, stderr, code := run("verify",
		"--ledger-dir", ledgerDir, "--key-file", keyFile, "--ledger-id", fixtureLedgerID,
		"--policy-file", policyPath, "--policy-public-key-file", pubKeyPath,
		"--verification-mode", "historical-unanchored")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"status":"unavailable"`)) {
		t.Fatalf("expected status unavailable (ADR-0007 Addendum 2 D24: derived from anchor_status, not hard-coded ok), got: %s", stdout)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"anchor_status":"unavailable"`)) {
		t.Fatalf("expected anchor_status unavailable (no --postgres-dsn-env given), got: %s", stdout)
	}
	if !bytes.Contains([]byte(stdout), []byte(`"verification_mode":"historical-unanchored"`)) {
		t.Fatalf("expected verification_mode historical-unanchored, got: %s", stdout)
	}
}

// TestVerifyRejectsAllowGenesisFlag is ADR-0007 Addendum 2 D24 (F-C):
// --allow-genesis has no legitimate meaning on verify -- its only effect,
// before this fix, was converting AnchorStatusAbsent (the exact and only
// signature of an anchor-table wipe, CAP §7.4) into success. Passing it
// here must now be a clean, named error, not a silently ignored flag.
func TestVerifyRejectsAllowGenesisFlag(t *testing.T) {
	ledgerDir := freshLedgerCopy(t)
	policyPath, pubKeyPath := policyFixture(t, true)
	_, stderr, code := run("verify",
		"--ledger-dir", ledgerDir, "--key-file", keyFile, "--ledger-id", fixtureLedgerID,
		"--policy-file", policyPath, "--policy-public-key-file", pubKeyPath,
		"--verification-mode", "historical-unanchored", "--allow-genesis", "true")
	if code == 0 {
		t.Fatal("expected a nonzero exit code when --allow-genesis is passed to verify (ADR-0007 Addendum 2 D24)")
	}
	if !bytes.Contains([]byte(stderr), []byte("--allow-genesis has no effect on this command")) {
		t.Fatalf("expected an error naming --allow-genesis as rejected, got: %q", stderr)
	}
}

// TestVerifyNoDatabaseExitsNonZeroInAnchoredMode is D20's stated
// companion obligation for D12: verify with no database now exits
// non-zero in the default `anchored` mode, replacing the previous
// "status":"partial" at exit 0 -- ADR-0007 Consequences: "I could not
// check" and "I checked and it was fine" must not share an outcome.
func TestVerifyNoDatabaseExitsNonZeroInAnchoredMode(t *testing.T) {
	ledgerDir := freshLedgerCopy(t)
	policyPath, pubKeyPath := policyFixture(t, true)
	_, stderr, code := run("verify",
		"--ledger-dir", ledgerDir, "--key-file", keyFile, "--ledger-id", fixtureLedgerID,
		"--policy-file", policyPath, "--policy-public-key-file", pubKeyPath)
	// No --verification-mode given: defaults to anchored, and no
	// --postgres-dsn-env is given either, so VerifyAnchored must fail.
	if code == 0 {
		t.Fatal("expected a nonzero exit code when verifying in anchored mode with no database configured (ADR-0007 D12)")
	}
	if !bytes.Contains([]byte(stderr), []byte("anchored mode requires a database connection")) {
		t.Fatalf("expected a message naming the missing anchored-mode database requirement, got: %q", stderr)
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
