// Black-box subprocess tests, per docs/CMD_TESTING_PATTERN.md.
package main_test

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningledger"
)

var binaryPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "screening-ledger-policy-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	binaryPath = filepath.Join(dir, "screening-ledger-policy")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("failed to build: " + err.Error() + "\n" + string(out))
	}
	os.Exit(m.Run())
}

func run(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else {
			code = -1
		}
	}
	return outBuf.String(), errBuf.String(), code
}

func TestNoArguments(t *testing.T) {
	_, stderr, code := run()
	if code == 0 {
		t.Fatal("expected nonzero exit with no arguments")
	}
	if !strings.Contains(stderr, "usage:") {
		t.Fatalf("expected a usage message, got stderr=%q", stderr)
	}
}

func TestUnknownCommand(t *testing.T) {
	_, stderr, code := run("bogus")
	if code == 0 {
		t.Fatal("expected nonzero exit for an unknown command")
	}
	if !strings.Contains(stderr, "unknown command") {
		t.Fatalf("expected an unknown-command error, got stderr=%q", stderr)
	}
}

func TestKeygenSignFingerprintRoundTrip(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "policy-signing-key.hex")
	pubPath := filepath.Join(dir, "policy-public-key.hex")

	stdout, stderr, code := run("keygen", "--private-key-file", privPath, "--public-key-file", pubPath)
	if code != 0 {
		t.Fatalf("keygen: exit %d, stderr=%q", code, stderr)
	}
	printedPub := strings.TrimSpace(stdout)
	if printedPub == "" {
		t.Fatal("keygen printed no public key to stdout")
	}
	privInfo, err := os.Stat(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if privInfo.Mode().Perm() != 0o400 {
		t.Fatalf("private key file mode = %v, want 0400", privInfo.Mode().Perm())
	}
	writtenPub, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(writtenPub)) != printedPub {
		t.Fatalf("public key file %q does not match the printed public key %q", strings.TrimSpace(string(writtenPub)), printedPub)
	}

	policyPath := filepath.Join(dir, "policy.json")
	policy := screeningledger.VerificationPolicy{
		SchemaVersion:        screeningledger.VerificationPolicySchemaV2,
		LedgerID:             "screening-ledger-policy-test",
		MinEventSchema:       screeningledger.EventSchemaV2,
		MinAuditSchema:       screeningledger.AuditSchemaV2,
		GenesisEventSequence: 1,
		GenesisAuditSequence: 1,
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	signedPath := filepath.Join(dir, "policy.signed.json")
	_, stderr, code = run("sign", "--policy-file", policyPath, "--private-key-file", privPath, "--output", signedPath)
	if code != 0 {
		t.Fatalf("sign: exit %d, stderr=%q", code, stderr)
	}

	loaded, _, err := screeningledger.LoadSignedVerificationPolicy(signedPath, mustDecodeHexPublicKey(t, pubPath))
	if err != nil {
		t.Fatalf("the signed envelope this binary produced did not verify under LoadSignedVerificationPolicy: %v", err)
	}
	if loaded.LedgerID != policy.LedgerID {
		t.Fatalf("round-tripped policy ledger_id = %q, want %q", loaded.LedgerID, policy.LedgerID)
	}

	fpStdout, stderr, code := run("fingerprint", "--public-key-file", pubPath)
	if code != 0 {
		t.Fatalf("fingerprint: exit %d, stderr=%q", code, stderr)
	}
	gotFingerprint := strings.TrimSpace(fpStdout)
	wantFingerprint := screeningledger.PolicyPublicKeyFingerprint(mustDecodeHexPublicKey(t, pubPath))
	if gotFingerprint != wantFingerprint {
		t.Fatalf("fingerprint = %q, want %q (screeningledger.PolicyPublicKeyFingerprint)", gotFingerprint, wantFingerprint)
	}
}

// TestSignRejectsWrongPublicKey proves the signature this binary produces
// is genuinely checked, not merely well-formed: verifying under a
// DIFFERENT keypair's public key must fail.
func TestSignRejectsWrongPublicKey(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "key-a.hex")
	if _, _, code := run("keygen", "--private-key-file", privPath); code != 0 {
		t.Fatal("keygen (key A) failed")
	}
	otherPubPath := filepath.Join(dir, "key-b-pub.hex")
	if _, _, code := run("keygen", "--private-key-file", filepath.Join(dir, "key-b.hex"), "--public-key-file", otherPubPath); code != 0 {
		t.Fatal("keygen (key B) failed")
	}

	policyPath := filepath.Join(dir, "policy.json")
	policy := screeningledger.VerificationPolicy{
		SchemaVersion:        screeningledger.VerificationPolicySchemaV2,
		LedgerID:             "screening-ledger-policy-wrong-key-test",
		MinEventSchema:       screeningledger.EventSchemaV2,
		MinAuditSchema:       screeningledger.AuditSchemaV2,
		GenesisEventSequence: 1,
		GenesisAuditSequence: 1,
	}
	raw, _ := json.Marshal(policy)
	if err := os.WriteFile(policyPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	signedPath := filepath.Join(dir, "policy.signed.json")
	if _, stderr, code := run("sign", "--policy-file", policyPath, "--private-key-file", privPath, "--output", signedPath); code != 0 {
		t.Fatalf("sign: stderr=%q", stderr)
	}

	if _, _, err := screeningledger.LoadSignedVerificationPolicy(signedPath, mustDecodeHexPublicKey(t, otherPubPath)); err == nil {
		t.Fatal("expected verification under key B's public key to fail for a policy signed with key A's private key")
	}
}

func mustDecodeHexPublicKey(t *testing.T, path string) ed25519.PublicKey {
	t.Helper()
	pub, err := screeningledger.LoadEd25519PublicKey(path, "")
	if err != nil {
		t.Fatal(err)
	}
	return pub
}
