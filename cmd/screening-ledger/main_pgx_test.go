// ADR-0007 Addendum 14 D128 (F-D, MEDIUM): status/verify/sync all reach
// anchor.go:921's absent-anchor message through VerifyAnchored, which
// names --allow-genesis -- a flag valid only on `anchor`. Reproduced end
// to end through the real, unmodified CLI binary against a live,
// disposable PostgreSQL cluster provisioned exactly as CI provisions it
// (scripts/ci/provision_test_roles.sh), one throwaway `CREATE DATABASE
// ... TEMPLATE` clone per test so each run starts from a genuinely
// anchor-less state for the fixture ledger. Gated on
// OWL_MIGRATOR_DATABASE_URL and OWL_LEDGER_ANCHOR_DATABASE_URL, the same
// two identities scripts/ci/run-ci.sh already requires for this suite.
package main_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningledger"
)

// policyFixtureShared is policyFixture's own shape (main_test.go) with
// Tenancy: TenancyShared rather than TenancyExclusive -- see the comment
// at its one call site in this file for why.
func policyFixtureShared(t *testing.T, allowUnanchored bool) (policyPath, pubKeyPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := screeningledger.VerificationPolicy{
		SchemaVersion:        screeningledger.VerificationPolicySchemaV4,
		LedgerID:             fixtureLedgerID,
		MinEventSchema:       screeningledger.EventSchemaV2,
		MinAuditSchema:       screeningledger.AuditSchemaV2,
		GenesisEventSequence: 1,
		GenesisAuditSequence: 1,
		AllowUnanchored:      allowUnanchored,
		Tenancy:              screeningledger.TenancyShared,
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

// cloneDisposableDatabase issues `CREATE DATABASE ... TEMPLATE` against
// the superuser-reachable primary named by dsn's own host/port, and
// returns a DSN for the fresh throwaway clone plus a cleanup func. Every
// test in this file gets its own clone so writing this ledger's first
// anchor in one test never contaminates another.
func cloneDisposableDatabase(t *testing.T, dsn string) (cloneDSN string, cleanup func()) {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parsing dsn: %v", err)
	}
	superDSN := fmt.Sprintf("postgresql://owl_ci:owl_ci@%s/postgres?sslmode=disable", u.Host)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, superDSN)
	if err != nil {
		t.Skipf("cannot connect as owl_ci bootstrap superuser (%s not reachable as owl_ci): %v", u.Host, err)
	}
	defer conn.Close(ctx)
	cloneName := fmt.Sprintf("owl_ci_a14_d128_%d", os.Getpid())
	if _, err := conn.Exec(ctx, "DROP DATABASE IF EXISTS "+cloneName); err != nil {
		t.Fatalf("dropping any stale clone: %v", err)
	}
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+cloneName+" TEMPLATE "+strings.TrimPrefix(u.Path, "/")); err != nil {
		t.Fatalf("cloning template database: %v", err)
	}
	cloneDSN = fmt.Sprintf("postgresql://owl_migrator:owl_migrator@%s/%s?sslmode=disable", u.Host, cloneName)
	return cloneDSN, func() {
		conn2, err := pgx.Connect(ctx, superDSN)
		if err != nil {
			return
		}
		defer conn2.Close(ctx)
		_, _ = conn2.Exec(ctx, "DROP DATABASE IF EXISTS "+cloneName)
	}
}

// TestAbsentAnchorNamesARemedyValidOnThisCommand is ADR-0007 Addendum 14
// D128/D131 item 6, run against a live, disposable clone rather than
// against CI's own shared owl_ci database, so the anchor-writing step at
// the end does not collide with any other test.
func TestAbsentAnchorNamesARemedyValidOnThisCommand(t *testing.T) {
	migratorDSN := os.Getenv("OWL_MIGRATOR_DATABASE_URL")
	anchorDSN := os.Getenv("OWL_LEDGER_ANCHOR_DATABASE_URL")
	if migratorDSN == "" || anchorDSN == "" {
		t.Skip("OWL_MIGRATOR_DATABASE_URL / OWL_LEDGER_ANCHOR_DATABASE_URL not set; SEC-7 Addendum 14 D128 suite requires a live Postgres provisioned via scripts/ci/provision_test_roles.sh")
	}
	cloneMigratorDSN, cleanup := cloneDisposableDatabase(t, migratorDSN)
	defer cleanup()
	au, err := url.Parse(anchorDSN)
	if err != nil {
		t.Fatal(err)
	}
	cu, err := url.Parse(cloneMigratorDSN)
	if err != nil {
		t.Fatal(err)
	}
	cloneAnchorDSN := fmt.Sprintf("postgresql://owl_ledger_anchor:owl_ledger_anchor@%s%s?sslmode=disable", au.Host, cu.Path)

	ledgerDir := freshLedgerCopy(t)
	// TenancyShared rather than policyFixture's own TenancyExclusive: the
	// clone below is templated off the SAME live database every other
	// package's pgx suite shares (OWL_MIGRATOR_DATABASE_URL), which can
	// legitimately carry other tests' own ledger_id rows in
	// screening_ledger_event at clone time (different packages' test
	// binaries run concurrently against one Postgres service container).
	// TenancyExclusive's own whole-table purity check (D110) would then
	// fail on a fact this test has no interest in -- D128's mechanism is
	// entirely in the ABSENT-anchor path, before any tenancy-dependent
	// adjudication runs at all.
	policyPath, pubKeyPath := policyFixtureShared(t, false) // AllowUnanchored: false -- anchored mode is the default

	kAnchorHex := hex.EncodeToString(bytes.Repeat([]byte{0x37}, 32))
	envMigratorDSN := "A14_D128_MIGRATOR_DSN"
	envAnchorDSN := "A14_D128_ANCHOR_DSN"
	envAnchorKey := "A14_D128_ANCHOR_KEY"
	t.Setenv(envMigratorDSN, cloneMigratorDSN)
	t.Setenv(envAnchorDSN, cloneAnchorDSN)
	t.Setenv(envAnchorKey, kAnchorHex)

	baseArgs := []string{
		"--ledger-dir", ledgerDir, "--key-file", keyFile, "--ledger-id", fixtureLedgerID,
		"--policy-file", policyPath, "--policy-public-key-file", pubKeyPath,
		"--postgres-dsn-env", envMigratorDSN, "--anchor-key-env", envAnchorKey,
	}

	// migrate this fresh clone first -- it was created from the fully
	// provisioned template, so Migrate() here is a no-op confirmation,
	// not a bootstrap; still required so mustSink's later connections
	// see a database CheckProvisioningState reports as provisioned.
	if _, stderr, code := run(append([]string{"migrate"}, baseArgs...)...); code != 0 {
		t.Fatalf("migrate on the fresh clone failed: %q", stderr)
	}

	// ADR-0007 Addendum 14 D128: status/verify/sync must each name the
	// `anchor` invocation (including --anchor-dsn-env, CAP #13's own
	// second trap) rather than printing VerifyAnchored's own bare
	// message, which named a remedy valid on no command reaching it here.
	assertNamesTheAnchorRemedy := func(t *testing.T, command, stderr string) {
		t.Helper()
		for _, want := range []string{"screening-ledger anchor", "--anchor-dsn-env", "--allow-genesis"} {
			if !strings.Contains(stderr, want) {
				t.Fatalf("%s: expected the absent-anchor message to name %q, got: %q", command, want, stderr)
			}
		}
		if strings.Contains(stderr, "pass --allow-genesis explicitly if this is genuinely a first anchor") {
			t.Fatalf("%s: expected VerifyAnchored's own bare message (naming a remedy valid on no command reaching it here) to NOT appear verbatim, got: %q", command, stderr)
		}
	}

	// (1) status: exits non-zero, naming the anchor invocation.
	_, stderr, code := run(append([]string{"status"}, baseArgs...)...)
	if code == 0 {
		t.Fatal("expected status to fail against a freshly cloned, never-anchored ledger")
	}
	assertNamesTheAnchorRemedy(t, "status", stderr)
	fmt.Printf("A14D128 status (before remedy): %s\n", strings.TrimSpace(stderr))

	// (2) verify: same message.
	_, stderr, code = run(append([]string{"verify"}, baseArgs...)...)
	if code == 0 {
		t.Fatal("expected verify to fail against a freshly cloned, never-anchored ledger")
	}
	assertNamesTheAnchorRemedy(t, "verify", stderr)
	fmt.Printf("A14D128 verify (before remedy): %s\n", strings.TrimSpace(stderr))

	// (3) sync: same message (sync also runs full anchored verification
	// before its first Persist).
	_, stderr, code = run(append([]string{"sync"}, baseArgs...)...)
	if code == 0 {
		t.Fatal("expected sync to fail against a freshly cloned, never-anchored ledger")
	}
	assertNamesTheAnchorRemedy(t, "sync", stderr)
	fmt.Printf("A14D128 sync (before remedy): %s\n", strings.TrimSpace(stderr))

	// (4) status --allow-genesis true: D24's own refusal, must not regress.
	_, stderr, code = run(append(append([]string{"status"}, baseArgs...), "--allow-genesis", "true")...)
	if code == 0 {
		t.Fatal("expected status --allow-genesis true to still be refused (ADR-0007 Addendum 2 D24)")
	}
	if !strings.Contains(stderr, "--allow-genesis has no effect on this command") {
		t.Fatalf("expected D24's own refusal text unregressed, got: %q", stderr)
	}

	// (5) anchor's OWN message, called WITHOUT --allow-genesis, is
	// UNCHANGED -- exactly VerifyAnchored's own bare error text, since
	// `anchor` is the one subcommand that message is actually valid on.
	anchorArgsNoGenesis := []string{
		"--ledger-dir", ledgerDir, "--key-file", keyFile, "--ledger-id", fixtureLedgerID,
		"--policy-file", policyPath, "--policy-public-key-file", pubKeyPath,
		"--postgres-dsn-env", envMigratorDSN, "--anchor-key-env", envAnchorKey,
		"--anchor-dsn-env", envAnchorDSN,
	}
	_, stderr, code = run(append([]string{"anchor"}, anchorArgsNoGenesis...)...)
	if code == 0 {
		t.Fatal("expected anchor (no --allow-genesis) to still fail against a never-anchored ledger")
	}
	if !strings.Contains(stderr, "pass --allow-genesis explicitly if this is genuinely a first anchor") {
		t.Fatalf("ADR-0007 Addendum 14 D128: expected anchor's OWN message to be UNCHANGED, got: %q", stderr)
	}
	fmt.Printf("A14D128 anchor (no --allow-genesis, message unchanged): %s\n", strings.TrimSpace(stderr))

	// (6) the named remedy, run for real: anchor --allow-genesis true.
	anchorArgs := []string{
		"--ledger-dir", ledgerDir, "--key-file", keyFile, "--ledger-id", fixtureLedgerID,
		"--policy-file", policyPath, "--policy-public-key-file", pubKeyPath,
		"--postgres-dsn-env", envMigratorDSN, "--anchor-key-env", envAnchorKey,
		"--anchor-dsn-env", envAnchorDSN, "--allow-genesis", "true",
	}
	stdout, stderr, code := run(append([]string{"anchor"}, anchorArgs...)...)
	if code != 0 {
		t.Fatalf("expected the named remedy to succeed, got exit %d stderr=%q", code, stderr)
	}
	fmt.Printf("A14D128 anchor --allow-genesis true: %s\n", strings.TrimSpace(stdout))

	// (7) status again: the state is now cleared.
	stdout, stderr, code = run(append([]string{"status"}, baseArgs...)...)
	if code != 0 {
		t.Fatalf("expected status to succeed after the remedy, got exit %d stderr=%q", code, stderr)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("parsing status output: %v (stdout=%q)", err, stdout)
	}
	if parsed["anchor_status"] != "verified" {
		t.Fatalf("expected anchor_status:verified after the remedy, got: %s", stdout)
	}
	fmt.Printf("A14D128 status (after remedy): %s\n", strings.TrimSpace(stdout))
}
