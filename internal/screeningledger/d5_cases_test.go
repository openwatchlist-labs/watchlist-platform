package screeningledger

// ADR-0007 §7.1 cases 2-7, minus the cases already covered elsewhere:
// case 5 (key separation) is TestDerivedSubkeysArePairwiseDistinct
// (chainkey_test.go), case 7 (TRUNCATE rejection) is
// TestSEC7AnchorTableRejectsTruncate (anchor_pgx_test.go). Cases 2 and 4
// (tail truncation vs anchor, anchor divergence) need a live anchor row
// and live over in verify_anchor_pgx_test.go. This file covers case 3
// (wrong key) and case 6 (frozen-prefix acceptance / genesis-boundary
// hard failure), both file-only.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWrongChainKeyFailsVerification is ADR-0007 §7.1 case 3: a chain
// MACed under one K_chain must fail verification when opened under a
// different one. NewStore derives K_chain from the root key plus ledger
// ID (deriveChainKeys), so two Store instances over the same directory
// but different root keys have different K_chain -- this is the direct,
// file-level way to exercise "wrong key" without needing to reach into
// package internals from outside.
func TestWrongChainKeyFailsVerification(t *testing.T) {
	directory := t.TempDir()
	rightKey := testKey()
	wrongKey := make([]byte, 32)
	copy(wrongKey, rightKey)
	wrongKey[0] ^= 0xFF // definitely different, still 32 bytes

	store, err := NewStore(directory, rightKey, "ledger-wrongkey")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(testAppendInput()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify(); err != nil {
		t.Fatalf("chain must verify under its own key: %v", err)
	}

	reopened, err := NewStore(directory, wrongKey, "ledger-wrongkey")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Verify(); err == nil {
		t.Fatal("chain verified successfully under the wrong K_chain")
	}
}

// TestFrozenV1PrefixAcceptedAndAnchoredGenesisBoundaryEnforced is
// ADR-0007 §7.1 case 6, using the real, historically-sourced frozen-v1
// fixture (test/fixtures/screening-ledger/frozen-v1-synthetic/ -- see
// its own README.md) rather than data fabricated inline, per the
// operator's instruction that this case get coverage against an actual
// unkeyed digest. It proves both halves of D4 points 5-6:
//
//  1. The genuine pre-D2 (v1, unkeyed) event verifies as a frozen,
//     unanchored prefix -- VerifyDetail reports EventFrozenPrefixLength
//     matching it, and the overall check succeeds.
//  2. A real v2 genesis record, appended on top via the ordinary,
//     unmodified Append path, extends the chain cleanly (mixed v1-then-v2
//     is accepted).
//  3. A v1-schema entry appearing AFTER that genesis boundary is a hard
//     failure, not a downgrade -- distinct from an ordinary digest
//     mismatch: Verify must reject it specifically because of chain
//     versioning, even though, in isolation, that entry's own digest is
//     perfectly correct under the legacy formula.
func TestFrozenV1PrefixAcceptedAndAnchoredGenesisBoundaryEnforced(t *testing.T) {
	directory := t.TempDir()
	copyDir(t, "../../test/fixtures/screening-ledger/frozen-v1-synthetic/state", directory)

	// The synthetic fixture's snapshot envelopes are copied unmodified
	// from the real committed fixture (see its README.md), so they are
	// encrypted under K_snap derived from the real fixture's root key,
	// not testKey() -- must load the same key the real fixture uses.
	key, err := LoadKey("../../test/fixtures/screening-ledger/snapshot-key.hex", "")
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(directory, key, "screening-api-v8g-example")
	if err != nil {
		t.Fatal(err)
	}

	report, err := store.VerifyDetail()
	if err != nil {
		t.Fatalf("frozen v1 prefix must verify under the legacy formula: %v", err)
	}
	if report.EventFrozenPrefixLength != 1 {
		t.Fatalf("expected event frozen prefix length 1 (the single recovered v1 entry), got %d", report.EventFrozenPrefixLength)
	}
	if report.Head.SchemaVersion != HeadSchemaV1 {
		t.Fatalf("head schema for an all-v1 chain must be labeled v1 (weaker guarantee), got %q", report.Head.SchemaVersion)
	}

	genesisInput := testAppendInput()
	genesisInput.Route = "_sec7_genesis_test"
	genesisResult, err := store.Append(genesisInput)
	if err != nil {
		t.Fatal(err)
	}
	if genesisResult.Event.SchemaVersion != EventSchemaV2 {
		t.Fatalf("newly appended entries must be v2, got %q", genesisResult.Event.SchemaVersion)
	}
	if genesisResult.Event.PreviousEventSHA256 == "" {
		t.Fatal("genesis must reference the frozen v1 prefix's final digest as its predecessor")
	}

	report, err = store.VerifyDetail()
	if err != nil {
		t.Fatalf("v1-prefix-then-v2-genesis chain must verify: %v", err)
	}
	if report.EventFrozenPrefixLength != 1 {
		t.Fatalf("frozen prefix length must still be 1 after genesis, got %d", report.EventFrozenPrefixLength)
	}
	if report.Head.SchemaVersion != HeadSchemaV2 {
		t.Fatalf("head must now be labeled v2 (the anchorable regime), got %q", report.Head.SchemaVersion)
	}

	// Hard failure: forge a v1-schema entry after the genesis boundary.
	// Its own digest is computed correctly under the legacy formula --
	// this is not a garden-variety checksum mismatch, it is specifically
	// the version-boundary rule (ADR-0007 D4 point 6) being tested.
	forged := Event{
		SchemaVersion:       EventSchemaV1,
		EventID:             digestHex([]byte("post-genesis-v1-forgery")),
		LedgerID:            store.ledgerID,
		Sequence:            genesisResult.Event.Sequence + 1,
		PreviousEventSHA256: genesisResult.Event.EventSHA256,
		OccurredAt:          "2026-08-13T00:00:00Z",
		Route:               "/v1/screenings",
		RetentionClass:      "screening-standard",
		ExpiresAt:           "2033-08-13T00:00:00Z",
	}
	sha, err := legacyHashEvent(forged)
	if err != nil {
		t.Fatal(err)
	}
	forged.EventSHA256 = sha
	if legacySelfCheck, _ := legacyHashEvent(forged); legacySelfCheck != forged.EventSHA256 {
		t.Fatal("test construction bug: forged entry's own digest does not even self-check")
	}
	raw, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.eventPath(forged.EventID), raw, 0o640); err != nil {
		t.Fatal(err)
	}
	newHead := Head{SchemaVersion: HeadSchemaV1, LedgerID: store.ledgerID, Sequence: forged.Sequence, EventID: forged.EventID, EventSHA256: forged.EventSHA256}
	if err := marshalAndWrite(filepath.Join(directory, "head.json"), newHead, 0o640); err != nil {
		t.Fatal(err)
	}

	_, err = store.Verify()
	if err == nil {
		t.Fatal("SEC-7 D4 point 6: a v1 entry appearing after the v2 genesis boundary was accepted")
	}
	if !strings.Contains(err.Error(), "after the v2 genesis boundary") {
		t.Fatalf("expected the genesis-boundary hard-failure message, got: %v", err)
	}
}

// copyDir recursively copies src into dst, both assumed to exist/be
// creatable, for tests that need a mutable copy of a committed fixture.
func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		s := filepath.Join(src, e.Name())
		d := filepath.Join(dst, e.Name())
		if e.IsDir() {
			if err := os.MkdirAll(d, 0o750); err != nil {
				t.Fatal(err)
			}
			copyDir(t, s, d)
			continue
		}
		raw, err := os.ReadFile(s)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(d), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(d, raw, 0o640); err != nil {
			t.Fatal(err)
		}
	}
}
