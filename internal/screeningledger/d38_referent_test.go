// ADR-0007 Addendum 4 D38 (H-A CRITICAL, H-B HIGH) and D42 point 1/2:
// the document's bytes, and the boundary's referent.
//
// D42 requires these tests to reproduce CAP #3's own transcript, not a
// paraphrase, and states plainly that several assertions must be shown
// "must pass today and fail after" -- for these findings the pre-fix
// behaviour is ACCEPTANCE, and a suite that only asserts the post-fix
// refusal cannot distinguish a working fix from a test that never
// exercised the path. Since this package's fix is already applied by
// the time this file is committed, the pre-fix behaviour is reproduced
// explicitly and inline: the naive alternative (bare json.Unmarshal for
// D38(a), a length-bound-only comparison for D38(b)) is executed
// side-by-side with the real, fixed function, exactly as this
// addendum's own design-phase transcripts did before deciding on the
// stronger mechanism (0007:2952-2966 for (a), 0007:3010-3024 for (b)).
package screeningledger

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDecodeUnsignedPolicyRejectsDuplicateKeys is D38(a) / D42 point 1.
func TestDecodeUnsignedPolicyRejectsDuplicateKeys(t *testing.T) {
	// CAP #3 §7.5's exact bait document: an operator reading the first
	// occurrence of each key sees genesis_event_sequence=1,
	// genesis_audit_sequence=1, min_anchor_sequence=500; the document
	// then repeats all three with the values that actually get signed.
	baitDocument := []byte(`{
		"schema_version":"openwatchlist.screening-ledger-verification-policy.v3",
		"ledger_id":"d38a-bait-ledger",
		"min_event_schema":"openwatchlist.screening-ledger-event.v2",
		"min_audit_schema":"openwatchlist.screening-ledger-audit.v2",
		"genesis_event_sequence":1,
		"genesis_audit_sequence":1,
		"min_anchor_sequence":500,
		"allow_unanchored":false,
		"genesis_event_sha256":"",
		"genesis_audit_sha256":"",
		"genesis_event_sequence":999999999,
		"genesis_audit_sequence":999999999,
		"min_anchor_sequence":0
	}`)

	// Naive alternative, standing in for the pre-fix behaviour (D38(a)'s
	// own transcript: "Decoder+DisallowUnknownFields ... last occurrence
	// silently wins"): a bare last-occurrence-wins decode, exactly what
	// DecodeUnsignedPolicy did before this addendum.
	var naive unsignedPolicyInput
	if err := json.Unmarshal(baitDocument, &naive); err != nil {
		t.Fatalf("test construction bug: the bait document must be valid JSON: %v", err)
	}
	if naive.GenesisEventSequence == nil || *naive.GenesisEventSequence != 999999999 {
		t.Fatalf("test construction bug: naive last-wins decode must resolve genesis_event_sequence to 999999999 (the CAP #3 H-B demonstration), got %v", naive.GenesisEventSequence)
	}
	if naive.MinAnchorSequence == nil || *naive.MinAnchorSequence != 0 {
		t.Fatalf("test construction bug: naive last-wins decode must resolve min_anchor_sequence to 0 (the CAP #3 H-B demonstration), got %v", naive.MinAnchorSequence)
	}

	// The real, fixed path must refuse the same bytes outright, naming
	// every repeated key.
	_, err := DecodeUnsignedPolicy(bytes.NewReader(baitDocument))
	if err == nil {
		t.Fatal("ADR-0007 Addendum 4 D38(a): DecodeUnsignedPolicy accepted CAP #3 §7.5's bait document -- duplicate keys must be refused before decoding")
	}
	for _, key := range []string{"genesis_audit_sequence", "genesis_event_sequence", "min_anchor_sequence"} {
		if !strings.Contains(err.Error(), key) {
			t.Fatalf("expected the error to name repeated key %q, got: %v", key, err)
		}
	}

	cases := []struct {
		name       string
		document   string
		wantReject bool
		wantErr    string
	}{
		{
			name:       "nested_object_duplicate",
			document:   `{"a":{"b":1,"b":2}}`,
			wantReject: true,
			wantErr:    "a.b",
		},
		{
			name:       "array_element_duplicate",
			document:   `{"a":[{"b":1},{"b":2,"b":3}]}`,
			wantReject: true,
			wantErr:    "a.[].b",
		},
		{
			name:       "trailing_content_after_top_level_value",
			document:   `{"a":1}{"b":2}`,
			wantReject: true,
			wantErr:    "trailing content",
		},
		{
			name:       "duplicate_differing_whitespace",
			document:   `{"a":1, "a"   :2}`,
			wantReject: true,
			wantErr:    "a",
		},
		{
			name:       "no_duplicates",
			document:   `{"a":1,"c":2}`,
			wantReject: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkNoDuplicateJSONKeys([]byte(c.document))
			if c.wantReject {
				if err == nil {
					t.Fatalf("expected %q to be rejected", c.document)
				}
				if !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("expected error to contain %q, got: %v", c.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected %q to be accepted, got: %v", c.document, err)
			}
		})
	}

	// The committed example fixture must still sign and load cleanly --
	// a validator that rejects everything is not a validator.
	fixtureRaw, err := os.ReadFile("../../test/fixtures/screening-ledger/policy/example-policy.signed.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := checkNoDuplicateJSONKeys(fixtureRaw); err != nil {
		t.Fatalf("committed example fixture must have no duplicate keys: %v", err)
	}
	pubHex, err := os.ReadFile("../../test/fixtures/screening-ledger/policy/example-public-key.hex")
	if err != nil {
		t.Fatal(err)
	}
	trustRoot := decodeHexPublicKeyForTest(t, strings.TrimSpace(string(pubHex)))
	loaded, _, err := LoadSignedVerificationPolicy("../../test/fixtures/screening-ledger/policy/example-policy.signed.json", trustRoot)
	if err != nil {
		t.Fatalf("committed example fixture must still load cleanly: %v", err)
	}
	if loaded.LedgerID != "screening-api-v8g-example" {
		t.Fatalf("unexpected ledger_id from committed fixture: %q", loaded.LedgerID)
	}

	// D36 must not have regressed: both of CAP #2 §7.8's inputs are still
	// refused.
	if _, err := DecodeUnsignedPolicy(strings.NewReader(`{
		"schema_version":"openwatchlist.screening-ledger-verification-policy.v3",
		"ledger_id":"ledger-a",
		"min_event_schema":"openwatchlist.screening-ledger-event.v2",
		"min_audit_schema":"openwatchlist.screening-ledger-audit.v2",
		"genesis_event_sequence":1,
		"genesis_audit_sequence":1,
		"allow_unanchored":false,
		"min_anchor_seqence":5,
		"genesis_event_sha256":"",
		"genesis_audit_sha256":""
	}`)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected the transposed min_anchor_seqence to still be refused with an unknown-field error, got: %v", err)
	}
	if _, err := DecodeUnsignedPolicy(strings.NewReader(`{
		"schema_version":"openwatchlist.screening-ledger-verification-policy.v3",
		"ledger_id":"ledger-a",
		"min_event_schema":"openwatchlist.screening-ledger-event.v2",
		"min_audit_schema":"openwatchlist.screening-ledger-audit.v2",
		"genesis_event_sequence":1,
		"genesis_audit_sequence":1,
		"allow_unanchored":false,
		"genesis_event_sha256":"",
		"genesis_audit_sha256":""
	}`)); err == nil || !strings.Contains(err.Error(), "missing required field") {
		t.Fatalf("expected an omitted min_anchor_sequence to still be refused with a missing-field error, got: %v", err)
	}
}

func decodeHexPublicKeyForTest(t *testing.T, hexKey string) ed25519.PublicKey {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pub.hex")
	if err := os.WriteFile(path, []byte(hexKey), 0o644); err != nil {
		t.Fatal(err)
	}
	pub, err := LoadEd25519PublicKey(path, "")
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// naiveLengthBoundOnlyAccepts reproduces the design-phase's own rejected
// alternative (0007:3010-3024): "require genesis_event_sequence - 1 <=
// len(chain)" with no digest pin at all. Used only to demonstrate, side
// by side with the real check, that a length bound alone cannot
// distinguish a legitimate post-migration "the entire ledger is frozen
// v1 prefix" state from the maximal form of H-A's attack.
func naiveLengthBoundOnlyAccepts(genesisEventSequence uint64, chainLength int) bool {
	if genesisEventSequence == 0 {
		return false
	}
	return int(genesisEventSequence-1) <= chainLength
}

// TestGenesisBoundaryRequiresPrefixCommitment is D38(b) / D42 point 2.
func TestGenesisBoundaryRequiresPrefixCommitment(t *testing.T) {
	ledgerID := uniqueID("d38b-genesis-pin")
	store, directory := buildGenuineMultiEntryChain(t, ledgerID)
	genuineHeadSHA, err := store.eventAtSequence(3)
	if err != nil {
		t.Fatal(err)
	}
	downgradeAndForge(t, store, directory, forgeOptions{tamperContent: true})
	assertGenuinelyForgedUnderLegacyFormula(t, directory)

	reopened, err := NewStore(directory, testKey(), ledgerID)
	if err != nil {
		t.Fatal(err)
	}

	// H-A's bait: genesis far above the chain's actual length. The naive
	// length bound alone would already reject this (999999999 - 1 > 3),
	// so this case establishes the baseline, not the distinguishing one.
	baitPolicy := testPolicy(ledgerID)
	baitPolicy.GenesisEventSequence = 999999999
	baitPolicy.GenesisEventSHA256 = strings.Repeat("0", 64)
	if naiveLengthBoundOnlyAccepts(baitPolicy.GenesisEventSequence, 3) {
		t.Fatal("test construction bug: the naive length bound was expected to already reject the bait boundary")
	}
	if _, err := reopened.VerifyPolicy(context.Background(), VerifyOptions{Policy: baitPolicy}); err == nil {
		t.Fatal("ADR-0007 Addendum 4 D38(b): VerifyPolicy accepted a genesis boundary (999999999) with no entry in the chain to pin")
	} else if !strings.Contains(err.Error(), "no entry at sequence") {
		t.Fatalf("expected the 'no entry to pin' error, got: %v", err)
	}

	// The distinguishing case: genesis == head+1 (the maximal form of the
	// attack, and simultaneously a legitimate post-D4-migration state).
	// The naive length bound alone ACCEPTS this -- confirmed inline,
	// exactly as the design phase's own execution did -- because every
	// entry is below the boundary and every entry verifies under
	// legacyHashEvent. Only the digest pin distinguishes forgery from a
	// genuine all-frozen-prefix chain.
	maxBoundaryPolicy := testPolicy(ledgerID)
	maxBoundaryPolicy.GenesisEventSequence = 4 // head (3) + 1
	if !naiveLengthBoundOnlyAccepts(maxBoundaryPolicy.GenesisEventSequence, 3) {
		t.Fatal("test construction bug: the naive length bound was expected to accept genesis == head+1 -- this is exactly what makes it insufficient")
	}
	maxBoundaryPolicy.GenesisEventSHA256 = genuineHeadSHA.EventSHA256
	if _, err := reopened.VerifyPolicy(context.Background(), VerifyOptions{Policy: maxBoundaryPolicy}); err == nil {
		t.Fatal("ADR-0007 Addendum 4 D38(b): VerifyPolicy accepted a max-boundary forgery (genesis=head+1) pinned to the GENUINE chain's head digest, against a chain whose content was tampered and re-hashed under the legacy formula")
	} else if !strings.Contains(err.Error(), "does not match the policy's pinned genesis_event_sha256") {
		t.Fatalf("expected the pin-mismatch error, got: %v", err)
	}

	// CONTROL: same forged chain, genesis=1 -- already defeated by the
	// existing D8 EA1/EA2 schema-floor mechanism (every entry is
	// v1-labelled, genesis=1 demands v2 from sequence 1 onward), so this
	// confirms the control path is unaffected by D38(b)'s addition.
	controlPolicy := testPolicy(ledgerID)
	if _, err := reopened.VerifyPolicy(context.Background(), VerifyOptions{Policy: controlPolicy}); err == nil {
		t.Fatal("expected genesis=1 against the fully-v1-relabelled forged chain to fail on the existing schema-floor check")
	} else if !strings.Contains(err.Error(), "minimum accepted schema version") {
		t.Fatalf("expected the schema-floor error, got: %v", err)
	}

	// Positive 1: bootstrap (genesis=1, empty sentinel) against a fresh,
	// entirely v2 ledger -- no prior chain reference needed at all.
	bootstrapLedgerID := uniqueID("d38b-bootstrap")
	bootstrapStore, _ := buildGenuineMultiEntryChain(t, bootstrapLedgerID)
	bootstrapPolicy := testPolicy(bootstrapLedgerID)
	if _, err := bootstrapStore.VerifyPolicy(context.Background(), VerifyOptions{Policy: bootstrapPolicy}); err != nil {
		t.Fatalf("bootstrap policy (genesis=1, empty sentinel) must verify against a fresh v2 ledger: %v", err)
	}

	// Positive 2: honest re-issue -- a genuine chain (no content
	// tampering) downgraded to a real v1 frozen prefix exactly as D4's
	// migration produces one, with a policy that correctly pins the
	// resulting frozen prefix's head digest at the same max boundary the
	// forged case above used. This is the case a length bound alone
	// could not distinguish from the forgery; the pin can.
	honestLedgerID := uniqueID("d38b-honest-reissue")
	honestStore, honestDirectory := buildGenuineMultiEntryChain(t, honestLedgerID)
	downgradeAndForge(t, honestStore, honestDirectory, forgeOptions{})
	honestReopened, err := NewStore(honestDirectory, testKey(), honestLedgerID)
	if err != nil {
		t.Fatal(err)
	}
	honestFrozenHead, err := honestReopened.eventAtSequence(3)
	if err != nil {
		t.Fatal(err)
	}
	honestAuditEntries := readAllAuditEntriesSortedBySequence(t, honestDirectory)
	if len(honestAuditEntries) != 2 {
		t.Fatalf("test construction bug: expected 2 genuine audit entries, got %d", len(honestAuditEntries))
	}
	honestPolicy := testPolicy(honestLedgerID)
	honestPolicy.GenesisEventSequence = 4 // event head (3) + 1
	honestPolicy.GenesisEventSHA256 = honestFrozenHead.EventSHA256
	honestPolicy.GenesisAuditSequence = 3 // audit head (2) + 1
	honestPolicy.GenesisAuditSHA256 = honestAuditEntries[1].AuditSHA256
	if _, err := honestReopened.VerifyPolicy(context.Background(), VerifyOptions{Policy: honestPolicy}); err != nil {
		t.Fatalf("honest re-issue (genesis=4/3, pins matching the genuine downgraded chain) must verify: %v", err)
	}
}
