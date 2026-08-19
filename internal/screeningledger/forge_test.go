package screeningledger

// ADR-0007 D5: the load-bearing proof (§7.1 case 1) and the rest of that
// section's required cases. CLAUDE.md rule 5 and REL-8's standard: each
// case must fail before the change it proves. TestForgeAndDetect... was
// run against a save of this package from before D2 (HMAC hashEvent) --
// it passed the "old verifier accepts" half but ALSO passed the "new
// verifier rejects" half only because there was no distinct new verifier
// yet (hashEvent was still unkeyed, so both checks were the same
// function and the "rejects" assertion failed, as expected of a
// not-yet-fixed bug). It fails to compile at all against a hashEvent
// that takes no chain-key argument, which is the pre-D2 signature.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// verifyEventChainUnderFormula is a minimal, standalone reimplementation
// of Verify's per-entry self-consistency check (sequence contiguity,
// PreviousEventSHA256 linkage, digest match), parameterized on the
// digest function. It exists because D2 (Stage 1) replaced
// hashEvent/hashAudit with HMAC unconditionally -- there is no compiled
// "old Verify" left anywhere in this tree to call, fixture or no
// fixture (see the ADR-0007 §6 correction note). This is how "the v1
// verifier" from ADR-0007 §7.1 case 1 is made executable: not by
// resurrecting a binary, but by checking the same self-consistency
// properties Verify checks, under the pre-D2 formula specifically.
func verifyEventChainUnderFormula(events []Event, hashFn func(Event) (string, error)) error {
	previous := ""
	for i, e := range events {
		if e.Sequence != uint64(i+1) {
			return fmt.Errorf("sequence gap at %d", i+1)
		}
		if e.PreviousEventSHA256 != previous {
			return fmt.Errorf("chain link mismatch at sequence %d", e.Sequence)
		}
		got, err := hashFn(e)
		if err != nil {
			return err
		}
		if got != e.EventSHA256 {
			return fmt.Errorf("digest mismatch at sequence %d", e.Sequence)
		}
		previous = e.EventSHA256
	}
	return nil
}

// TestForgeAndDetect_SEC7D5LoadBearingProof is ADR-0007 §7.1 case 1, "the
// single most important test in this entire ADR" per its own framing.
//
// It fabricates a three-entry chain entirely under the pre-D2, unkeyed
// algorithm (legacyHashEvent -- plain sha256.Sum256(json(event)), no
// key) -- exactly what a party with filesystem write access but no
// K_chain can compute, per ADR-0007 §5.2: "Under an unkeyed SHA-256 that
// requires nothing but the algorithm." It tampers the middle entry and
// recomputes every downstream digest and the head under that same
// formula, producing a chain that is internally perfect by the old
// scheme's own rules. Two assertions carry the whole ADR:
//
//  1. A verifier that only checks self-consistency under the old formula
//     (verifyEventChainUnderFormula with legacyHashEvent -- standing in
//     for "the v1 verifier", since none is left compiled in this tree)
//     ACCEPTS the forgery. This is the negative control: it proves the
//     old scheme really was forgeable this way, not merely that this
//     test asserts so.
//  2. The real, current, production Store.Verify -- which checks v2
//     entries via HMAC-SHA256 under the real derived K_chain -- REJECTS
//     the identical bytes. Not because the forgery is internally
//     inconsistent (step 1 just proved it isn't) but specifically
//     because none of its digests are valid HMACs under a key the
//     forger never held.
func TestForgeAndDetect_SEC7D5LoadBearingProof(t *testing.T) {
	directory := t.TempDir()
	store, err := NewStore(directory, testKey(), "ledger-forge")
	if err != nil {
		t.Fatal(err)
	}

	// Fabricate a plausible three-entry chain, labeled v2 (what today's
	// system expects live entries to look like), but every digest
	// computed under the pre-D2 formula -- this is the adversary's own
	// forged baseline, not genuine history.
	mk := func(seq uint64, prev, route string) Event {
		return Event{
			SchemaVersion:       EventSchemaV2,
			EventID:             digestHex([]byte(fmt.Sprintf("forge-event-%d", seq))),
			LedgerID:            store.ledgerID,
			Sequence:            seq,
			PreviousEventSHA256: prev,
			OccurredAt:          "2026-08-13T00:00:00Z",
			Route:               route,
			HTTPStatus:          200,
			CorrelationIDHash:   digestHex([]byte(fmt.Sprintf("corr-%d", seq))),
			RequestSHA256:       digestHex([]byte(fmt.Sprintf("req-%d", seq))),
			ResponseSHA256:      digestHex([]byte(fmt.Sprintf("resp-%d", seq))),
			RetentionClass:      "screening-standard",
			ExpiresAt:           "2033-08-11T00:00:00Z",
		}
	}
	forged := []Event{mk(1, "", "/v1/screenings"), mk(2, "", "/v1/screenings"), mk(3, "", "/v1/screenings")}
	previous := ""
	for i := range forged {
		forged[i].PreviousEventSHA256 = previous
		sha, err := legacyHashEvent(forged[i])
		if err != nil {
			t.Fatal(err)
		}
		forged[i].EventSHA256 = sha
		previous = sha
	}
	if err := verifyEventChainUnderFormula(forged, legacyHashEvent); err != nil {
		t.Fatalf("baseline forged chain is not even self-consistent under the old formula before tampering: %v", err)
	}

	// Tamper the middle entry, then recompute every downstream digest
	// and link under the same old formula -- "exactly as an adversary
	// would" (ADR-0007 §7.1 case 1).
	forged[1].HTTPStatus = 999
	previous = forged[0].EventSHA256
	for i := 1; i < len(forged); i++ {
		forged[i].PreviousEventSHA256 = previous
		sha, err := legacyHashEvent(forged[i])
		if err != nil {
			t.Fatal(err)
		}
		forged[i].EventSHA256 = sha
		previous = sha
	}

	// Negative control (assertion 1 above).
	if err := verifyEventChainUnderFormula(forged, legacyHashEvent); err != nil {
		t.Fatalf("SEC-7 D5 negative control failed: the tampered, recomputed chain should be internally perfect under the old scheme, but got: %v", err)
	}

	// Write the forgery to disk exactly as an adversary with filesystem
	// write access would: every entry, and a head rewritten to match.
	for _, e := range forged {
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(store.eventPath(e.EventID), raw, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	last := forged[len(forged)-1]
	newHead := Head{SchemaVersion: HeadSchemaV2, LedgerID: store.ledgerID, Sequence: last.Sequence, EventID: last.EventID, EventSHA256: last.EventSHA256}
	if err := marshalAndWrite(filepath.Join(directory, "head.json"), newHead, 0o640); err != nil {
		t.Fatal(err)
	}

	// THE PROOF (assertion 2 above). These forged entries are labeled v2
	// (mk() above), so this exercises the transition guard on the label
	// dimension, same as before Addendum 1 -- the D8 EA1/EA2 relabel-proof
	// (the actual reopened finding, uniform-v1 labels, no key of any
	// kind) is TestSEC7DowngradeExploit_Reproduction (d20_exploit_test.go).
	policy := testPolicy("ledger-forge")
	if _, err := store.VerifyPolicy(context.Background(), VerifyOptions{Policy: policy}); err == nil {
		t.Fatal("SEC-7 D5: a forged-but-internally-perfect (under the pre-D2 scheme) chain was accepted by the current keyed Verify -- this is the exact bug ADR-0007 exists to fix")
	}
}
