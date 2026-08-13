package screeningledger

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestHashEventDependsOnChainKey is the load-bearing test for ADR-0007 D2.
// Before D2, hashEvent computed plain sha256.Sum256(json(event)) with no
// key input at all -- its signature took no key parameter, so it could not
// depend on one. Two different keys must now produce two different
// digests for the identical event, and neither may collapse back to the
// unkeyed SHA-256 digest the pre-D2 scheme would have produced.
func TestHashEventDependsOnChainKey(t *testing.T) {
	event := Event{SchemaVersion: EventSchemaV1, EventID: "e1", LedgerID: "ledger-chainkey", Sequence: 1, OccurredAt: "2026-08-13T00:00:00Z", Route: "/v1/screenings", RetentionClass: "screening-standard", ExpiresAt: "2033-08-13T00:00:00Z"}
	keyA := bytes.Repeat([]byte{0xAA}, 32)
	keyB := bytes.Repeat([]byte{0xBB}, 32)

	hashA, err := hashEvent(event, keyA)
	if err != nil {
		t.Fatal(err)
	}
	hashB, err := hashEvent(event, keyB)
	if err != nil {
		t.Fatal(err)
	}
	if hashA == hashB {
		t.Fatal("hashEvent output must depend on the chain key; got identical output under two different keys")
	}

	blanked := event
	blanked.EventSHA256 = ""
	raw, err := json.Marshal(blanked)
	if err != nil {
		t.Fatal(err)
	}
	unkeyed := digestHex(raw)
	if hashA == unkeyed || hashB == unkeyed {
		t.Fatal("hashEvent must not degrade to the pre-D2 unkeyed SHA-256 digest")
	}
}

// TestHashAuditDependsOnChainKey mirrors TestHashEventDependsOnChainKey
// for the audit chain's hashAudit (ADR-0007 D2, audit.go:101-108).
func TestHashAuditDependsOnChainKey(t *testing.T) {
	event := AuditEvent{SchemaVersion: AuditSchemaV1, LedgerID: "ledger-chainkey", Sequence: 1, OccurredAt: "2026-08-13T00:00:00Z", Action: "export_bundle"}
	keyA := bytes.Repeat([]byte{0xAA}, 32)
	keyB := bytes.Repeat([]byte{0xBB}, 32)

	hashA, err := hashAudit(event, keyA)
	if err != nil {
		t.Fatal(err)
	}
	hashB, err := hashAudit(event, keyB)
	if err != nil {
		t.Fatal(err)
	}
	if hashA == hashB {
		t.Fatal("hashAudit output must depend on the chain key; got identical output under two different keys")
	}

	blanked := event
	blanked.AuditSHA256 = ""
	raw, err := json.Marshal(blanked)
	if err != nil {
		t.Fatal(err)
	}
	unkeyed := digestHex(raw)
	if hashA == unkeyed || hashB == unkeyed {
		t.Fatal("hashAudit must not degrade to the pre-D2 unkeyed SHA-256 digest")
	}
}

// TestDerivedSubkeysArePairwiseDistinct is ADR-0007 §7.1 case 5: the test
// that would catch a copy-paste leaving two HKDF derivations sharing an
// info string.
func TestDerivedSubkeysArePairwiseDistinct(t *testing.T) {
	root := bytes.Repeat([]byte{0x11}, 32)
	keys, err := deriveChainKeys(root, "ledger-chainkey")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(keys.snap, keys.redact) || bytes.Equal(keys.snap, keys.chain) || bytes.Equal(keys.redact, keys.chain) {
		t.Fatal("K_snap, K_redact, and K_chain must be pairwise distinct")
	}
	other, err := deriveChainKeys(root, "different-ledger")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(keys.chain, other.chain) {
		t.Fatal("K_chain must differ across ledger IDs sharing the same root secret")
	}
}
