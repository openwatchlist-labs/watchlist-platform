package screeningledger

import (
	"bytes"
	"testing"
)

// TestAnchorMACDependsOnKey is D3's analogue of TestHashEventDependsOnChainKey:
// two different K_anchor values must produce two different anchor_mac
// outputs for the identical (ledger_id, sequence, event_sha256,
// audit_sha256, audit_sequence, policy_sha256) tuple. A forger who does
// not hold K_anchor must not be able to reproduce anchor_mac by any means
// that does not depend on it.
func TestAnchorMACDependsOnKey(t *testing.T) {
	keyA := bytes.Repeat([]byte{0xAA}, 32)
	keyB := bytes.Repeat([]byte{0xBB}, 32)

	macA := anchorMAC(keyA, "ledger-anchor", 1, "event-sha", "audit-sha", 1, "policy-sha")
	macB := anchorMAC(keyB, "ledger-anchor", 1, "event-sha", "audit-sha", 1, "policy-sha")
	if macA == macB {
		t.Fatal("anchor_mac must depend on K_anchor; got identical output under two different keys")
	}
}

// TestAnchorMACDependsOnEveryField guards the NUL-delimited concatenation
// anchorMAC uses: changing any one of the six inputs it is defined over
// (ADR-0007 §5.3, extended by Addendum 1 D11/AR7: ledger_id, sequence,
// event_sha256, audit_sha256, audit_sequence, policy_sha256) must change
// the output. This is also what would catch a delimiter bug that let two
// different (ledger_id, sequence) pairs collide into the same serialized
// input.
func TestAnchorMACDependsOnEveryField(t *testing.T) {
	key := bytes.Repeat([]byte{0xCC}, 32)
	base := anchorMAC(key, "ledger-a", 1, "event-sha-1", "audit-sha-1", 1, "policy-sha-1")

	variants := map[string]string{
		"ledger_id":      anchorMAC(key, "ledger-b", 1, "event-sha-1", "audit-sha-1", 1, "policy-sha-1"),
		"sequence":       anchorMAC(key, "ledger-a", 2, "event-sha-1", "audit-sha-1", 1, "policy-sha-1"),
		"event_sha256":   anchorMAC(key, "ledger-a", 1, "event-sha-2", "audit-sha-1", 1, "policy-sha-1"),
		"audit_sha256":   anchorMAC(key, "ledger-a", 1, "event-sha-1", "audit-sha-2", 1, "policy-sha-1"),
		"audit_sequence": anchorMAC(key, "ledger-a", 1, "event-sha-1", "audit-sha-1", 2, "policy-sha-1"),
		"policy_sha256":  anchorMAC(key, "ledger-a", 1, "event-sha-1", "audit-sha-1", 1, "policy-sha-2"),
	}
	for field, mac := range variants {
		if mac == base {
			t.Fatalf("anchor_mac did not change when %s changed", field)
		}
	}
}

// TestAnchorMACNoDelimiterCollision is the concrete case the NUL delimiter
// in anchorMAC exists to prevent. Undelimited concatenation of
// event_sha256="ab", audit_sha256="cd" and event_sha256="abc",
// audit_sha256="d" both yield the raw string "abcd" -- a real forger's
// lever, since it means two different (event_sha256, audit_sha256) pairs
// could share one anchor_mac. The NUL delimiter makes the two inputs
// distinguishable.
func TestAnchorMACNoDelimiterCollision(t *testing.T) {
	key := bytes.Repeat([]byte{0xDD}, 32)
	macA := anchorMAC(key, "ledger-a", 1, "ab", "cd", 1, "policy-sha")
	macB := anchorMAC(key, "ledger-a", 1, "abc", "d", 1, "policy-sha")
	if macA == macB {
		t.Fatal("anchor_mac must not collide across a delimiter-free concatenation ambiguity")
	}
}

// TestAnchorMACIsDeterministic: the same inputs must always produce the
// same anchor_mac, since VerifyAnchored needs to recompute it and compare.
func TestAnchorMACIsDeterministic(t *testing.T) {
	key := bytes.Repeat([]byte{0xEE}, 32)
	first := anchorMAC(key, "ledger-a", 7, "event-sha", "audit-sha", 7, "policy-sha")
	second := anchorMAC(key, "ledger-a", 7, "event-sha", "audit-sha", 7, "policy-sha")
	if first != second {
		t.Fatal("anchor_mac must be deterministic for identical inputs")
	}
}

// TestKAnchorDistinctFromChainKeys is ADR-0007 §5.1's key-separation
// requirement extended to K_anchor: K_anchor must not be derivable from
// the same root secret R that produces K_snap/K_redact/K_chain
// (deriveChainKeys). There is no code path from root to K_anchor at all
// -- this test documents that absence by construction rather than
// asserting a negative on deriveChainKeys' output, since the whole point
// of §5.1 is that K_anchor is generated and loaded independently
// (LoadKey, the same loader R uses, but never fed through HKDF against
// R).
func TestKAnchorDistinctFromChainKeys(t *testing.T) {
	root := bytes.Repeat([]byte{0x11}, 32)
	keys, err := deriveChainKeys(root, "ledger-anchor")
	if err != nil {
		t.Fatal(err)
	}
	// An independently generated K_anchor, unrelated to root.
	kAnchor := bytes.Repeat([]byte{0x99}, 32)
	if bytes.Equal(kAnchor, keys.chain) || bytes.Equal(kAnchor, keys.snap) || bytes.Equal(kAnchor, keys.redact) {
		t.Fatal("test fixture error: K_anchor fixture collided with a derived subkey")
	}
	macUnderAnchorKey := anchorMAC(kAnchor, "ledger-anchor", 1, "event-sha", "audit-sha", 1, "policy-sha")
	macUnderChainKey := anchorMAC(keys.chain, "ledger-anchor", 1, "event-sha", "audit-sha", 1, "policy-sha")
	if macUnderAnchorKey == macUnderChainKey {
		t.Fatal("anchor_mac computed under K_anchor must differ from the same computation under K_chain")
	}
}
