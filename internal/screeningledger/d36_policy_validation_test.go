// ADR-0007 Addendum 3 D36 (G-F): CAP #2 §7.8 found runSign
// (cmd/screening-ledger-policy) was os.ReadFile -> json.Unmarshal ->
// SignVerificationPolicy with no field examined, and signed four inputs
// that should never have produced a validly signed artifact: a
// transposed min_anchor_sequence, an omitted one, a retired v1 document
// with empty fields, and {"hello":"world"}. min_anchor_sequence is the
// only mechanism bounding anchor rollback (D25, R14); a typo or omission
// both zero-fill it silently. This is a table-driven reproduction of
// exactly those four inputs against DecodeUnsignedPolicy, the function
// runSign now goes through, plus a control case proving the committed
// example fixture still signs and loads.
package screeningledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeUnsignedPolicyRejectsCAPTwoSevenPointEightInputs(t *testing.T) {
	cases := []struct {
		name        string
		document    string
		wantErrLike string
	}{
		{
			name: "transposed_min_anchor_sequence",
			document: `{
				"schema_version":"openwatchlist.screening-ledger-verification-policy.v2",
				"ledger_id":"ledger-a",
				"min_event_schema":"openwatchlist.screening-ledger-event.v2",
				"min_audit_schema":"openwatchlist.screening-ledger-audit.v2",
				"genesis_event_sequence":1,
				"genesis_audit_sequence":1,
				"allow_unanchored":false,
				"min_anchor_seqence":5
			}`,
			wantErrLike: "unknown field",
		},
		{
			name: "omitted_min_anchor_sequence",
			document: `{
				"schema_version":"openwatchlist.screening-ledger-verification-policy.v2",
				"ledger_id":"ledger-a",
				"min_event_schema":"openwatchlist.screening-ledger-event.v2",
				"min_audit_schema":"openwatchlist.screening-ledger-audit.v2",
				"genesis_event_sequence":1,
				"genesis_audit_sequence":1,
				"allow_unanchored":false
			}`,
			wantErrLike: "missing required field",
		},
		{
			name: "retired_v1_with_empty_fields",
			document: `{
				"schema_version":"openwatchlist.screening-ledger-verification-policy.v1",
				"ledger_id":"",
				"min_event_schema":"",
				"min_audit_schema":"",
				"genesis_event_sequence":0,
				"genesis_audit_sequence":0,
				"allow_unanchored":true,
				"min_anchor_sequence":0
			}`,
			wantErrLike: "schema_version",
		},
		{
			// Caught even earlier than the other cases: strict decoding
			// rejects the unrecognized "hello" key before presence-checking
			// ever runs, which is a stronger outcome than "missing
			// required field" would have been, not a weaker one.
			name:        "hello_world",
			document:    `{"hello":"world"}`,
			wantErrLike: "unknown field",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := DecodeUnsignedPolicy(strings.NewReader(c.document))
			if err == nil {
				t.Fatalf("CAP #2 §7.8: expected DecodeUnsignedPolicy to refuse this document (ADR-0007 Addendum 3 D36), but it succeeded")
			}
			if !strings.Contains(err.Error(), c.wantErrLike) {
				t.Fatalf("expected error to contain %q, got: %v", c.wantErrLike, err)
			}
		})
	}
}

// TestSignVerificationPolicyRefusesInvalidPolicy is D36's second
// enforcement point: even a caller that bypasses DecodeUnsignedPolicy
// entirely (constructs a VerificationPolicy directly, as a Go value)
// cannot get SignVerificationPolicy to sign an invalid one. Enforcing at
// only one end would leave the other as the gap -- exactly what
// policy.go:135 being the sole check produced before this addendum.
func TestSignVerificationPolicyRefusesInvalidPolicy(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	invalid := VerificationPolicy{} // the {"hello":"world"} shape's zero-value equivalent
	if _, err := SignVerificationPolicy(invalid, priv); err == nil {
		t.Fatal("expected SignVerificationPolicy to refuse an all-zero-value policy (ADR-0007 Addendum 3 D36)")
	}
}

// TestDecodeUnsignedPolicyAcceptsTheCommittedExampleFixture is the
// control case D37 requires alongside the four rejections: a genuinely
// well-formed unsigned policy document -- the same shape as the
// committed test/fixtures/screening-ledger/policy example -- must still
// decode, validate, sign, and load cleanly. A validator that rejects
// everything is not a validator.
func TestDecodeUnsignedPolicyAcceptsTheCommittedExampleFixture(t *testing.T) {
	document := `{
		"schema_version":"openwatchlist.screening-ledger-verification-policy.v2",
		"ledger_id":"screening-api-v8g-example",
		"min_event_schema":"openwatchlist.screening-ledger-event.v2",
		"min_audit_schema":"openwatchlist.screening-ledger-audit.v2",
		"genesis_event_sequence":1,
		"genesis_audit_sequence":1,
		"allow_unanchored":false,
		"min_anchor_sequence":0
	}`
	policy, err := DecodeUnsignedPolicy(strings.NewReader(document))
	if err != nil {
		t.Fatalf("the committed example fixture's own shape must still decode and validate: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignVerificationPolicy(policy, priv)
	if err != nil {
		t.Fatalf("SignVerificationPolicy must still sign a valid policy: %v", err)
	}

	path := filepath.Join(t.TempDir(), "policy.signed.json")
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := LoadSignedVerificationPolicy(path, pub)
	if err != nil {
		t.Fatalf("LoadSignedVerificationPolicy must still load the signed, valid envelope: %v", err)
	}
	if loaded.LedgerID != policy.LedgerID {
		t.Fatalf("round-tripped ledger_id = %q, want %q", loaded.LedgerID, policy.LedgerID)
	}
}
