package screeningledger

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// VerificationPolicySchemaV1 is the schema_version of a VerificationPolicy
// document as originally specified by ADR-0007 D10. Retired by Addendum 2
// D25 -- LoadSignedVerificationPolicy no longer accepts it (see the
// exact-equality check below) -- kept only so error messages and any
// historical reference to it stay meaningful.
const VerificationPolicySchemaV1 = "openwatchlist.screening-ledger-verification-policy.v1"

// VerificationPolicySchemaV2 is ADR-0007 Addendum 2 D25: adds
// MinAnchorSequence (EA4's floor, committed under the same Ed25519
// signature as EA1-EA3) to the policy document. This is a schema change,
// not an additive field on v1 -- policy.go:112's exact-equality pin
// means a v1-labeled document is rejected outright by a v2 verifier
// rather than silently narrowed to the fields the old struct knows,
// exactly as D8 chose for the analogous chain-schema check. Adding the
// field is free now (zero anchor rows exist in any environment --
// screening-ledger remains absent from runtime_executables) and never
// free again, the same argument D11 made for db/migrations/017.
const VerificationPolicySchemaV2 = "openwatchlist.screening-ledger-verification-policy.v2"

// VerificationPolicy carries the externally-authenticated facts ADR-0007
// D8 names EA1-EA3, plus Addendum 2 D25's MinAnchorSequence (EA4's
// floor): the minimum accepted schema version per chain, the genesis
// boundary as a sequence number, the ledger this policy authenticates,
// and the minimum anchor sequence a verified anchor must be at or above.
// It is never read out of the ledger directory -- see
// LoadSignedVerificationPolicy.
type VerificationPolicy struct {
	SchemaVersion        string `json:"schema_version"`
	LedgerID             string `json:"ledger_id"`
	MinEventSchema       string `json:"min_event_schema"`
	MinAuditSchema       string `json:"min_audit_schema"`
	GenesisEventSequence uint64 `json:"genesis_event_sequence"`
	GenesisAuditSequence uint64 `json:"genesis_audit_sequence"`
	AllowUnanchored      bool   `json:"allow_unanchored"`
	// MinAnchorSequence (D25): 0 means no floor is asserted -- the correct
	// value for a ledger's first policy, since no anchor exists yet.
	// Raising it above zero is a policy re-issue, which by D11 is a
	// re-anchoring event, so the new floor is always satisfiable by
	// construction at the moment it is signed.
	MinAnchorSequence uint64 `json:"min_anchor_sequence"`
}

// Validate is ADR-0007 Addendum 3 D36 (G-F): validity defined as a
// property of the artifact, enforced by one function called from both
// the producing end (SignVerificationPolicy) and the consuming end
// (LoadSignedVerificationPolicy) -- a policy that cannot be validated can
// be neither produced nor consumed. Before this, policy.go:135's
// exact-equality schema check was the sole check, applied only at load;
// CAP #2 §7.8 signed an invalid document with no complaint at all,
// because nothing on the producing side ever asked.
func (p VerificationPolicy) Validate() error {
	if p.SchemaVersion != VerificationPolicySchemaV2 {
		return fmt.Errorf("verification policy schema_version %q is not %q", p.SchemaVersion, VerificationPolicySchemaV2)
	}
	if strings.TrimSpace(p.LedgerID) == "" {
		return errors.New("verification policy ledger_id must not be empty")
	}
	if _, ok := eventSchemaOrdinal(p.MinEventSchema); !ok {
		return fmt.Errorf("verification policy min_event_schema %q is not a recognized event schema version", p.MinEventSchema)
	}
	if _, ok := auditSchemaOrdinal(p.MinAuditSchema); !ok {
		return fmt.Errorf("verification policy min_audit_schema %q is not a recognized audit schema version", p.MinAuditSchema)
	}
	if p.GenesisEventSequence < 1 {
		return errors.New("verification policy genesis_event_sequence must be >= 1 (sequence numbering starts at 1; 0 is not a boundary, it is an unset field)")
	}
	if p.GenesisAuditSequence < 1 {
		return errors.New("verification policy genesis_audit_sequence must be >= 1 (sequence numbering starts at 1; 0 is not a boundary, it is an unset field)")
	}
	return nil
}

// unsignedPolicyInput is ADR-0007 Addendum 3 D36: the shape an unsigned
// policy document is decoded through before signing, distinct from
// VerificationPolicy itself. Every field is a pointer so an omitted key
// is distinguishable from its zero value -- the gap CAP #2 §7.8 walked
// through: a typo'd or omitted min_anchor_sequence both silently produced
// a signed floor of 0, and min_anchor_sequence is the only mechanism
// bounding anchor rollback (D25, R14).
type unsignedPolicyInput struct {
	SchemaVersion        *string `json:"schema_version"`
	LedgerID             *string `json:"ledger_id"`
	MinEventSchema       *string `json:"min_event_schema"`
	MinAuditSchema       *string `json:"min_audit_schema"`
	GenesisEventSequence *uint64 `json:"genesis_event_sequence"`
	GenesisAuditSequence *uint64 `json:"genesis_audit_sequence"`
	AllowUnanchored      *bool   `json:"allow_unanchored"`
	MinAnchorSequence    *uint64 `json:"min_anchor_sequence"`
}

// DecodeUnsignedPolicy is ADR-0007 Addendum 3 D36: strict decoding
// (json.Decoder.DisallowUnknownFields, the same established pattern
// cmd/policy-evaluate, cmd/release-config, cmd/catalog-registry and
// cmd/matcher-project already use) catches a misspelled field name --
// CAP #2 §7.8's "min_anchor_seqence" -- as a decode error rather than a
// silently ignored key; presence-checking every pointer field catches an
// omitted one, which strict decoding alone does not. Both are required
// before this ever reaches Validate(). This is the sole path
// cmd/screening-ledger-policy's sign command uses to read its input --
// see D36's own text: enforcing at only one end (the consumer) would
// leave the producer as the gap, which is exactly what policy.go:135
// being the sole check produced.
func DecodeUnsignedPolicy(r io.Reader) (VerificationPolicy, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var in unsignedPolicyInput
	if err := dec.Decode(&in); err != nil {
		return VerificationPolicy{}, fmt.Errorf("decode unsigned policy document (ADR-0007 Addendum 3 D36): %w", err)
	}
	var missing []string
	if in.SchemaVersion == nil {
		missing = append(missing, "schema_version")
	}
	if in.LedgerID == nil {
		missing = append(missing, "ledger_id")
	}
	if in.MinEventSchema == nil {
		missing = append(missing, "min_event_schema")
	}
	if in.MinAuditSchema == nil {
		missing = append(missing, "min_audit_schema")
	}
	if in.GenesisEventSequence == nil {
		missing = append(missing, "genesis_event_sequence")
	}
	if in.GenesisAuditSequence == nil {
		missing = append(missing, "genesis_audit_sequence")
	}
	if in.AllowUnanchored == nil {
		missing = append(missing, "allow_unanchored")
	}
	if in.MinAnchorSequence == nil {
		missing = append(missing, "min_anchor_sequence")
	}
	if len(missing) > 0 {
		return VerificationPolicy{}, fmt.Errorf("unsigned policy document is missing required field(s): %s (ADR-0007 Addendum 3 D36) -- an operator who genuinely wants no anchor floor must write \"min_anchor_sequence\": 0 and mean it; silence is not a value", strings.Join(missing, ", "))
	}
	policy := VerificationPolicy{
		SchemaVersion:        *in.SchemaVersion,
		LedgerID:             *in.LedgerID,
		MinEventSchema:       *in.MinEventSchema,
		MinAuditSchema:       *in.MinAuditSchema,
		GenesisEventSequence: *in.GenesisEventSequence,
		GenesisAuditSequence: *in.GenesisAuditSequence,
		AllowUnanchored:      *in.AllowUnanchored,
		MinAnchorSequence:    *in.MinAnchorSequence,
	}
	if err := policy.Validate(); err != nil {
		return VerificationPolicy{}, err
	}
	return policy, nil
}

// SignedVerificationPolicy is the on-disk envelope: the policy document
// plus an Ed25519 signature over its canonical form (D10) and, for human
// convenience only, the public key that produced it. The signature is
// NEVER checked against SignedVerificationPolicy.PublicKeyBase64 -- an
// adversary who can replace the policy file can replace that field too.
// It is always checked against the caller-supplied trust-root public key
// (EA5), loaded independently via LoadEd25519PublicKey.
type SignedVerificationPolicy struct {
	Policy          VerificationPolicy `json:"policy"`
	SignatureBase64 string             `json:"signature_base64"`
	PublicKeyBase64 string             `json:"public_key_base64,omitempty"`
}

// canonicalPolicyBytes is what gets signed and what the signature is
// checked against. D10: "unlike Event, this document is authored by hand
// and by tooling, so its byte form cannot be pinned to a Go struct
// declaration" -- so signing and verification both go through the same
// canonicalJSON helper this package already uses for snapshot bodies
// (crypto.go), not through json.Marshal's struct-order-dependent output.
func canonicalPolicyBytes(policy VerificationPolicy) ([]byte, error) {
	raw, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	return canonicalJSON(raw)
}

// PolicySHA256 is the digest that binds an anchor row to the policy it
// was written under (D11): sha256 of the policy's canonical bytes, hex
// encoded, matching this package's existing digest convention.
func PolicySHA256(policy VerificationPolicy) (string, error) {
	canon, err := canonicalPolicyBytes(policy)
	if err != nil {
		return "", err
	}
	return digestHex(canon), nil
}

// SignVerificationPolicy signs policy with priv and returns the envelope
// to write to the policy file. This is an operator-initiated, rare
// action (D10: "used at ledger-provisioning time and at policy-change
// time") -- there is no CLI subcommand for it; it is exposed as a
// package function for whatever out-of-band tooling an operator runs it
// from, deliberately kept out of the appending/verifying process.
func SignVerificationPolicy(policy VerificationPolicy, priv ed25519.PrivateKey) (SignedVerificationPolicy, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return SignedVerificationPolicy{}, fmt.Errorf("Ed25519 private key must be %d bytes", ed25519.PrivateKeySize)
	}
	// ADR-0007 Addendum 3 D36 (G-F): refuses to sign an invalid policy --
	// CAP #2 §7.8 signed a typo'd/omitted min_anchor_sequence, a retired
	// v1 document with empty fields, and {"hello":"world"}, all four
	// producing a validly signed artifact. A signer that does not examine
	// its input at all is the gap; this closes it at the producing end.
	if err := policy.Validate(); err != nil {
		return SignedVerificationPolicy{}, fmt.Errorf("refusing to sign an invalid policy (ADR-0007 Addendum 3 D36): %w", err)
	}
	canon, err := canonicalPolicyBytes(policy)
	if err != nil {
		return SignedVerificationPolicy{}, err
	}
	sig := ed25519.Sign(priv, canon)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return SignedVerificationPolicy{}, errors.New("unexpected Ed25519 public key type")
	}
	return SignedVerificationPolicy{
		Policy:          policy,
		SignatureBase64: base64.StdEncoding.EncodeToString(sig),
		PublicKeyBase64: base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// LoadSignedVerificationPolicy reads path, verifies its signature under
// trustedPublicKey (the operator-supplied trust root, EA5 -- never the
// embedded public_key_base64 field, which an adversary who replaces the
// policy file controls too), and returns the authenticated policy plus
// its canonical-form SHA-256 (for D11's anchor policy_sha256 binding).
func LoadSignedVerificationPolicy(path string, trustedPublicKey ed25519.PublicKey) (VerificationPolicy, string, error) {
	if len(trustedPublicKey) != ed25519.PublicKeySize {
		return VerificationPolicy{}, "", fmt.Errorf("policy trust-root public key must be %d bytes", ed25519.PublicKeySize)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return VerificationPolicy{}, "", fmt.Errorf("read verification policy: %w", err)
	}
	var envelope SignedVerificationPolicy
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return VerificationPolicy{}, "", fmt.Errorf("parse verification policy: %w", err)
	}
	canon, err := canonicalPolicyBytes(envelope.Policy)
	if err != nil {
		return VerificationPolicy{}, "", err
	}
	sig, err := base64.StdEncoding.DecodeString(envelope.SignatureBase64)
	if err != nil {
		return VerificationPolicy{}, "", fmt.Errorf("decode verification policy signature: %w", err)
	}
	if !ed25519.Verify(trustedPublicKey, canon, sig) {
		return VerificationPolicy{}, "", errors.New("verification policy signature is invalid under the configured trust-root public key")
	}
	// ADR-0007 Addendum 3 D36: Validate() replaces the previous bare
	// schema_version equality check -- still the same exact-equality pin
	// (Validate's first check), now joined by every other fact D36 names,
	// checked after the signature so an attacker who cannot forge a
	// signature cannot use an invalid-but-signed document to reach here
	// either.
	if err := envelope.Policy.Validate(); err != nil {
		return VerificationPolicy{}, "", fmt.Errorf("signed verification policy failed validation (ADR-0007 Addendum 3 D36): %w", err)
	}
	return envelope.Policy, digestHex(canon), nil
}

// PolicyPublicKeyFingerprint is EA5 made concrete: the SHA-256 fingerprint
// of the trust-root public key a verification run used, meant to be
// printed in the same output an operator reads status from (D10: "makes
// that termination auditable rather than assumed").
func PolicyPublicKeyFingerprint(trustedPublicKey ed25519.PublicKey) string {
	return digestHex(trustedPublicKey)
}
