package screeningledger

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// VerificationPolicySchemaV1 is the schema_version of a VerificationPolicy
// document (ADR-0007 D10).
const VerificationPolicySchemaV1 = "openwatchlist.screening-ledger-verification-policy.v1"

// VerificationPolicy carries the externally-authenticated facts ADR-0007
// D8 names EA1-EA3: the minimum accepted schema version per chain, the
// genesis boundary as a sequence number, and the ledger this policy
// authenticates. It is never read out of the ledger directory -- see
// LoadSignedVerificationPolicy.
type VerificationPolicy struct {
	SchemaVersion        string `json:"schema_version"`
	LedgerID             string `json:"ledger_id"`
	MinEventSchema       string `json:"min_event_schema"`
	MinAuditSchema       string `json:"min_audit_schema"`
	GenesisEventSequence uint64 `json:"genesis_event_sequence"`
	GenesisAuditSequence uint64 `json:"genesis_audit_sequence"`
	AllowUnanchored      bool   `json:"allow_unanchored"`
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
	SignatureBase64 string              `json:"signature_base64"`
	PublicKeyBase64 string              `json:"public_key_base64,omitempty"`
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
	if envelope.Policy.SchemaVersion != VerificationPolicySchemaV1 {
		return VerificationPolicy{}, "", fmt.Errorf("verification policy schema_version %q is not %q", envelope.Policy.SchemaVersion, VerificationPolicySchemaV1)
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
	return envelope.Policy, digestHex(canon), nil
}

// PolicyPublicKeyFingerprint is EA5 made concrete: the SHA-256 fingerprint
// of the trust-root public key a verification run used, meant to be
// printed in the same output an operator reads status from (D10: "makes
// that termination auditable rather than assumed").
func PolicyPublicKeyFingerprint(trustedPublicKey ed25519.PublicKey) string {
	return digestHex(trustedPublicKey)
}
