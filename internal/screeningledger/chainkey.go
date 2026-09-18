package screeningledger

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
)

// ADR-0007 §5.1: the root secret loaded by LoadKey is never used directly
// for any primitive. Three subkeys derive from it via HKDF-SHA256, salted
// by the ledger ID so two ledgers sharing a root secret do not share
// subkeys, and domain-separated by these info strings.
//
// This claim was false on cmd/screening-ledger's default path before
// Addendum 1 D14/F9: the CLI's --ledger-id default was the shared
// literal "screening-ledger-cli", durably written into every
// CLI-bootstrapped ledger that didn't pass an explicit --ledger-id, so
// two such ledgers under one root secret derived identical subkeys. D14
// removes that default (main.go's resolveLedgerID requires an explicit
// --ledger-id or a signed --policy-file), which is what makes this
// comment's claim true rather than aspirational -- corrected here, as
// Addendum 1's own text says it would be.
const (
	infoSnapshotAEAD       = "openwatchlist/screening-ledger/snapshot-aead/v2"
	infoRedactionPseudonym = "openwatchlist/screening-ledger/redaction-pseudonym/v2"
	infoChainMAC           = "openwatchlist/screening-ledger/chain-mac/v2"
)

// chainKeys holds the three subkeys derived from a ledger's root secret.
type chainKeys struct {
	snap   []byte // K_snap: encryptSnapshot / decryptSnapshot
	redact []byte // K_redact: RedactJSON's hmacHex pseudonyms
	chain  []byte // K_chain: hashEvent / hashAudit
}

// AssertAnchorKeyDisjoint is ADR-0007 Addendum 20 D157 (G5): §5.3 point 1
// makes K_anchor not-derived-from-R load-bearing ("otherwise the anchor
// proves nothing beyond the chain MAC"), and before this it was asserted
// only by a unit test on deriveChainKeys's own output, never against the
// bytes an operator actually loads at runtime. Measured on a freshly
// provisioned, never-anchored mirror: loading the same 32 bytes as both R
// and K_anchor produces a genesis anchor with no refusal anywhere.
//
// This is operator-misconfiguration protection (a byte comparison against
// a value this same process just derived), not a §2 adversary path -- LOW,
// per D157 -- so a plain constant-time comparison is all it needs; there is
// no secret on the other side of this check that a timing side-channel
// could leak beyond what the caller already possesses.
func AssertAnchorKeyDisjoint(root, kAnchor []byte, ledgerID string) error {
	if len(kAnchor) != 32 {
		return errors.New("anchor key (K_anchor) must be 32 bytes")
	}
	keys, err := deriveChainKeys(root, ledgerID)
	if err != nil {
		return err
	}
	named := []struct {
		name string
		key  []byte
	}{
		{"the root secret R", root},
		{"K_snap (the derived snapshot-AEAD subkey)", keys.snap},
		{"K_redact (the derived redaction-pseudonym subkey)", keys.redact},
		{"K_chain (the derived chain-MAC subkey)", keys.chain},
	}
	for _, n := range named {
		if subtle.ConstantTimeCompare(kAnchor, n.key) == 1 {
			return fmt.Errorf("anchor key (K_anchor) must not equal %s (ADR-0007 Addendum 20 D157 / §5.3 point 1): loading the same bytes for both means the anchor proves nothing beyond the chain MAC it is meant to corroborate independently", n.name)
		}
	}
	return nil
}

func deriveChainKeys(root []byte, ledgerID string) (chainKeys, error) {
	salt := []byte(ledgerID)
	snap, err := hkdf.Key(sha256.New, root, salt, infoSnapshotAEAD, 32)
	if err != nil {
		return chainKeys{}, err
	}
	redact, err := hkdf.Key(sha256.New, root, salt, infoRedactionPseudonym, 32)
	if err != nil {
		return chainKeys{}, err
	}
	chain, err := hkdf.Key(sha256.New, root, salt, infoChainMAC, 32)
	if err != nil {
		return chainKeys{}, err
	}
	return chainKeys{snap: snap, redact: redact, chain: chain}, nil
}
