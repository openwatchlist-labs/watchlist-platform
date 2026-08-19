package screeningledger

import (
	"crypto/hkdf"
	"crypto/sha256"
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
