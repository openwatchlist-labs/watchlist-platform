# Operator procedure: signing a screening-ledger verification policy

ADR-0007 D8-D10 (as repaired by Addendum 2 D23). This is the procedure CAP §7.8 found missing
entirely: no policy-signing subcommand, no committed example, and no documentation anywhere in the
tree.

## What this key controls

`--policy-file` is required for every `screening-ledger` verification path (`status`, `verify`,
`sync`, `anchor`). Without a signed policy, verification cannot run at all. The Ed25519 private
key that signs a policy is therefore high-value: whoever holds it can produce a policy any
verifier will accept as authoritative for a ledger.

The private key is used only at two points in a ledger's lifecycle: provisioning (the first
policy) and policy change (e.g. raising the schema floor, or raising `min_anchor_sequence` per
ADR-0007 Addendum 2 D25). It is never read by `cmd/screening-ledger` itself, never enters the
appending or verifying process, and never enters CI.

## Where the private key lives

- On an offline host, not the ledger host and not any host running `cmd/screening-ledger`.
- Mode `0400` (`screening-ledger-policy keygen` writes it this way by default).
- Owned by a principal that is not the ledger directory's owner -- the same custody language
  ADR-0007 §5.2 sets for the root secret `R`, applied here to the policy signing key.
- Never committed to this or any other repository. (The keypair under
  `test/fixtures/screening-ledger/policy/` is example material for tests only -- see that
  directory's own README.)

## Generating a keypair

```sh
screening-ledger-policy keygen \
  --private-key-file /secure/offline/path/policy-signing-key.hex \
  --public-key-file ./policy-public-key.hex
```

The public key is also printed to stdout. Distribute it to every host that runs
`screening-ledger status|verify|sync|anchor` via `--policy-public-key-file` or
`--policy-public-key-env` -- never derive it from the policy file itself (EA5: the trust root is
always supplied independently of the artifact it authenticates).

## Signing a policy

Write the unsigned policy document (see `internal/screeningledger/policy.go`'s
`VerificationPolicy` for the current field set):

```json
{
  "schema_version": "openwatchlist.screening-ledger-verification-policy.v3",
  "ledger_id": "<this ledger's authenticated identity>",
  "min_event_schema": "openwatchlist.screening-ledger-event.v2",
  "min_audit_schema": "openwatchlist.screening-ledger-audit.v2",
  "genesis_event_sequence": 1,
  "genesis_audit_sequence": 1,
  "allow_unanchored": false,
  "min_anchor_sequence": 0,
  "genesis_event_sha256": "",
  "genesis_audit_sha256": ""
}
```

`genesis_event_sequence`/`genesis_audit_sequence` of `1` means no `v1` (pre-D2, unkeyed) prefix is
permitted at all -- the correct value for a ledger with no genuine pre-D2 history.
`min_anchor_sequence` of `0` means no floor is asserted -- the correct value for a ledger's first
policy, since no anchor exists yet (ADR-0007 Addendum 2 D25). Raising it later, once real anchors
exist, is what makes a full anchor-table wipe detectable without needing to trust the table's
owner: an absent or below-floor anchor fails verification outright, rather than being reported as
a legitimate absence.

**`genesis_event_sha256`/`genesis_audit_sha256` (ADR-0007 Addendum 4 D38(b)) commit to the frozen
prefix the genesis boundary declares** -- without this pin, the boundary was a claim about the
ledger checked against nothing in it, and CAP #3's CRITICAL finding (H-A) showed a boundary set far
above the chain's actual head silently downgrades the whole chain to unkeyed verification. The rule:

- **`genesis_event_sequence`/`genesis_audit_sequence` of `1`** (no `v1` prefix, the value above and
  every real ledger today, per ADR-0007 §6.1): the companion `_sha256` field must be the
  **empty-string sentinel** `""`. No ledger needs to exist yet to write this -- it is a complete,
  signable bootstrap document.
- **A value `N` greater than `1`** (a ledger with a genuine frozen `v1` prefix): the companion
  field must be the 64-character lowercase-hex `EventSHA256`/`AuditSHA256` of the chain entry at
  sequence `N-1` -- read once from that entry, from `screening-ledger status`'s output or the
  entry file itself. This does not need to be re-read on every re-issue: `Append`/`AppendAudit`
  never write a `v1` entry, so the frozen prefix and its pinned digest never change for the life of
  the ledger. A policy re-issue that only raises `min_anchor_sequence` or changes
  `allow_unanchored` carries the same two pin values forward unchanged.

Then, on the offline host holding the private key:

```sh
screening-ledger-policy sign \
  --policy-file ./policy.json \
  --private-key-file /secure/offline/path/policy-signing-key.hex \
  --output ./policy.signed.json
```

Distribute `policy.signed.json` to every verifying host via `--policy-file`. It is not secret --
its integrity, not its confidentiality, is what matters, and that is what the signature protects.

## Verifying a trust-root fingerprint out of band

```sh
screening-ledger-policy fingerprint --public-key-file ./policy-public-key.hex
```

This prints the same SHA-256 fingerprint `screening-ledger verify`'s JSON output carries as
`policy_public_key_fingerprint` (EA5). Compare it against an out-of-band record (a runbook, a
change ticket) before trusting a verification result -- R8's stated residual is that an adversary
who can replace both the policy file and the public key a verifier is configured with defeats
EA1-EA3, and fingerprint disclosure is the only mitigation this design provides. Nothing in the
system compares the fingerprint automatically.

## A policy change is a re-anchoring event

`screening_ledger_anchor.policy_sha256` binds each anchor row to the policy it was written under
(ADR-0007 D11). Re-signing a policy (raising the schema floor, or raising `min_anchor_sequence`,
D25) means the next `screening-ledger anchor` run commits a new `policy_sha256`; verification
against the old anchor row and the new policy will fail until that re-anchoring happens. This is
intentional: a policy change is a change to what the ledger claims about itself, and it must be
re-committed, not silently absorbed.

## Raising `min_anchor_sequence`

Once a ledger has real anchor rows, re-signing its policy with a higher `min_anchor_sequence`
ratchets the floor below which a rollback becomes detectable (D25). Two things worth knowing
before doing this:

- The new floor must already be satisfied by the current anchor at the moment the policy is
  signed -- verification would otherwise fail immediately after distributing it. Check the
  ledger's current anchor sequence (`anchor_sequence` in `screening-ledger verify`'s output)
  before choosing a value.
- This bounds rollback to the new floor; it does not prevent rollback to it. An adversary holding
  DDL authority over the anchor table can still roll back to any sequence at or above the floor
  (see ADR-0007 Addendum 2 D25's own stated limit, and D26 for the mechanism that closes the
  residual this cannot).
