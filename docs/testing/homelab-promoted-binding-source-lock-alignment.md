# H1 r1.13.8 promoted-binding source-lock alignment

H1 r1.13.8 repairs the validation defect exposed by the real promoted binding.
The workfile represents frozen-source lineage with `frozen_source_lock_sha256`
but does not contain a source-lock ID field. Earlier verification incorrectly
required an ID unconditionally after the correct digest-only repair had been
produced.

## Contract

The repair remains pinned to the governed state and exact candidate pack:

- schema `openwatchlist.homelab.binding-candidates.v2`;
- candidate-set ID from the bound governed state;
- exact candidate-pack SHA-256 from that state;
- 35 archetypes and 280 bounded candidates;
- `review_eligible` quality gate;
- finalized frozen-source-lock SHA-256 and source hashes.

The proposed promoted workfile must preserve the canonical 35-binding array.
Only bounded source-lock lineage metadata outside `bindings`/`items` may change.

A matching frozen-source-lock SHA-256 is always required. A source-lock ID,
source hashes, or source-lock path are required only when the workfile represents
them or the binding-review runtime explicitly references them. Existing stale ID
or source-hash fields are never ignored.

## Safety

The installer snapshots the bound governed state, candidate pack, promoted
binding, and original acceptance evidence before replacement. It validates a
proposal first, replaces the promoted binding under rollback protection, then
runs repository validators, the real `show fp-001` context load, and the homelab
qualification Go tests. Any failure restores the promoted file and all installed
repair files and removes the incomplete r1.13.8 evidence directory.

The governed selections, set review, acceptance record, candidate pack, and
original acceptance evidence are immutable.
