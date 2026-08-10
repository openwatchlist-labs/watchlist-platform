# Phase 2D — Delta refresh, catalog diff, and promotion policy

Phase 2D adds an administrative delta layer without changing the live screening path. A delta is never applied to an active catalog or an active `.owpcat` package. The update manager reconstructs a complete candidate catalog in isolated state, validates its identity, evaluates a promotion policy, and only then compiles a new immutable runtime package.

## Contracts

- `ofac-catalog-delta/v1alpha1`
- `catalog-diff-report/v1alpha1`
- `catalog-promotion-policy/v1alpha1`
- `catalog-promotion-decision/v1alpha1`
- `catalog-refresh-replay/v1alpha1`
- engine: `catalog-refresh-engine/v0.1.0`

## Off-path reconstruction

```text
immutable base catalog A
        +
ordered, content-addressed delta N
        |
        v
precondition validation
        |
        v
complete reconstructed candidate catalog B
        |
        +--> semantic diff A -> B
        +--> target checksum verification
        +--> optional independent full-rebuild parity
        |
        v
promotion decision
  promote_delta | force_full_rebuild | reject
```

No operation mutates catalog A. Add, replace, and remove operations are applied to a private record map. Replace and remove operations carry a SHA-256 precondition for the exact prior record, preventing stale or out-of-order changes from silently applying.

## Delta identity and sequence

Each delta records:

- monotonically increasing sequence;
- exact base catalog ID, version, checksum, and record count;
- exact target catalog ID, version, checksum, and record count;
- target source-manifest lineage;
- canonical, record-ID-ordered operations;
- deterministic delta checksum and delta ID; and
- generation timestamp.

A sequence gap, base checksum mismatch, duplicate operation, unknown operation, invalid add/replace/remove precondition, target checksum mismatch, or delta checksum drift yields `reject`.

## Semantic diff

The diff report measures:

- added, modified, removed, and unchanged records;
- total changes;
- change ratio in integer basis points;
- deletion ratio in integer basis points;
- affected provider record IDs; and
- changed field categories such as aliases, identifiers, programs, addresses, remarks, dates, and source assertions.

The change-ratio denominator is the larger of the base and target record counts. The deletion-ratio denominator is the base record count.

## Promotion policy

The reference policy uses:

```json
{
  "max_change_ratio_basis_points": 2000,
  "max_deletion_ratio_basis_points": 1000,
  "max_operations": 1000,
  "force_full_at_or_above_threshold": true,
  "require_contiguous_sequence": true,
  "require_base_checksum_match": true,
  "require_target_checksum_match": true,
  "full_rebuild_verification_interval": 10
}
```

The 20% rule is configurable rather than embedded in matching code. With `force_full_at_or_above_threshold=true`, exactly 20% also forces a full rebuild. Periodic full-rebuild verification remains required even when all intermediate deltas are small.

## Outcomes

### `promote_delta`

The reconstructed target is complete, sequence-correct, checksum-correct, within policy thresholds, and eligible for deterministic `.owpcat` compilation and the existing Phase 2C canary protocol.

### `force_full_rebuild`

The delta is valid, but its change volume, deletion volume, operation count, or periodic verification schedule requires rebuilding from a comprehensive source. The current fleet pointer remains unchanged.

### `reject`

The delta cannot be trusted because identity, sequence, preconditions, checksums, or optional full-rebuild parity failed. The current fleet pointer remains unchanged.

## Independent full-rebuild parity

When a comprehensive target catalog is available, Phase 2D can compare it with the delta reconstruction before promotion. The regression gate proves:

```text
delta reconstruction checksum == full rebuild checksum
compiled delta package bytes   == compiled full package bytes
compiled package ID            == compiled full package ID
```

This is a strong administrative validation path and does not require raw-list parsing on screening workers.

## Update-manager integration

`Manager.PrepareDelta` performs:

1. scheduled not-before enforcement;
2. immutable delta persistence;
3. promotion evaluation and immutable decision persistence;
4. no compilation for `reject` or `force_full_rebuild`;
5. deterministic package compilation only for `promote_delta`; and
6. audit events for delta staging, promotion decision, and package compilation.

The existing Phase 2C readiness, canary, fleet activation, drain, rollback, and audit protocol is reused without modification.

## Persistent state

```text
<state-dir>/
  deltas/<delta-id>.json
  promotion-decisions/<decision-id>.json
  packages/<package-id>.owpcat
  updates/<update-id>.json
  ... Phase 2C worker/fleet/audit state ...
```

Delta and decision records use immutable exclusive-create semantics.

## CLI

Run the deterministic fixture replay:

```bash
go run ./cmd/catalog-refresh --command simulate
```

Build and evaluate a delta:

```bash
go run ./cmd/catalog-refresh \
  --command build-delta \
  --base-catalog base.json \
  --target-catalog target.json \
  --sequence 1 \
  --generated-at 2026-07-13T19:03:00Z \
  > delta.json

go run ./cmd/catalog-refresh \
  --command evaluate \
  --base-catalog base.json \
  --delta delta.json \
  --policy test/fixtures/catalog-refresh/promotion-policy-v1.json \
  --expected-sequence 1 \
  --full-target target.json
```

## Deliberate limits

Phase 2D does not parse an OFAC-published delta format, automatically poll for deltas, patch worker memory, or alter screening behavior. Provider-specific delta acquisition and scheduling may be added later, but they must produce this normalized immutable delta contract before promotion.
