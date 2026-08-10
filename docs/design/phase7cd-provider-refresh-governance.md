# Phase 7C-D — Provider Refresh Governance

## Purpose

Phase 7C-D governs provider-catalog changes before they can alter the active screening data plane. It operates on provider-neutral Phase 7C-B catalog components and exact Phase 7C-C alert mappings. It does not hardcode provider dataset names and does not load full watchlist rows into PostgreSQL.

A provider refresh is evaluated in four steps:

```text
previous provider inventory
        +
candidate provider inventory
        +
explicit provider-declared rename directives
        +
active stable catalog components and alert mappings
        ↓
component-change and mapping-impact analysis
        ↓
ready or blocked immutable refresh candidate
        ↓
approve or reject decision
        ↓
compare-and-set registration and activation
        ↓
append-only rollback evidence when required
```

## Provider inventory contract

A provider adapter emits a sorted inventory containing opaque provider component references and immutable artifact metadata. References are provider metadata only. They never become platform list identities.

Each inventory component contains:

- provider component reference and title;
- catalog ID, version, schema, and checksum;
- artifact URI and SHA-256;
- source-manifest identity and checksum;
- record count and producer version; and
- optional provider metadata.

The inventory checksum covers the normalized complete inventory.

## Change classification

The analyzer reports:

- `added` — present only in the candidate inventory;
- `removed` — present only in the previous inventory and not covered by an explicit rename;
- `renamed` — exact administrator/provider-declared old-to-new reference mapping; and
- `unchanged` — exact provider component reference preserved.

Renames are never inferred with fuzzy matching. A rename directive must reference an existing previous component and an existing candidate component, and both sides must be unique.

New provider components do not automatically create stable Phase 7C-B components or Phase 7C-C mappings. An organization must explicitly register and map them.

## Mapping-impact analysis

For each active provider-mode catalog component, Phase 7C-D reads its currently active provider reference and counts exact alert-list mappings effective at analysis time. The report distinguishes:

- available under the same provider reference;
- available through an approved exact rename; and
- missing from the candidate provider inventory.

A missing component with active alert mappings produces `MAPPED_COMPONENT_UNAVAILABLE`. The target component must also be available before promotion. Alert mappings remain attached to the stable component ID throughout provider reference changes.

## Policy gates

The candidate records the exact policy used to evaluate it. Initial gates include:

- maximum added, removed, and renamed component counts;
- maximum record-count delta percentage for active components;
- provider ID continuity;
- availability of every component with active mappings; and
- availability of the selected promotion target.

A candidate is `ready` only when no policy violation exists. A blocked candidate cannot be approved.

## Promotion

Promotion is single stable-component activation backed by an inventory-wide impact analysis. It requires:

1. a `ready` immutable candidate;
2. a current explicit `approve` decision;
3. no previous promotion of the same candidate;
4. the active catalog version to equal the candidate's compare-and-set precondition;
5. successful immutable catalog-version registration; and
6. successful Phase 7C-B activation.

The provider reference is stored in the new catalog version metadata. The stable component ID and Phase 7C-C mappings do not change.

## Rollback

Rollback uses the Phase 7C-B rollback action and requires an exact current-version precondition. It creates:

- a new catalog activation event and component epoch; and
- a new Phase 7C-D execution event linked to the catalog activation.

History is never rewritten.

## Persistence boundary

The deterministic local reference store is:

```text
var/provider-refresh/<namespace>/
  registry.json
  candidates/<candidate-id>.json
  decisions/<sequence>-<decision-id>.json
  executions/<sequence>-<execution-id>.json
```

The PostgreSQL migration stores only refresh candidates, policy/change/impact metadata, decisions, executions, and foreign keys to Phase 7C-B catalog metadata. It does not store provider entities, names, aliases, addresses, identifiers, or relationships.

## CLI

```text
provider-refresh init
provider-refresh analyze
provider-refresh decide
provider-refresh promote
provider-refresh rollback
provider-refresh snapshot
provider-refresh verify
provider-refresh postgres-schema
```

## Acceptance criteria

- deterministic inventory normalization and checksums;
- exact component add/remove/rename classification;
- active alert-mapping impact counts;
- blocked mapped-component removal without an explicit rename;
- thresholded record-count and component-change gates;
- immutable approval/rejection evidence;
- compare-and-set promotion;
- stable component ID across provider reference rename;
- activation and rollback audit linkage;
- deterministic replay and tamper detection;
- PostgreSQL control-plane metadata only; and
- Phase 7C-C compatibility.
