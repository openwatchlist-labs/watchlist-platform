# Phase 7A — Provider-ready catalog and hybrid official overlay

## Purpose

Phase 7A proves that the provider-neutral matcher and review contracts can consume a consolidated provider-entity catalog without changing downstream APIs. The repository retains OFAC direct-list mode, adds an OpenSanctions-like synthetic snapshot adapter, and adds a hybrid mode that links provider entities back to official OFAC source records.

The fixture is synthetic and does not call or redistribute OpenSanctions data. It models the evidence shape expected from an OpenSanctions-like or commercial consolidated provider: one entity, multiple aliases and identifiers, and multiple immutable source memberships.

## Contracts

- `opensanctions-like-snapshot/v1alpha1`
- `provider-entity-catalog/v1alpha1`
- `hybrid-overlay-catalog/v1alpha1`
- `catalog-comparison/v1alpha1`
- adapter `opensanctions-like-adapter/v0.1.0`
- provider `opensanctions-like-provider/v0.1.0`
- hybrid provider `provider-entity-ofac-hybrid/v0.1.0`

The existing public matcher contracts remain unchanged:

- `matcher-provider-descriptor/v1alpha1`
- `candidate-result-batch/v1alpha1`
- `transaction-screening-observation-batch/v1alpha1`
- `review-run-bundle/v1alpha1`

## Provider entities and source memberships

A provider entity has a stable `provider_entity_id`, provider record ID, entity type, names, identifiers, addresses, dates, attributes, and ordered source memberships. Each active membership contains:

- source ID;
- source authority;
- list ID;
- source record ID;
- programs; and
- active state.

Matcher candidates carry the provider entity ID and convert active memberships into the existing `source_assertions` array. Downstream false-positive classification, policy evaluation, RAG, and review orchestration therefore retain source lineage without knowing which provider adapter produced it.

## Hybrid overlay

Hybrid mode accepts:

1. a checksum-protected provider-entity base catalog; and
2. a checksum-protected OFAC direct-list overlay.

The link key is:

```text
source_id + list_id + source_record_id
```

When an OFAC result links to a provider entity, hybrid mode preserves the provider entity identity and merges official source assertions. Exact official routes can win candidate ranking while consolidated entity identity remains stable. An official record with no provider membership remains available as an unlinked official-overlay candidate.

Hybrid mode never edits either source catalog. Its descriptor is content-addressed from both immutable catalog references and the merge policy.

## Catalog comparison

The comparison command reports:

- linked official records;
- provider-only entities;
- direct-only records;
- primary-name differences;
- entity-type differences; and
- program-membership differences.

The reference fixture contains four provider entities and three OFAC records. Three records link, one provider entity is provider-only, no OFAC record is missing from the provider snapshot, and one linked record intentionally has a program difference.

## Commands

Project the synthetic provider snapshot:

```bash
go run ./cmd/provider-catalog project \
  --snapshot test/fixtures/provider-entity/opensanctions-like-snapshot.json \
  --output /tmp/provider-catalog.json
```

Compare against OFAC direct-list evidence:

```bash
go run ./cmd/provider-catalog compare \
  --provider /tmp/provider-catalog.json \
  --direct test/golden/ofac/ofac-sdn-fixture.catalog.json
```

Run the provider-entity adapter:

```bash
go run ./cmd/matcher-run \
  --provider provider-entity \
  --catalog test/golden/provider-entity/provider-catalog.json \
  test/golden/matcher-baseline/pacs008-fuzzy-names.matcher-requests.json
```

Run the hybrid provider:

```bash
go run ./cmd/matcher-run \
  --provider hybrid-overlay \
  --catalog test/golden/provider-entity/provider-catalog.json \
  --overlay-catalog test/golden/ofac/ofac-sdn-fixture.catalog.json \
  test/golden/matcher-baseline/pacs008-fuzzy-names.matcher-requests.json
```

The resulting hybrid matcher batch can be passed directly to `review-run`; the locked regression produces eight review cases, seven `investigate` decisions, one exact-LEI `escalate` decision, eight completed retrievals, and no generated notes when note generation is disabled.

## Safety and scope

- Snapshot, catalog, hybrid descriptor, comparison, matcher result, and review-run outputs are deterministic and checksum or content addressed.
- Unknown JSON fields and checksum drift are rejected.
- Provider entities do not replace official source assertions.
- Official records do not silently overwrite consolidated entity identity.
- LLM behavior and deterministic policy behavior are unchanged.
- The prototype is an offline adapter contract, not a live OpenSanctions service integration.
