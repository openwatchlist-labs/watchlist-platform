# Phase 1D: Matcher provider and candidate-result contracts

Phase 1D defines the stable boundary between Phase 1C candidate-search requests and future watchlist catalogs. It does not ingest OFAC data and it does not make sanctions or policy decisions.

## Responsibilities

A provider adapter owns catalog-specific lookup only:

```text
candidate-search request
  -> provider adapter
  -> provider-neutral catalog candidates
```

The platform runner owns:

- provider descriptor and capability validation;
- request-route and target-entity compatibility checks;
- atomic batch execution;
- candidate validation and canonical ordering;
- content-addressed candidate, result, batch, and replay identifiers;
- request, screening-plan, provider, catalog, and source-assertion lineage; and
- strict result and replay validation.

A provider cannot reinterpret the ISO 20022 field, change the screening plan, alter the request query, or produce a policy outcome.

## Provider interface

```go
type Provider interface {
    Descriptor() ProviderDescriptor
    Search(context.Context, matcherrequest.CandidateSearchRequest) ([]ProviderCandidate, error)
}
```

`ProviderDescriptor` identifies the adapter and immutable catalog snapshot. It declares supported match routes, candidate types, maximum candidates per request, deterministic behavior, and source-assertion support.

Catalog modes are established now so later adapters do not change the result contract:

- `direct_list` — one candidate corresponds to an official source-list record;
- `provider_entity` — one candidate corresponds to a consolidated provider entity; and
- `hybrid_overlay` — a provider entity is augmented by direct-list assertions.

## Candidate-result contracts

Phase 1D introduces:

```text
matcher-provider-descriptor/v1alpha1
candidate-search-result/v1alpha1
candidate-result-batch/v1alpha1
matcher-provider-replay-envelope/v1alpha1
matcher-provider-runner/v0.1.0
```

Each result preserves the complete request context needed to interpret the candidate:

- request, message, transaction, native path, and occurrence;
- semantic role, party role, value type, and trigger policy;
- query, routes, target entity types, and profiles;
- evidence, canonical-element, source-payload, parser, executor, and screening-plan lineage;
- provider and immutable catalog identity; and
- provider record/entity identifiers and source assertions.

Candidate scores are provider retrieval scores expressed as integer basis points from 0 through 10,000. They are not policy scores and cannot produce `clear`, `investigate`, or `escalate` decisions.

## Determinism

The runner preserves input request order. Candidates are ordered by:

```text
score descending
exact match before non-exact
provider record ID ascending
match route ascending
normalized matched value ascending
```

Candidate, result, result-batch, and provider-replay IDs are content-addressed. Any mutation to a candidate value, score, route, source assertion, catalog checksum, or request lineage invalidates the contract.

Execution is atomic: a provider error or invalid candidate returns no partial result batch.

## Synthetic fixture provider

`test/fixtures/providers/synthetic/synthetic-catalog-v1.json` is a strict, test-only provider-entity catalog. It exercises names, aliases, BICs, LEIs, accounts, dates, addresses, jurisdictions, narratives, and source assertions. It contains synthetic data and is not an OFAC loader or a production matching implementation.

Run a persisted Phase 1C request batch:

```bash
go run ./cmd/matcher-run \
  --input requests \
  --output results \
  --catalog test/fixtures/providers/synthetic/synthetic-catalog-v1.json \
  test/golden/iso20022/pacs008/pacs008-basic.matcher-requests.json
```

Run the complete provider replay contract:

```bash
go run ./cmd/matcher-run \
  --input replay \
  --output replay \
  --catalog test/fixtures/providers/synthetic/synthetic-catalog-v1.json \
  test/golden/iso20022/pacs008/pacs008-basic.replay.json
```

## Future adapter mapping

Phase 2 can implement an OFAC direct-list provider behind the same interface:

```text
OFAC source record
  -> direct_list ProviderCandidate
  -> platform candidate result
```

A later OpenSanctions-like or commercial provider adapter can emit consolidated entities and multiple source assertions using `provider_entity` or `hybrid_overlay`. Neither path requires changes to the Phase 1C request contract or the Phase 1D public result contracts.

## Non-goals

Phase 1D does not implement:

- OFAC download, parsing, refresh, or source-record storage;
- fuzzy name scoring or transliteration algorithms;
- ownership, control, or relationship expansion;
- candidate comparison or alert aggregation;
- false-positive classification; or
- policy disposition.
