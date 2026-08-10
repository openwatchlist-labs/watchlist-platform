# Phase 1C: Matcher Request Projection and Replay Contracts

## 1. Purpose

Phase 1C converts Phase 1B match-eligible evidence into deterministic candidate-search requests. It creates the stable boundary between message interpretation and future list-catalog or matcher implementations.

The projection layer does not search a watchlist, score a candidate, or make a case decision. It selects only evidence explicitly marked `eligible_for_matching`, preserves all source and screening-plan lineage, and emits content-addressed request and replay contracts.

## 2. Contract versions

Phase 1C introduces:

```text
candidate-search-request/v1alpha1
candidate-search-request-batch/v1alpha1
matcher-replay-envelope/v1alpha1
matcher-request-projector/v0.1.0
```

Contract changes must be intentional, versioned, and accompanied by golden-file review.

## 3. Projection rule

A Phase 1B element is projected only when:

```text
resolution.eligible_for_matching = true
```

This requires a present value and one of these trigger policies:

```text
candidate_alert
supporting_evidence
```

The following evidence remains in the Phase 1B bundle but cannot produce a request:

```text
retain_only
disabled
skip_empty
skip_invalid
```

Requests retain evidence order. The projector does not regroup, merge, infer, or deduplicate fields. One eligible evidence element produces one request.

## 4. Candidate-search request

Each request includes:

- deterministic request ID;
- candidate-alert or supporting-evidence request kind;
- message and transaction identity;
- native ISO 20022 path and occurrence;
- semantic role, party role, and value type;
- original and normalized query values;
- retained XML attributes;
- trigger policy;
- ordered match routes;
- target entity types;
- normalization and threshold profiles;
- supporting-field role declarations; and
- full source, evidence, parser, executor, and plan lineage.

The request ID is content-addressed from the complete request contract. Changing a query value, route, target type, profile, evidence reference, or plan checksum changes the request ID.

## 5. Request batch

A request batch is a deterministic message-level handoff containing:

- input evidence-bundle ID;
- message identity and source reference;
- parser, executor, and projector versions;
- screening-plan ID, version, and checksum;
- ordered requests; and
- summary counts by request kind, transaction, route, and target entity type.

The batch ID is derived from the lineage fields and ordered request IDs. Reordering requests therefore changes the batch identity and is treated as a contract change.

For the representative `pacs008-basic.xml` fixture:

```text
total requests: 30
candidate-alert requests: 14
supporting-evidence requests: 16
transactions: 1
```

## 6. Replay envelope

The replay envelope embeds the complete request batch and pins the projection behavior:

```text
selection_policy: eligible_for_matching_only
ordering_policy: evidence_order
identity_policy: content_addressed
lineage_policy: full_source_and_plan_lineage
```

It also records the evidence schema, evidence-bundle ID, source reference, parser version, executor version, projector version, and screening-plan reference.

No wall-clock timestamp is included. The same validated evidence bundle must reproduce the same request batch and replay ID on any machine using the same contract implementation.

## 7. CLI workflows

Project directly from ISO 20022 XML:

```bash
go run ./cmd/iso20022-inspect \
  --output matcher-requests \
  --source-ref fixture:pacs008-basic.xml \
  test/fixtures/iso20022/pacs008/pacs008-basic.xml
```

Build a replay envelope directly from XML:

```bash
go run ./cmd/iso20022-inspect \
  --output replay \
  --source-ref fixture:pacs008-basic.xml \
  test/fixtures/iso20022/pacs008/pacs008-basic.xml
```

Reproject a persisted evidence bundle:

```bash
go run ./cmd/matcher-project \
  --output requests \
  test/golden/iso20022/pacs008/pacs008-basic.evidence.json
```

Rebuild its replay envelope:

```bash
go run ./cmd/matcher-project \
  --output replay \
  test/golden/iso20022/pacs008/pacs008-basic.evidence.json
```

The persisted-evidence CLI uses strict JSON decoding and rejects unknown fields, trailing JSON values, invalid evidence IDs, bundle drift, and inconsistent summaries.

## 8. Golden contracts

Phase 1C adds:

```text
test/golden/iso20022/pacs008/
  pacs008-basic.matcher-requests.json
  pacs008-basic.replay.json
  pacs008-multi-transaction.matcher-requests.json
```

The golden gate requires direct XML projection and persisted-evidence projection to be byte-for-byte identical.

## 9. Regression and integrity gates

Tests and validation assert:

- only match-eligible evidence becomes a request;
- retain-only, disabled, empty, and invalid elements do not become requests;
- one evidence ID cannot produce duplicate requests;
- request order follows evidence order;
- request, batch, and replay IDs are deterministic;
- any request-value, route, target, profile, or lineage drift is rejected;
- plan and source lineage match the input evidence bundle;
- persisted evidence reprojects identically to direct XML execution;
- multi-transaction identity and indexes remain isolated;
- summaries match the request population; and
- all CLI modes emit strict machine-readable JSON.

Run:

```bash
./scripts/validate_phase1c.sh
```

## 10. Decision boundary

Phase 1C does not:

- load OFAC or provider data;
- choose a search backend or index;
- retrieve candidate profiles;
- calculate similarity or identifier-match scores;
- merge multiple field requests into an alert;
- classify false positives;
- apply policy thresholds or case routes; or
- invoke RAG or an LLM.

The next matcher phase can consume these requests without reparsing XML or interpreting screening-plan policy.
