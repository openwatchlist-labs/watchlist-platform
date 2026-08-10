# Phase 1B: Screening-Plan Execution and Evidence Bundles

**Status:** Implementation baseline
**Input contract:** `canonical-message/v1alpha1`
**Evidence bundle:** `screening-evidence-bundle/v1alpha1`
**Element evidence:** `screening-element-evidence/v1alpha1`
**Executor:** `screening-plan-executor/v0.1.0`

## 1. Purpose

Phase 1B establishes the runtime boundary between canonical ISO 20022 parsing and future list retrieval or matching. It executes the compiled screening plan for every canonical element, independently verifies the parser-attached directive, and emits a deterministic message-level evidence bundle.

The bundle is screening **input evidence**, not a sanctions hit, review route, or policy decision. Candidate retrieval, comparison scores, false-positive classification, and alert disposition remain future layers.

## 2. Independent plan verification

The Phase 1A parser attaches semantic and screening metadata while extracting each XML value. Phase 1B does not trust that attachment blindly. The executor:

1. validates the canonical message;
2. verifies message-level plan ID, version, and checksum;
3. resolves every native path against the compiled plan again;
4. compares the resolved semantic role, party role, value type, plan entry, trigger policy, routes, target entity types, normalization profile, threshold profile, and supporting fields with the canonical attachment; and
5. fails before evidence emission when any value differs.

This gate detects accidental plan drift, stale canonical data, altered directives, ambiguous routes, and unresolved paths.

## 3. Effective execution actions

The executor converts plan intent and value presence into an explicit action:

```text
candidate_lookup   present candidate-alert value may invoke its configured routes
supporting_lookup  present supporting value may invoke its configured routes
retain_only        retain the value and lineage without candidate retrieval
disabled           preserve the explicit plan exclusion
skip_empty         preserve an empty matching field but do not invoke a route
skip_invalid       preserve an invalid matching field but do not invoke a route
```

`eligible_for_matching` is true only when a `candidate_alert` or `supporting_evidence` element has `presence=present`. Empty and invalid values remain visible in evidence but cannot reach a matcher.

## 4. Element evidence contract

Each evidence record includes:

- stable evidence and canonical element IDs;
- message and transaction identity;
- namespace, native path, and occurrence;
- original and normalized values;
- XML attributes retained by the parser;
- resolved semantic and party roles;
- typed value classification;
- trigger policy and effective execution action;
- match routes;
- target entity types;
- normalization and threshold profiles;
- configured supporting-field roles;
- parser/source lineage; and
- element warnings.

The evidence ID is derived from the canonical element ID, plan checksum, and plan entry. The same canonical input and compiled plan therefore produce the same evidence identity.

## 5. Message-level evidence bundle

The bundle includes:

- stable bundle ID;
- message identity and source reference;
- parser and executor versions;
- plan ID, version, and checksum;
- ordered element evidence;
- parser warnings; and
- deterministic summary counts.

Summary counts cover transactions, trigger-policy classes, match eligibility, skipped empty or invalid values, element warnings, routes, and target entity types. Count lists are sorted to keep JSON snapshots stable.

## 6. Machine-readable CLI output

The inspection command supports three JSON shapes:

```bash
# Backward-compatible canonical output
go run ./cmd/iso20022-inspect \
  --output canonical \
  --source-ref fixture:pacs008-basic.xml \
  test/fixtures/iso20022/pacs008/pacs008-basic.xml

# Message-level screening evidence
go run ./cmd/iso20022-inspect \
  --output evidence \
  --source-ref fixture:pacs008-basic.xml \
  test/fixtures/iso20022/pacs008/pacs008-basic.xml

# Canonical message and evidence in one JSON envelope
go run ./cmd/iso20022-inspect \
  --output inspection \
  --compact \
  --source-ref fixture:pacs008-basic.xml \
  test/fixtures/iso20022/pacs008/pacs008-basic.xml
```

`canonical` remains the default so Phase 1A callers do not change behavior. `--compact` affects whitespace only.

## 7. Golden JSON contracts

Reviewable snapshots are stored under:

```text
test/golden/iso20022/pacs008/
  pacs008-basic.canonical.json
  pacs008-basic.evidence.json
  pacs008-multi-transaction.evidence.json
```

Tests regenerate output in memory and require byte-for-byte equality with these files. A snapshot update is therefore an explicit contract change and should be reviewed alongside parser, plan, schema, or normalization changes.

## 8. Regression gates

Phase 1B tests assert:

- stable canonical and evidence output;
- every element resolves exactly once;
- parser-attached directives match fresh plan resolution;
- message plan ID, version, and checksum match the executor;
- semantic-role or directive tampering is rejected;
- unresolved native paths are rejected;
- candidate and supporting values expose route and target metadata;
- retain-only fields never become match eligible;
- empty and invalid matching values are preserved and skipped;
- transaction counts and summary totals are deterministic;
- golden JSON contracts remain unchanged; and
- all three CLI output modes emit valid JSON.

Run the complete gate:

```bash
./scripts/validate_phase1b.sh
```

## 9. Decision boundary

Phase 1B does not:

- download or query a watchlist;
- create a list candidate;
- compute name or identifier similarity;
- classify an alert as true or false positive;
- apply scoring thresholds or blockers;
- release, clear, investigate, or escalate a case; or
- invoke RAG or an LLM.

The bundle is the stable handoff to those later capabilities.

## 10. Next slice

Phase 1C consumes this bundle to produce deterministic matcher requests and replay envelopes. See [`phase1c-matcher-requests-replay.md`](phase1c-matcher-requests-replay.md). Parser-registry expansion remains a later Phase 1 slice after the matcher handoff is locked.
