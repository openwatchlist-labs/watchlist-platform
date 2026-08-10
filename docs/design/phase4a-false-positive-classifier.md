# Phase 4A — deterministic false-positive classifier

Phase 4A introduces a deterministic classification boundary between matcher evidence and the configurable policy engine planned for Phase 5.

The classifier does **not** clear, block, reject, or escalate a transaction. It emits versioned pattern evidence, route hints, escalation blockers, missing-evidence requirements, and countervailing signals that a later policy profile can consume.

## Contracts

```text
transaction-screening-observation/v1alpha1
transaction-screening-observation-batch/v1alpha1
false-positive-pattern-library/v1alpha1
false-positive-pattern-evidence/v1alpha1
false-positive-classification/v1alpha2
false-positive-classification-batch/v1alpha2
countervailing-evidence-policy/v1alpha1
false-positive-countervailing-signal/v1alpha1
```

Classifier version:

```text
false-positive-classifier/v0.1.1
```

All observation, classification, and batch identities are content-addressed. Collections and output order are canonicalized before identity calculation.

## Input boundary

The canonical observation contract supports both OpenWatchlist matcher results and alerts produced by external screening systems. It retains:

- source system, case, message, and field identity;
- ISO semantic role, value type, trigger policy, and native path;
- original and normalized input/watchlist values;
- candidate entity type, match route, score, and exactness;
- matcher reason and diagnostic codes;
- allowed target entity types;
- secondary identifier evidence;
- required/present qualifiers;
- technical and legal-context markers; and
- watchlist source assertions.

`ObservationsFromMatcherResults` converts accepted `candidate-result-batch/v1alpha1` output into this contract without reparsing the payment message.

## Pattern library

The baseline pattern library is strict JSON and checksum protected:

```text
configs/false-positive-patterns/baseline-r1.json
```

The library versions the default strength, route hint, blockers, and reason codes for ten deterministic pattern families:

1. substring containment;
2. wrong field/data type;
3. entity-type mismatch;
4. missing qualifier;
5. routing/BIC collision;
6. acronym collision;
7. phonetic/transliteration-only support;
8. narrative denial context;
9. technical/system artifacts; and
10. legal-control context.

Phase 4A owns detection semantics. Phase 5 will externalize final weights, thresholds, overlays, route selection, and disposition policy.

## Route hints

The classifier emits one of:

```text
clear_or_auto_release_eligible
investigate
manual_review
escalation_candidate
```

These are evidence-level hints, not final case decisions.

Countervailing evidence is governed by `configs/false-positive-patterns/countervailing-evidence-r1.json`. Exact LEI and BIC are primary identifiers and may support `escalation_candidate` only when the observation is a `candidate_alert`. Exact account and date routes are secondary attributes and cannot independently escalate. Every `supporting_evidence` observation is prohibited from independently producing `escalation_candidate`. If strong false-positive evidence and primary identifier support coexist, the route hint remains conservatively limited to `investigate`.

## Pattern examples

```text
SCUBA -> CUBA
  substring_containment
  blocker: substring_only_match

account identifier -> vessel name
  wrong_field_data_type
  blocker: wrong_field_context

company-name field -> vessel candidate
  entity_type_mismatch
  blocker: entity_type_conflict

NATIONAL DEVELOPMENT -> NATIONAL DEVELOPMENT BANK
  missing_qualifier
  blocker: missing_critical_watchlist_terms

BIC ABCDKPX1XXX -> KP token
  routing_bic_collision
  blocker: routing_code_collision

:20: FARC-2026-001 -> FARC
  acronym_collision
  blocker: acronym_field_collision

BECHIR -> BASHIR with phonetic evidence only
  phonetic_transliteration_only
  blocker: secondary_identifier_missing

NO BUSINESS RELATIONSHIP WITH JORDAN EXAMPLE
  narrative_denial_context
  blocker: denial_context

MIGRATION-0000000000
  technical_system_artifact
  blocker: technical_artifact

BANKRUPTCY TRUSTEE FOR JORDAN EXAMPLE
  legal_control_context
  blocker: legal_control_evidence_required
```

## CLI

Classify canonical observations:

```bash
go run ./cmd/false-positive-classify \
  --input observations \
  --pattern-library configs/false-positive-patterns/baseline-r1.json \
  --countervailing-policy configs/false-positive-patterns/countervailing-evidence-r1.json \
  test/fixtures/false-positive/pattern-observations.json
```

Classify accepted matcher results:

```bash
go run ./cmd/false-positive-classify \
  --input matcher-results \
  --source-reference golden:phase3b-contextual-results \
  --pattern-library configs/false-positive-patterns/baseline-r1.json \
  --countervailing-policy configs/false-positive-patterns/countervailing-evidence-r1.json \
  test/golden/matcher-context/pacs008-contextual.results.json
```

## Regression boundary

The fixture pack contains 16 observations. It verifies all ten pattern families plus:

- exact LEI primary-identifier evidence;
- exact BIC primary-identifier evidence;
- exact birth-date secondary evidence that cannot escalate;
- exact account secondary evidence that cannot escalate;
- true whole-token geography context; and
- multi-feature fuzzy name evidence that is not misclassified as phonetic-only.

Phase 3B matcher output is also adapted and classified to prove that denial diagnostics and transliteration-only evidence cross the boundary without changing accepted matcher goldens.

## Non-goals

Phase 4A does not add:

- a final `clear`, `investigate`, or `escalate` disposition;
- tenant/business-line policy overlays;
- configurable policy scoring weights;
- prior-case evidence;
- RAG retrieval;
- LLM reasoning; or
- automatic release authority.

See [Phase 4A-r2 countervailing evidence repair](phase4a-r2-countervailing-evidence-repair.md) for the repaired primary/secondary evidence policy and migration details.
