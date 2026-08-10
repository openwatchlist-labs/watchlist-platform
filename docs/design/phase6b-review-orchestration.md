# Phase 6B — Deterministic review orchestration and immutable case bundle

## Purpose

Phase 6B proves that the Phase 3–6 contracts compose into one deterministic review workflow without allowing orchestration, retrieval, or a model to reinterpret the compliance decision.

The orchestrator consumes an accepted `candidate-result-batch/v1alpha1`. It projects canonical observations, classifies false-positive patterns, evaluates the checksum-protected policy, retrieves citation packages, optionally generates governed draft notes, and emits one `review-run-bundle/v1alpha1`.

## Contracts

- `review-run-bundle/v1alpha1`
- `review-case-bundle/v1alpha1`
- `review-audit-event/v1alpha1`
- orchestrator `review-orchestrator/v0.1.0`

The run bundle retains the complete input matcher batch and every derived observation, classification, and decision batch. Per-case bundles reference those immutable stage identities and add retrieval packages, optional analyst-note invocations, stable correlation IDs, assistance status, and warnings.

## Failure boundary

Classification and policy errors fail the run atomically because no valid deterministic decision exists. Retrieval and model errors are fail-soft because they affect only analyst assistance. A failed assistance stage records a warning and auditable status while preserving the accepted decision, score, blockers, reason codes, and route.

## Audit chain

Every run emits a deterministic hash chain covering:

1. run start and input identity;
2. observation projection;
3. classification completion;
4. policy completion;
5. per-case retrieval result;
6. per-case note result;
7. per-case completion;
8. run summary.

Each event contains a sequence, event type, case ID where applicable, payload digest, previous hash, event ID, and event hash. Validation reconstructs the expected events from the bundle and rejects payload, order, insertion, removal, or head-hash drift.

## Analyst-note controls

- `auto_release` routes skip note generation;
- disabled providers preserve citation packages but emit no note;
- provider errors produce `generation_failed` and do not fail the run;
- generated notes must pass the Phase 6A citation and route-lock validators;
- fixture and Ollama providers share the same bundle contract.

## Reference regression

The reference run selects the Phase 3A suppressed entity-type mismatch case:

- input field: `creditor.name`;
- candidate entity type: `vessel`;
- deterministic disposition: `investigate`;
- review route: `standard_review`;
- retrieval: completed;
- governed fixture note: generated;
- audit events: 8.

The same inputs produce byte-identical JSON, run ID, case ID, citation package, invocation, and audit head.
