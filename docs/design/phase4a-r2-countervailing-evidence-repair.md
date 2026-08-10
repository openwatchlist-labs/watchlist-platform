# Phase 4A-r2 — countervailing evidence repair

Phase 4A-r2 corrects an over-broad rule in the initial Phase 4A classifier. The original rule treated every exact typed route as independently escalation-worthy. That caused exact birth-date and account matches carried as `supporting_evidence` to receive the `escalation_candidate` route hint.

The repaired classifier separates primary identifiers from secondary attributes through a strict, checksum-protected policy:

```text
configs/false-positive-patterns/countervailing-evidence-r1.json
```

## Contracts and versioning

```text
countervailing-evidence-policy/v1alpha1
false-positive-countervailing-signal/v1alpha1
false-positive-classification/v1alpha2
false-positive-classification-batch/v1alpha2
false-positive-classifier/v0.1.1
```

Every classification and batch stamps the countervailing policy ID, version, and checksum. Classification IDs and batch IDs therefore change whenever the governing countervailing policy changes.

## Baseline evidence classes

```text
exact_lei      -> primary_identifier   -> 10000 -> escalation eligible
exact_bic      -> primary_identifier   -> 10000 -> escalation eligible
exact_account  -> secondary_attribute  ->  8000 -> not escalation eligible
exact_date     -> secondary_attribute  ->  7000 -> not escalation eligible
secondary identifier support
               -> secondary_support    ->  9000 -> not escalation eligible
```

An escalation-eligible signal is necessary but not sufficient. The observation must also have:

```text
trigger_policy = candidate_alert
```

Any observation marked `supporting_evidence` is prohibited from independently producing `escalation_candidate`, even when it uses an otherwise primary route such as exact LEI or exact BIC. The signal remains visible for audit, but the route is limited to `investigate` and receives:

```text
blocker: supporting_evidence_cannot_escalate
requires_evidence: qualifying_candidate_alert
```

A candidate-alert observation with only secondary evidence is also limited to `investigate` and receives:

```text
blocker: primary_identifier_required
requires_evidence: primary_identifier
```

## Corrected Phase 3B adaptation

The accepted Phase 3B matcher-result fixture contains:

- one exact LEI candidate-alert observation;
- one exact birth-date supporting observation; and
- one exact account supporting observation.

After this repair:

```text
exact LEI candidate alert  -> escalation_candidate
exact birth date support   -> investigate
exact account support      -> investigate
```

The Phase 3B classification summary changes from three escalation candidates to one:

```text
clear_or_auto_release_eligible: 1
escalation_candidate:            1
investigate:                    14
```

## Safety invariants

The validator and unit tests enforce:

1. no `supporting_evidence` observation can independently escalate;
2. only `primary_identifier` signals may be marked escalation eligible;
3. `escalation_candidate` requires an escalation-eligible primary signal;
4. exact account and exact date remain secondary evidence in the baseline policy;
5. policy JSON rejects unknown fields and checksum drift;
6. pattern outputs remain deterministic; and
7. the ten false-positive pattern families remain unchanged.

Phase 4A-r2 still produces evidence-level route hints only. Final case disposition remains outside the classifier and belongs to the later configurable policy engine.
