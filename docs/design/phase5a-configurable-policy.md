# Phase 5A — Configurable scoring and threshold policy

Phase 5A implements the deterministic decision layer between false-positive classification and future RAG/LLM analyst assistance. It converts a validated `false-positive-classification-batch/v1alpha2` into content-addressed `clear`, `investigate`, or `escalate` decisions.

## Decision ownership

The policy engine is the only component in the current pipeline allowed to issue a final platform disposition. Matchers produce candidates and scores. The false-positive classifier produces pattern evidence, route hints, blockers, and countervailing signals. The policy engine combines those inputs under a versioned configuration.

RAG and LLM components may later retrieve guidance and draft an analyst note, but they cannot alter the deterministic policy result.

## Contracts

```text
transaction-screening-policy/v1alpha1
tenant-policy-overlay/v1alpha1
policy-score-component/v1alpha1
policy-rule-trace/v1alpha1
transaction-screening-decision/v1alpha1
transaction-screening-decision-batch/v1alpha1
```

Engine version:

```text
transaction-policy-engine/v0.1.0
```

## Baseline score matrix

All values are integer basis points.

```text
screening score contribution       matcher score × 4500 / 10000
countervailing contribution        countervailing support × 4000 / 10000
release-support reduction          release support × 5000 / 10000
pattern adjustment                 configured signed basis-point delta
final policy score                 clamp(total, 0, 10000)
```

Baseline thresholds:

```text
clear maximum                               2500
escalate minimum                            8500
minimum release support for clear           7000
minimum countervailing support to escalate  9000
```

The numeric score is necessary but not sufficient. Route hints, trigger policy, blockers, evidence class, and controls are separate deterministic gates.

## Escalation gate

An observation may escalate only when all of the following are true:

```text
policy score >= escalation threshold
base/overlay control allows escalation
trigger_policy == candidate_alert
countervailing support meets the configured minimum
no classifier escalation blockers are present
route and pattern rules do not cap the case below escalate
```

Under the Phase 4A-r2 countervailing policy, exact LEI and BIC candidate-alert matches are primary identifiers and can satisfy this gate. Exact date and account matches are secondary attributes. Supporting evidence can never independently escalate.

## Clear gate

Automatic clear requires:

```text
policy score <= clear threshold
base/overlay control allows automatic clear
classification route hint is clear_or_auto_release_eligible
release support meets the configured minimum
```

A low score alone is not enough. This prevents ordinary weak or incomplete matches from being auto-released merely because they lack positive risk evidence.

## Investigate route

Any case that does not pass the escalation or clear gate is investigative. A `manual_review` classifier hint is preserved as the `manual_review` review route. Other investigative decisions use `standard_review`.

## Pattern and blocker policy

The YAML policy maps every Phase 4A pattern to:

```text
score adjustment
maximum disposition
reason code
```

Named blockers can independently cap the maximum disposition and add policy reason codes. This allows an institution to tune semantics without recompiling the engine.

## Tenant overlays

The optional overlay can override:

```text
weights
thresholds
allow_auto_clear
allow_escalation
named pattern-rule adjustments, caps, and reason codes
```

The synthetic `conservative-review-r1` overlay disables both automatic clear and escalation. The same 16 canonical classifications therefore all route to investigation, proving that behavior changes are configuration-driven.

An overlay must name the exact base policy ID, version, and checksum. It cannot silently attach to a different policy generation.

## Restricted YAML profile

The repository intentionally supports a small YAML mapping subset:

```text
supported: nested mappings, strings, integers, booleans, null
rejected: sequences, anchors, aliases, tags, flow collections, multiline scalars, duplicate keys, tabs, odd indentation
```

This keeps policy parsing deterministic and avoids adding a third-party module to the current standard-library-only Go baseline.

## Decision trace

Every output contains:

```text
full Phase 4A classification input
base policy reference and checksum
optional tenant overlay reference and checksum
ordered score components
score before clamp and final score
threshold snapshot
final disposition and review route
blockers and required evidence
canonical reason codes
ordered rule trace
content-addressed decision ID
```

Re-evaluating identical evidence under identical policy artifacts produces byte-identical output.

## Regression expectations

Baseline policy over the 16 canonical Phase 4A classifications:

```text
clear:        6
investigate:  8
escalate:     2
```

Baseline policy over the accepted Phase 3B matcher adaptation:

```text
clear:        1
investigate: 14
escalate:     1
```

Synthetic conservative overlay over the 16 canonical classifications:

```text
clear:        0
investigate: 16
escalate:     0
```

## Non-goals

Phase 5A does not add:

```text
RAG corpus ingestion
policy-document retrieval
historical-case retrieval
LLM analyst notes
human workflow or approvals
production tenant storage
REST or batch service deployment
```

Those are later phases. This phase establishes the immutable decision contract they must consume.
