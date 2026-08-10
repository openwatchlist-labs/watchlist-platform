# Phase 8F — Controlled activation promotion, canary rollout and immutable operational audit

Phase 8F adds a deployment control plane around the immutable catalog,
projection and scoring-policy activation tuple introduced in Phase 8E. It does
not alter candidate retrieval, deterministic scoring, similarity bands or any
regulatory/analyst disposition contract.

## Goals

- stage and validate a candidate activation without moving the live pointer;
- bind every promotion intent to exact current/candidate activation bytes;
- enforce a monotonic `prepare -> validated -> canary -> promoted` state machine;
- block stale or concurrent operators with revision compare-and-swap checks;
- measure deterministic current/candidate shadow differences before canary;
- route a bounded canary by correlation hash or explicit allowlist;
- require instance acknowledgements before promotion;
- publish the candidate activation atomically through the Phase 8E manager;
- support a validated rollback to the prior activation;
- preserve an append-only, SHA-256 hash-chained operational audit.

## Immutable objects

### Staged activation

`activation-promotion stage` invokes the Phase 8E tuple validator and writes an
immutable activation document under the activation state directory. It does
not update `active.json`.

### Promotion intent

A promotion intent binds:

- current and candidate activation IDs;
- SHA-256 of the exact canonical activation document bytes;
- operator and reason;
- canary basis points and correlation allowlist;
- required ready acknowledgement count;
- score/order/coverage/blocker thresholds.

Intent IDs are immutable. Reusing an ID with different bytes is rejected.

### State snapshots

Each transition writes an immutable revision snapshot and updates
`promotion.json` through fsync plus atomic rename. Every mutating command must
provide the expected revision. A stale revision is rejected before any pointer
or audit change.

### Audit chain

Every operational event contains its sequence, previous event SHA-256 and its
own SHA-256. Event files are immutable and `audit-head.json` identifies the
last accepted event. `verify-audit` recomputes the entire chain and rejects
missing, reordered or modified events.

## State machine

| Phase | Public routing | Allowed next operation |
|---|---|---|
| `prepared` | current | collect shadow observations and evaluate |
| `validated` | current, synchronously shadowed to candidate | start canary |
| `blocked` | current | re-evaluate with a new report or abandon externally |
| `canary` | deterministic current/candidate split | acknowledge and promote |
| `promoted` | candidate only | rollback |
| `rolled_back` | current only | terminal for this intent |

The candidate activation remains inactive until `promote`. Promotion requires
all configured readiness gates and uses the Phase 8E activation manager's
compare-and-swap publication method.

## Shadow comparison

Current and candidate responses are compared using only bounded screening
contract fields:

- candidate ID set changes;
- top candidate changes;
- maximum absolute score delta for shared candidates;
- candidates lost by the candidate tuple;
- additional blockers.

The comparison never loads or emits full catalog rows. Each observation and
summary is checksum-addressed. Threshold evaluation produces stable blocker
codes and cannot create a regulatory disposition.

## Canary routing

During `canary`, the candidate route is selected when either:

1. the correlation ID appears in the immutable allowlist; or
2. the first 64 bits of SHA-256(correlation ID), modulo 10,000, are below the
   configured canary basis points.

The same correlation ID therefore selects the same route on every instance.
The public Phase 8F front door verifies backend `/readyz` activation IDs before
forwarding and rejects mixed-version or stale backends.

## Fleet acknowledgements

An acknowledgement is immutable per intent and instance and records:

- instance ID;
- candidate activation ID;
- `ready` or `not_ready` status;
- observed tuple SHA-256;
- observation timestamp.

Promotion is rejected until the configured number of `ready`
acknowledgements is present.

## Recovery and rollback

State transitions use a pending transaction document containing the target
state and exact audit event. Startup recovery completes the immutable audit and
state pointer if an interruption occurred between those writes.

Rollback uses compare-and-swap to republish the original current activation and
moves the promotion state to `rolled_back`. A rollback is itself audit chained.

## Runtime topology

`screening-api-v8f` sits in front of two Phase 8E-compatible endpoints:

- `current_base_url`: server bound to the current activation;
- `candidate_base_url`: server bound to the staged candidate activation.

The public response remains the selected Phase 8E response plus bounded
`promotion` metadata. Phase 8F adds its own file-backed idempotency layer so a
successful replay remains byte-exact even if the rollout state later changes.

## Explicit exclusions

Phase 8F does not introduce:

- regulatory clearance or disposition;
- analyst or case decisions;
- automatic alert closure;
- full catalog rows or source records;
- non-deterministic LLM scoring;
- silent mixed-version fleet operation.
