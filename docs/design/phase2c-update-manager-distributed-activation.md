# Phase 2C — Update manager and distributed activation

Phase 2C adds the control-plane protocol that prepares immutable OFAC runtime packages and coordinates their rollout across multiple screening workers. It builds on the Phase 2B `.owpcat` artifact, readiness report, activation record, rollback record, and generation-stamp contracts.

## Scope

Phase 2C covers:

- staged local or official-source acquisition;
- schedule enforcement before acquisition and compilation;
- immutable source archives and compiled packages;
- worker-local package staging and readiness acknowledgements;
- explicit canary worker selection;
- one reserved fleet activation epoch shared by canary and broad rollout;
- durable worker activation acknowledgements;
- fleet-pointer advancement only after every required worker succeeds;
- explicit rollback to a retained package under a new fleet epoch;
- append-only, hash-chained update audit events;
- deterministic fixture replay and failure regression tests.

It does not yet provide a network transport, leader election, distributed consensus service, cron daemon, production health telemetry, or automatic OFAC polling. The interfaces and records are transport-neutral so those capabilities can be added without changing the update contracts.

## Control-plane sequence

```text
scheduled update
    |
    v
schedule gate ---- too early ---> no acquisition and no state change
    |
    v
acquire source -> strict parse -> immutable source archive
    |
    v
project direct-list catalog -> compile deterministic .owpcat
    |
    v
persist immutable package -> stage package on every required worker
    |
    v
collect worker readiness acknowledgements
    |
    +---- any required worker not ready ---> abort; fleet pointer unchanged
    |
    v
reserve next fleet activation epoch
    |
    v
activate explicit canary set -> run worker-local smoke probes
    |
    +---- canary failure ---> activation failed; fleet pointer unchanged
    |
    v
activate remaining required workers with same fleet epoch
    |
    +---- worker failure ---> activation failed; fleet pointer unchanged
    |
    v
persist fleet activation record -> atomically replace fleet active pointer
```

The protocol does not claim that memory pointers across multiple machines switch in one CPU instruction. The atomic boundary is the durable control-plane fleet pointer. Every worker acknowledgement includes the reserved fleet epoch and its worker-local generation stamp. Screening traffic should only be routed to an epoch after the fleet pointer identifies it as active.

## Scheduling

`UpdateSpec.scheduled_for` is a hard not-before boundary. `Manager.Prepare` returns `ErrNotDue` before source acquisition when the supplied control-plane time is earlier than the schedule. This permits an external scheduler, cron service, workflow engine, or operator to call the manager safely without embedding scheduler infrastructure in the screening process.

The update specification also pins:

- source path or official source URL;
- request and scheduled timestamps;
- required worker IDs;
- explicit canary worker IDs;
- deterministic update ID.

## Worker readiness

Each required worker independently:

1. receives the exact package bytes and package identity;
2. parses and verifies `.owpcat` framing;
3. verifies artifact and payload checksums;
4. validates provider, catalog, and source lineage;
5. validates the compiled exact index;
6. emits `worker-readiness-ack/v1alpha1`.

The acknowledgement is content-addressed and includes the worker descriptor, package ID/checksum, check timestamp, check list, and final ready state. A missing or negative acknowledgement from any required worker blocks activation.

## Canary and broad activation

Canary workers are an explicit subset of required workers. They activate first under the reserved fleet epoch and return `worker-activation-ack/v1alpha1` with:

- worker and zone;
- update ID;
- fleet epoch;
- rollout phase;
- activation status;
- local probe result;
- complete generation stamp;
- activation timestamp.

The broad phase begins only after every canary acknowledgement passes. Remaining workers use the same fleet epoch. The deterministic fixture uses three workers across three zones, with one explicit canary per update.

## Fleet active pointer

`active.json` uses `fleet-active-pointer/v1alpha1` and records:

- fleet activation or rollback record ID;
- update ID;
- fleet epoch;
- package ID and checksum;
- catalog ID, version, and checksum;
- source manifest ID;
- activation time.

The pointer advances only after all required acknowledgements are persisted and the fleet activation record validates. Failed readiness, canary, or broad activation does not advance it.

## Rollback

Rollback is not a catalog mutation. The manager stages a retained immutable package, reactivates it on every required worker, and assigns a new fleet epoch. The rollback record preserves:

- failed or superseded activation ID;
- target package ID;
- reason;
- new fleet epoch;
- worker rollback acknowledgements;
- request and completion timestamps.

The Phase 2C replay validates:

```text
package A active at fleet epoch 1
package B active at fleet epoch 2
package A reactivated at fleet epoch 3
```

Content identity for package A remains unchanged; activation identity and epoch change.

## Audit history

Every state transition emits `update-audit-event/v1alpha1`. Events are written with exclusive-create semantics and chained using:

```text
sequence
previous_hash
payload_sha256
event_hash
event_id
```

The history validator recomputes the complete chain and rejects sequence changes, payload digest changes, event removal, event insertion, or head-hash drift. Audit events cover schedule release, source staging, package compilation, worker readiness, canary activation, broad activation, fleet activation, worker rollback, and fleet rollback.

## Persistent layout

```text
<state-dir>/
  packages/<package-id>.owpcat
  updates/<update-id>.json
  worker-readiness/<update-id>/<worker-id>-<ack-id>.json
  fleet-activations/<activation-id>.json
  fleet-rollbacks/<rollback-id>.json
  audit/<sequence>-<event-id>.json
  active.json

<archive-dir>/
  ofac-sdn/<source-sha256>/...
```

Immutable records use exclusive creation. The fleet active pointer is the only replaceable control-plane record.

## CLI fixture replay

```bash
rm -rf /tmp/openwatchlist-phase2c-state /tmp/openwatchlist-phase2c-archive

go run ./cmd/update-manager \
  --command simulate \
  --state-dir /tmp/openwatchlist-phase2c-state \
  --archive-dir /tmp/openwatchlist-phase2c-archive \
  --source-v1 test/fixtures/ofac/sdn/sdn-fixture.xml \
  --source-v2 test/fixtures/ofac/sdn/sdn-fixture-v2.xml
```

The replay performs two scheduled source-to-package updates across three workers and then rolls back to the first package. Its complete output is locked by `test/golden/update-manager/distributed-update-replay.json`.

## Production integration path

Later phases can replace `MemoryWorker` with an authenticated network client while preserving `Worker`:

```go
type Worker interface {
    Descriptor() WorkerDescriptor
    Stage(context.Context, string, []byte, ofacruntime.PackageInfo, time.Time, time.Time) (WorkerReadinessAck, error)
    Activate(context.Context, ActivationCommand) (WorkerActivationAck, error)
}
```

The recommended production control plane should additionally provide:

- single-writer leadership or compare-and-swap around fleet epochs;
- authenticated and encrypted worker communication;
- worker identity certificates;
- bounded retries with idempotency keys;
- activation deadlines and explicit unavailable-worker policy;
- real screening smoke probes and latency/error canary metrics;
- durable database or consensus-backed state instead of a local filesystem;
- alerting for stale schedules, missing workers, rollout failure, and rollback.
