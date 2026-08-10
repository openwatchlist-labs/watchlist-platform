# List update architecture

OpenWatchlist uses immutable catalog generations with read-copy-update semantics.

## Lifecycle

```text
discovered -> acquired -> archived -> parsed -> projected -> compiled
-> staged -> validated -> active -> draining -> retired -> purged
```

Failures go to `quarantined`; raw files never compile inside the live screening path.

## Active/shadow behavior

Generation A remains immutable and active while generation B is built and validated separately. Each screening request acquires a generation lease at its start. Activation atomically swaps the active pointer to B. Existing A leases complete on A; new requests acquire B. A is reclaimed only after its lease count reaches zero. Every screening execution must stamp the lease metadata: generation ID, catalog ID/version/checksum, source-manifest ID, and activation epoch. Phase 2A exposes that immutable lease metadata; result-envelope integration follows with the runtime service.

This is an RCU-style separation between removing the active reference and reclaiming the old generation.

## Important corrections to the proposed guardrails

- Shadow compilation is logically isolated but does not consume zero resources on the same host. Compile on an update-manager node/process with CPU, memory, and I/O limits; screening workers should load only validated artifacts.
- An in-process atomic swap does not require pausing MQ, Kafka, or NATS. Queue buffering is still useful for node failure, backpressure, and distributed rollout.
- OFAC publishes delta files, but also recommends comprehensive refreshes for database updates. Full snapshots are therefore the Phase 2A default.
- A 20% delta threshold is a useful starting policy, not a universal constant. It must be configurable and measured against catalog size, compile cost, and memory behavior.

## Delta design

A future delta is applied off-path to an immutable base, producing a complete generation B. The active generation is never patched. Sequence gaps, base-version mismatch, duplicate operations, checksum mismatch, or excessive change volume force a full snapshot rebuild. Periodic full rebuilds remain mandatory.

## Multi-process rollout

There is no process-global atomic pointer. The control plane distributes B, waits for required workers to report ready, advances an activation epoch, lets each worker swap locally, and routes/retries work only on workers at the required epoch. A drains independently on each worker.

## Rollback

Retain at least the previous validated compiled artifact through canary. Rollback rehydrates that immutable artifact as a new runtime generation and performs another atomic activation. The catalog version/checksum and source-manifest identity remain unchanged, while the generation ID and activation epoch advance for auditability.

Phase 2A includes the immutable source/catalog contracts and an in-process atomic lease/swap proof. Scheduling, delta application, compiled memory-mapped indices, distributed epochs, and canary automation follow later.

## Phase 2B implementation

Phase 2B implements the compiled-artifact and audit layer described above:

- deterministic architecture-neutral `.owpcat` packages;
- precompiled exact-match index entries rather than raw-list parsing in workers;
- immutable package and readiness storage;
- readiness reports before activation;
- atomic active-pointer persistence;
- activation and rollback records;
- package-backed in-process generation activation and lease drain; and
- generation stamps in candidate-result batches and individual results.

The package checksum and catalog checksum serve different purposes. The catalog checksum identifies normalized watchlist content. The package checksum identifies the exact compiled artifact loaded by a worker. Both are retained in each generation stamp.

## Phase 2C distributed control plane

Phase 2C adds a fleet-level protocol above the Phase 2B worker-local runtime. Required workers stage the same immutable package and return content-addressed readiness acknowledgements. An explicit canary subset activates first under a reserved fleet epoch; broad rollout proceeds only when every canary probe passes. The durable fleet pointer advances only after all required workers acknowledge the same package and epoch.

This is a two-level commit, not a claim of a globally atomic in-memory pointer operation. Each worker performs a local switch. The control plane determines when an epoch is eligible for routing and preserves the exact package, source manifest, worker acknowledgements, and fleet epoch in the audit history. See [Phase 2C — Update manager and distributed activation](phase2c-update-manager-distributed-activation.md).

## Phase 2D delta promotion implementation

Phase 2D implements the previously described off-path delta design. A content-addressed delta names an exact immutable base and target, carries a contiguous sequence, and uses record SHA-256 preconditions for replace and remove operations. Applying the delta creates a complete candidate catalog; it does not mutate the active catalog.

A semantic diff and configurable policy decide whether to promote the reconstructed catalog, force a full comprehensive rebuild, or reject the update. The reference policy forces a full rebuild when the change ratio is at or above 20%, when deletion or operation limits are exceeded, or when periodic full verification is due. Base mismatch, sequence gaps, operation drift, and checksum failures reject the delta. Promotion and delta records are immutable and feed the existing Phase 2C audit and canary protocol.
