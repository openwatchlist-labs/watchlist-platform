# Phase 8 runtime operations

This document describes the completed Phase 8 runtime topology, validation order, persistence boundary, and operating constraints.

## Runtime topology

Phase 8 uses explicit incremental boundaries rather than one opaque service:

```text
external request
  -> screening-api-v8g          durable delivery and screening ledger
      -> screening-api-v8f      rollout routing and activation fencing
          -> current/candidate Phase 8E scored backend
              -> Phase 8D scoring-integrated API
                  -> Phase 8B retrieval backend
                      -> persistent Rust catalog-mmap workers
```

Supporting control and audit commands are:

- `projection-package` — compile or verify bounded scoring projections;
- `scoring-activation` — inspect and atomically manage catalog/projection/policy tuples;
- `activation-promotion` — prepare, validate, canary, promote, roll back, and verify promotion audit;
- `screening-ledger` — inspect, synchronize, replay, export, retain, and audit screening events; and
- `candidate-score` — independently validate scoring policy and deterministic scoring behavior.

The phase-specific front doors are retained to make regression, replay, and fault isolation explicit. New deployment work should target `screening-api-v8g` as the public boundary unless a lower-level component is being tested deliberately.

## Startup and readiness dependencies

A Phase 8G instance is ready only when its configured dependency chain is valid:

1. The Phase 8B retrieval backend is healthy and bound to the expected active catalog component/version.
2. The Phase 8D scorer can load and checksum-verify the configured policy.
3. The Phase 8E activation tuple binds a compatible catalog package, projection package, policy, normalization profile, counts, and coverage.
4. The Phase 8F front door can verify promotion state, backend activation identity, and required rollout fencing.
5. The Phase 8G ledger can load its encryption key, local state, PostgreSQL configuration, and required durability mode.

Missing, inactive, mixed-version, stale, tampered, or unacknowledged state must produce an explicit readiness failure or response blocker rather than silent fallback.

## Validation order

Run the final validator for normal development verification:

```bash
./scripts/validate_phase8g.sh
```

The final validator includes the accepted Phase 8 regression chain. Lower-level validators remain useful when isolating a failure:

```bash
./scripts/validate_phase8a.sh
./scripts/validate_phase8b.sh
./scripts/validate_phase8c.sh
./scripts/validate_phase8d.sh
./scripts/validate_phase8e.sh
./scripts/validate_phase8f.sh
./scripts/validate_phase8g.sh
```

Use a disposable database for the live PostgreSQL gate:

```bash
createdb temporary_phase8g_db

PHASE8G_POSTGRES_DSN="postgresql:///temporary_phase8g_db?user=$(whoami)" \
  ./scripts/validate_phase8g_postgres.sh

dropdb temporary_phase8g_db
```

Do not point the live gate at production because it creates and purges fixture rows.

## Persistence boundary

Immutable data-plane catalog rows remain in checksum-addressed catalog and projection packages. PostgreSQL stores bounded operational and screening lineage only:

- catalog registry, mapping, activation, promotion, and rollback metadata;
- screening event and encrypted snapshot envelopes;
- replication and idempotency receipts;
- retention tombstones and screening-ledger audit; and
- imported activation-promotion operational audit.

The public API does not return full catalog rows. The ledger does not persist complete provider records.

## Durable-before-delivery

With `require_postgres` enabled, `screening-api-v8g` returns the exact Phase 8F response bytes only after the local event and PostgreSQL transaction succeed. A PostgreSQL failure prevents response delivery while leaving the local event available for repair synchronization.

Operators should monitor:

- local ledger chain verification;
- unreplicated event count;
- PostgreSQL transaction failures and latency;
- idempotency conflicts;
- snapshot encryption and key-loading failures;
- activation pointer or backend identity changes;
- promotion phase, revision, and fleet acknowledgement count; and
- retention, legal-hold, export, replay, and audit-import operations.

## Secrets and access

Production deployments should:

- supply the AES-256-GCM snapshot key from a secret manager or mounted secret;
- use a dedicated least-privilege PostgreSQL role;
- separate migration privileges from runtime write privileges;
- restrict ledger and key-file permissions;
- encrypt transport and storage appropriate to institutional policy;
- back up PostgreSQL and retained local ledger state; and
- govern key rotation through tested re-encryption and recovery procedures.

## Failure and recovery

Phase 8 includes explicit recovery paths:

- Rust worker failures are surfaced through retrieval readiness and worker-pool error handling.
- Incomplete activation transactions are recovered or rejected before active use.
- Stale promotion revisions fail compare-and-swap.
- Mixed or changed backend activation identities are fenced.
- Interrupted local ledger transactions recover from durable state.
- Unreplicated local events can be repaired with `screening-ledger sync`.
- Promotion can roll back to the validated prior activation tuple.
- Purged snapshots remain represented by immutable event and retention-tombstone lineage.

Recovery must never rewrite historical event or audit identities.

## Decision ownership

Phase 8 produces candidate evidence, deterministic similarity scores, non-dispositive bands, activation state, rollout evidence, and durable audit records. It does not produce regulatory clearance, final alert disposition, or analyst decisions. Those remain governed by the deterministic policy and human-review boundaries documented elsewhere in the repository.
