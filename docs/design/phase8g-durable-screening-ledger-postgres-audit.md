# Phase 8G — Durable screening ledger, reproducible snapshots, and PostgreSQL audit storage

Phase 8G closes the Phase 8 runtime durability boundary. The public `screening-api-v8g` front door delegates matching, scoring, activation fencing, and rollout routing to the accepted Phase 8F service, but it does not release a screening response until the exact request/response lineage has been durably recorded according to configuration.

## Implementation status

Phase 8G is implemented and validated. The accepted validation includes the local ledger, encryption, replay, export, retention, recovery, idempotency, and durable-before-delivery gates plus a disposable live PostgreSQL run.

The accepted PostgreSQL run:

- applied migration `db/migrations/008g_screening_ledger.sql` to a new database;
- synchronized one previously unreplicated screening event;
- imported one Phase 8F operational-audit event; and
- completed the PostgreSQL persistence and durable-audit assertions successfully.

On a fresh database, `NOTICE` messages stating that immutable or snapshot-guard triggers do not exist are expected. The migration defensively drops old trigger definitions before creating the accepted definitions.

## Delivery invariant

For every accepted real-time or batch request, Phase 8G performs the following sequence:

1. Forward the original request bytes, correlation ID, and idempotency key to Phase 8F.
2. Receive the exact Phase 8F HTTP status and response bytes.
3. Canonicalize decision-input snapshots only for encrypted snapshot storage; retain SHA-256 values of the original wire bytes separately.
4. Append an immutable local event to a per-ledger hash chain using fsync and atomic rename.
5. Persist the event, encrypted snapshot envelopes, replication receipt, and idempotency receipt to PostgreSQL in one transaction.
6. Return the unchanged Phase 8F response bytes with durable-ledger headers.

When `require_postgres` is true, PostgreSQL failure prevents delivery. The local event remains available for repair with `screening-ledger sync`.

## Event contents

The append-only event contains:

- ledger ID, monotonic sequence, previous-event hash, and event hash;
- exact request-byte and response-byte SHA-256 values;
- encrypted request/response snapshot SHA-256 values;
- hashed correlation and idempotency identifiers;
- route, HTTP status, retention class, and expiry;
- bounded activation and promotion lineage; and
- bounded candidate IDs, ordering, scores, bands, reason codes, and blockers.

It does not contain complete catalog rows, complete provider source records, regulatory disposition, analyst decisions, or clearance decisions.

## Snapshot protection and retention

Decision-input snapshots use AES-256-GCM. The key is supplied from a file or environment variable and is never written to the ledger. The snapshot filename is keyed by a deterministic content identity, while each encrypted envelope uses a fresh nonce.

Redacted exports replace configured direct identifiers and HMAC-hash configured quasi-identifiers. Internal exports require explicit `--mode internal` selection. Retention purge removes ciphertext and nonce material, writes an audit event, and retains the immutable event/snapshot identity. Event-specific legal holds are represented by files under `holds/<event-id>`.

Production deployments should provide the snapshot key through a secret manager or mounted secret, restrict filesystem permissions, rotate through a controlled re-encryption process, and use a dedicated least-privilege PostgreSQL role.

## PostgreSQL schema

Migration `db/migrations/008g_screening_ledger.sql` creates:

- `screening_ledger_event`
- `screening_ledger_snapshot`
- `screening_ledger_replication`
- `screening_idempotency_receipt`
- `screening_ledger_retention_tombstone`
- `screening_ledger_audit`
- `watchlist_operational_audit`

Events, audit records, replication receipts, idempotency receipts, and retention tombstones are protected by immutable triggers. Snapshot mutation is limited to the audited purge transition. PostgreSQL idempotency persistence rejects reuse that conflicts with the original request, response, or HTTP status.

The implementation invokes `psql` without a shell and transmits values through hex encoding before conversion inside PostgreSQL. This avoids interpolating untrusted screening values as SQL syntax.

PostgreSQL stores bounded screening, receipt, retention, and audit records. Complete catalog or provider source rows remain immutable external data-plane artifacts.

## Reproducible replay

`screening-ledger replay` decrypts the original request snapshot and submits it to a specified backend. Reports are classified as:

- `exact`: response bytes match the original response SHA-256;
- `explainable_drift`: bytes differ and a bounded candidate-order/score delta is emitted; or
- `unreproducible`: snapshots were purged, the backend is unavailable, or replay cannot complete.

Replay is an audit function. It does not change the original event or create a regulatory decision.

## Operational audit convergence

Phase 8G retains its own local hash-chained operational audit and can persist it to PostgreSQL. It can also verify and import the accepted Phase 8F activation-promotion audit stream into `watchlist_operational_audit`, preserving source, stream, sequence, event hash, previous hash, action, timestamp, and exact payload.

## Commands

Run the complete Phase 8G fixture validation:

```bash
./scripts/validate_phase8g.sh
```

Inspect the checked-in fixture ledger:

```bash
go run ./cmd/screening-ledger status \
  --ledger-dir test/fixtures/screening-ledger/state \
  --key-file test/fixtures/screening-ledger/snapshot-key.hex \
  --ledger-id screening-api-v8g-example
```

Check the public Phase 8G configuration:

```bash
go run ./cmd/screening-api-v8g check \
  --config configs/screening-ledger/phase8g-example.json
```

Run the live persistence gate against a disposable local database using socket authentication:

```bash
createdb temporary_phase8g_db

PHASE8G_POSTGRES_DSN="postgresql:///temporary_phase8g_db?user=$(whoami)" \
  ./scripts/validate_phase8g_postgres.sh

dropdb temporary_phase8g_db
```

The live gate creates and purges fixture rows and must not target a production database.

## Production boundary

The validated implementation proves the persistence and audit contracts, but production deployment still requires institution-specific secrets management, PostgreSQL high availability and backup, retention policy approval, access control, observability, incident response, schema migration governance, load and failure testing, and human compliance oversight.
