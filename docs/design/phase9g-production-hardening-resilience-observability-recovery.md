# Phase 9G r1 — Production hardening, resilience, observability, and recovery

Phase 9G wraps the accepted Phase 9F review API with a production operations boundary. It does not replace screening, policy, case, assistance, adapter, or authorization ownership.

## Runtime entrypoints

- `platform-api check|serve` loads the checksum-bound Phase 9G runtime configuration, tenant quotas, and the existing Phase 9F API.
- `platform-ops` provides readiness, quota inspection, durable outbox, backup/restore, and PostgreSQL synchronization commands.

The hardened API exposes `/livez`, `/healthz`, `/readyz`, and Prometheus text at `/metrics`. Readiness fails while draining, when required paths or free-space requirements are missing, when the outbox chain is invalid, when the inherited API is not ready, or when required PostgreSQL connectivity fails.

## Secret boundary

Fixture mode may use the Phase 9F fixture key. Production mode requires `signing_key_env`, rejects disabled TLS, and rejects fixture model mode. The key is decoded from the environment into a mode-0600 startup file solely for the inherited loader and is deleted immediately after the key is loaded into memory. The checked-in examples contain no usable production secret.

Rotate a signing key by deploying a new protected environment value and restarting all API instances in a coordinated window. Existing tokens signed by the old key stop validating. Identity-registry `session_epoch` remains the user-level revocation mechanism.

## Resilience and load control

The gateway enforces:

- global and per-tenant concurrent-request limits;
- checksum-addressed tenant rate and body-size quotas;
- request, read-header, read, write, idle, and shutdown deadlines;
- server-generated or preserved request IDs;
- fail-closed TLS/proxy checks in production;
- graceful `SIGTERM` drain and readiness withdrawal;
- bounded request bodies before the inherited handler reads them.

Tenant identity for quota enforcement is obtained only from a successfully verified Phase 9F bearer token. Unauthenticated traffic is limited by source address.

## Durable operational outbox

The file-backed outbox stores immutable content-addressed messages, idempotency receipts, and one append-only hash chain of lifecycle events. Supported transitions are:

`enqueued → leased → completed`

or

`enqueued → leased → retry_scheduled → leased ...`

Expired leases are recovered explicitly. Attempts are bounded and transition to `dead` after the configured maximum. Reuse of an idempotency key with different request bytes is rejected. `sync-outbox` copies immutable messages and events into PostgreSQL without deleting the local recovery source.

## Backup and restore

Backups are deterministic ZIP archives with sorted entries, fixed metadata timestamps, per-file SHA-256 values, and a checksum-addressed manifest. Restore verifies the full archive before writing. The backup builder refuses filenames that resemble signing keys, `.env` files, or secrets. Production backup roots should contain runtime data only; configuration and secrets should be restored from their governed deployment systems.

The recovery gate validates expired-lease recovery, retries, completion, archive verification, and restore parity.

## PostgreSQL hardening

Migration `009g_production_hardening.sql` uses a transaction-scoped advisory migration lock and creates immutable tables for runtime configuration, quota registries, outbox messages/events, backup catalog entries, and recovery audit events. It enables tenant policies on applicable alert, case, assistance, adapter, and security-audit tables.

The Phase 9G PostgreSQL gate also closes the Phase 9E qualification gap: it synchronizes and asserts one vendor adapter record, idempotency receipt, and audit event. Mutation triggers reject updates and deletes to immutable operational history.

Application connections that query tenant-scoped relational tables should set `openwatchlist.tenant_id` for each transaction. Database-owner connections may bypass non-forced PostgreSQL RLS and must not be used as application identities.

## Observability

Every proxied request emits a structured JSON log with timestamp, request ID, method, path, status, response bytes, and duration. Metrics include request and response counts, in-flight work, cumulative duration, authentication denials, rate limiting, overload rejection, panic recovery, and immutable config/quota lineage.

Protect `/metrics` at the reverse proxy or service-mesh layer. The supplied nginx example restricts it to loopback.

## Deployment contract

`deploy/phase9g` includes a least-privilege systemd unit, TLS reverse-proxy example, non-secret environment template, and container-security contract. Phase 11 will package these contracts into the open-source Docker Compose release; Phase 9G does not introduce a production Compose stack.

## Qualification commands

```bash
./scripts/validate_phase9g.sh
./scripts/validate_phase9g_recovery.sh
PHASE9G_POSTGRES_DSN='postgresql:///temporary_phase9g_db?user=LOCAL_ROLE' ./scripts/validate_phase9g_postgres.sh
```

## Preserved boundaries

Phase 9G cannot alter deterministic screening scores, policy routes, watchlist activation, case decisions, four-eyes requirements, or analyst acceptance of AI drafts. It does not generate regulatory disposition. It does not persist complete watchlist catalogs, full proprietary vendor payloads, or full ISO 20022 documents in PostgreSQL.
