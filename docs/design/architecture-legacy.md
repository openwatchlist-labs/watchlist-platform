# Architecture

## System intent

OpenWatchlist Platform reduces avoidable watchlist-review work while preserving false-negative protection, evidence lineage, deterministic replay, and human accountability. The platform can screen native source messages or ingest alerts produced by an external engine.

## Logical components

```text
+----------------------+        +-------------------------+
| ISO 20022 / batch /  |        | External screening     |
| API source messages  |        | engine alert exports   |
+----------+-----------+        +------------+------------+
           |                                 |
           v                                 v
+----------------------------------------------------------------+
| Canonical evidence and governed adapter boundary                |
| source paths, transaction index, entity type, identifiers,      |
| names, addresses, geography, amounts, references, source hash   |
+-------------------------------+--------------------------------+
                                |
                                v
+----------------------------------------------------------------+
| Catalog runtime and candidate retrieval                         |
| immutable provider/component/version lineage, mmap indexes,      |
| exact identifier, exact/prefix name, bounded fuzzy candidates    |
+-------------------------------+--------------------------------+
                                |
                                v
+----------------------------------------------------------------+
| Deterministic decision path                                     |
| integer scoring -> false-positive classification -> policy       |
| thresholds -> blockers -> route -> reason codes                  |
+-------------------------------+--------------------------------+
                                |
                                v
+----------------------------------------------------------------+
| Durable operations                                              |
| encrypted screening ledger, PostgreSQL projections, alert/case, |
| idempotency receipts, outbox, backup, restore, audit chains      |
+-------------------------------+--------------------------------+
                                |
                  +-------------+-------------+
                  |                           |
                  v                           v
+--------------------------------+  +-----------------------------+
| Governed assistance            |  | Review console              |
| corpus snapshot, hybrid RAG,    |  | signed tokens, tenant RBAC, |
| citations, model profiles,      |  | four-eyes actions, security |
| Guardian unsupported-claim gate|  | audit, no-store browser UI   |
+--------------------------------+  +-----------------------------+
```

## Decision and trust boundaries

- Catalog refresh and activation are governed separately from request processing.
- Candidate retrieval never owns policy or case disposition.
- Scoring and policy are deterministic and checksum-addressed.
- RAG and LLM components can summarize evidence and retrieve cited guidance, but cannot clear, escalate, approve, activate, or mutate authoritative records.
- The API derives tenant and actor identity from signed claims; client-supplied actor fields are overwritten.
- Four-eyes controls prevent the proposing analyst from independently approving the same decision or assistance record.
- PostgreSQL records, file ledgers, and audit events use append-only or immutable contracts.

## Runtime deployment

```text
client
  -> TLS gateway :8443
      -> platform-api :18094
          -> file-backed runtime state and outbox volume
          -> PostgreSQL durability and readiness
          -> optional Ollama endpoint for governed assistance
```

The API runs as a non-root user with a read-only root filesystem, dropped capabilities, bounded writable state, request and concurrency limits, fail-closed readiness, and graceful SIGTERM drain. PostgreSQL migrations execute through a one-shot service before the API becomes available.

## Primary stores

| Store | Purpose | Mutation contract |
|---|---|---|
| Immutable catalog package | Watchlist/provider entities and indexes | New package + governed activation |
| Screening ledger | Request/response replay and operational evidence | Append-only hash chain |
| Alert/case state | Human workflow and idempotency | Append-only events with projections |
| Assistance state | RAG/LLM request, response, citations, review | Immutable records and independent review |
| Security audit | Authentication and authorization outcomes | Append-only hash chain |
| Operational outbox | Durable inter-component delivery | Immutable message + leased event stream |
| PostgreSQL | Durable searchable projections and release evidence | Transactions, immutability triggers, tenant RLS |
| Backup archives | Deterministic restore material | Content-addressed, secret-excluding archives |

## Release architecture

Phase 11 adds two OCI targets:

- `platform-api`: the hardened runtime API plus PostgreSQL client readiness support.
- `release-tooling`: migration, evaluation, benchmark, recovery, and artifact-verification tools.

Release qualification binds source commit, image IDs/digests, SBOM hashes, scan results, benchmark report, database backup hash, upgrade/rollback report, and deterministic release-manifest hash into one evidence directory.
