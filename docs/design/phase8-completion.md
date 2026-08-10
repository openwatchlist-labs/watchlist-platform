# Phase 8 completion baseline

Phase 8 is complete and validated through Phase 8G. It supplies the full runtime path from immutable catalog artifacts to durable, reproducible screening-event and operational-audit storage.

## Completed increments

| Increment | Completed boundary |
|---|---|
| 8A | Provider-neutral Go export contract, dependency-free Rust compiler, read-only memory-mapped catalog package, and bounded record/name/prefix/typed-identifier retrieval |
| 8B | Exact alert-list resolution, active component/version binding, persistent Rust worker pools, and idempotent real-time and ordered batch retrieval APIs |
| 8C | Immutable checksum-addressed scoring policy, integer-only scoring, stable reason codes, deterministic ordering, and bounded evidence projection |
| 8D | Policy-bound scored screening response contract with real-time/batch parity, projection blockers, and non-dispositive similarity bands |
| 8E | Catalog-derived projection packages, exact coverage checks, Go/Rust payload conformance, and atomic catalog/projection/policy activation tuples |
| 8F | Immutable promotion intents, CAS-protected rollout state, deterministic shadow comparison, canary routing, fleet acknowledgements, promotion, rollback, and hash-chained operational audit |
| 8G | Durable screening-event ledger, AES-256-GCM decision-input snapshots, PostgreSQL persistence, idempotency receipts, replay, export, retention, repair sync, and audit convergence |

## Current public runtime boundary

`cmd/screening-api-v8g` is the latest public screening front door. It preserves the exact Phase 8F response bytes and does not release a successful response until the request, response, activation lineage, bounded decision inputs, and audit lineage have satisfied the configured durability requirement.

Earlier Phase 8 commands remain intentionally available as isolated compatibility and regression surfaces:

- `cmd/screening-api` — Phase 8B candidate retrieval;
- `cmd/candidate-score` — Phase 8C deterministic scoring;
- `cmd/screening-api-v8d` — Phase 8D scored response contract;
- `cmd/projection-package`, `cmd/scoring-activation`, and `cmd/screening-api-v8e` — Phase 8E package and activation tuple;
- `cmd/activation-promotion` and `cmd/screening-api-v8f` — Phase 8F rollout and operational audit; and
- `cmd/screening-ledger` and `cmd/screening-api-v8g` — Phase 8G durable delivery and audit.

## Final Phase 8 invariants

- Catalog, projection, scoring-policy, activation, promotion, screening-event, and operational-audit lineage are checksum-addressed.
- Candidate retrieval and scoring remain deterministic, bounded, and replayable.
- Real-time and batch paths preserve request ordering, candidate ordering, correlation lineage, and idempotency.
- Inactive, mixed, stale, missing, or tampered activation members cannot silently serve traffic.
- Promotion requires immutable intent, revision compare-and-swap, configured evidence thresholds, and required fleet acknowledgements.
- Screening response delivery can require durable PostgreSQL persistence before response release.
- Every delivered response can be tied to exact request-byte and response-byte SHA-256 values.
- Reproducible decision-input snapshots are encrypted and retention-controlled.
- Local and PostgreSQL screening and operational records are append-only or restricted to audited retention transitions.
- Full catalog rows remain immutable data-plane artifacts and are not stored in PostgreSQL or returned by the screening API.
- Similarity bands and rollout states are non-dispositive; Phase 8 does not issue regulatory clearance, alert disposition, or analyst decisions.

## Accepted validation evidence

The accepted Phase 8 baseline passed:

- complete Go repository regression tests;
- Rust memory-mapped catalog unit, contract, worker-protocol, and Go/Rust projection-conformance tests;
- exact alert-list resolution and active-lineage enforcement;
- deterministic real-time and batch scoring parity;
- atomic activation, rollback, and interrupted-state recovery;
- controlled canary, promotion, fleet acknowledgement, rollback, and audit verification;
- byte-exact idempotent replay and key-reuse conflict detection;
- local durable screening-ledger, encrypted snapshot, replay, export, retention, and recovery gates; and
- disposable PostgreSQL migration, event synchronization, idempotency, retention, and operational-audit import gates.

The accepted disposable PostgreSQL run synchronized one screening event and imported one Phase 8F operational-audit event. Fresh-database trigger-drop `NOTICE` messages are expected because migration `008g_screening_ledger.sql` defensively removes prior triggers before recreating them.

## Validation commands

Validate the complete local Phase 8 implementation:

```bash
./scripts/validate_phase8g.sh
```

Inspect the durable fixture ledger and current Phase 8G configuration:

```bash
go run ./cmd/screening-ledger status \
  --ledger-dir test/fixtures/screening-ledger/state \
  --key-file test/fixtures/screening-ledger/snapshot-key.hex \
  --ledger-id screening-api-v8g-example

go run ./cmd/screening-api-v8g check \
  --config configs/screening-ledger/phase8g-example.json
```

Validate PostgreSQL only against a disposable database:

```bash
createdb temporary_phase8g_db

PHASE8G_POSTGRES_DSN="postgresql:///temporary_phase8g_db?user=$(whoami)" \
  ./scripts/validate_phase8g_postgres.sh

dropdb temporary_phase8g_db
```

The PostgreSQL gate creates and purges fixture rows and must not target production.

## Completion boundary

Phase 8 completes runtime retrieval, deterministic scoring, bounded evidence, atomic activation, controlled promotion, durable screening delivery, PostgreSQL persistence, reproducible input snapshots, replay, retention, and tamper-evident audit storage.

Subsequent phases may consume the immutable Phase 8 event and evidence contracts for alert creation, case orchestration, model validation, analyst workflows, observability, and deployment automation without weakening the Phase 8 decision-ownership and data-boundary guarantees.
