# Phase 9A–9B: deterministic alert and case-management backend

## Status

Phase 9A–9B is the deterministic product bridge from the accepted Phase 8G screening ledger to durable alert and case workflows. It deliberately excludes RAG, Ollama, generated notes, and model guardrails; those belong to the single Phase 9C deliverable.

## Ingress contracts

The backend accepts either:

1. an immutable `openwatchlist.screening-ledger-event.v1` record whose event hash is reverified before alert creation; or
2. a strict `openwatchlist.external-alert.v1` envelope preserving source system, source alert ID, exact raw list name, external score/reasons, matched fields, candidate/message/attachment references, and exact Phase 7C-C alert-list resolution.

Unknown top-level HTTP fields are rejected. External raw list names are never trimmed, case-folded, or fuzzily resolved.

## Deterministic alert creation

Alert identity is content-addressed from tenant, source identity, and the checksum-addressed policy decision. The reference policy boundary projects Phase 4-style pattern and countervailing evidence from bounded candidate reason codes and then applies Phase 5-style deterministic thresholds, blockers, stable reason codes, and ordered rule traces. No analyst action or future AI output can modify this alert-time policy record.

Routes remain deterministic platform routes (`clear`, `investigate`, or `escalate`). An alert record is not an analyst disposition.

## Case event model

The authoritative case history is an append-only SHA-256 chain. `projection.json` is a rebuildable convenience view. Every mutation requires an expected revision and is rejected on compare-and-swap conflict.

Supported actions are:

- `assign`
- `start_investigation`
- `request_evidence`
- `submit_evidence`
- `propose_decision`
- `approve_decision`
- `reject_decision`
- `reopen`
- `link_rescreen`

Approval and rejection enforce four-eyes separation: the actor must differ from the decision proposer. Decisions are superseded by later events rather than updated in place.

## Persistence

Local files provide retry-safe, content-addressed state and hash-chained audit. When PostgreSQL is required, the API persists the alert/case event, idempotency receipt, membership, projection, and all local operational audit events before returning success. A PostgreSQL failure returns a retryable service error; retrying the same idempotency key completes persistence without creating a second object.

Migration `009ab_alert_case_management.sql` adds:

- `alert_record`
- `alert_case`
- `alert_case_membership`
- `alert_case_event`
- `alert_case_idempotency`
- `alert_case_audit`

Alert records, memberships, case events, receipts, and audit rows are immutable. The current case projection is the only updateable operational row and is guarded by monotonic revisions.

Full catalog rows remain outside PostgreSQL.

## HTTP API

- `GET /healthz`
- `GET /readyz`
- `POST /v1/alerts`
- `POST /v1/alerts/batch`
- `GET /v1/alerts/{id}`
- `POST /v1/cases`
- `GET /v1/cases/{id}`
- `POST /v1/cases/{id}/events`
- `POST /v1/cases/{id}/verify`

## Validation

```bash
./scripts/validate_phase9ab.sh

go run ./cmd/alert-case-api check \
  --config configs/alert-case/phase9ab-example.json
```

A disposable live PostgreSQL gate is available:

```bash
PHASE9AB_POSTGRES_DSN='postgresql:///temporary_phase9ab_db?user=YOUR_LOCAL_ROLE' \
  ./scripts/validate_phase9ab_postgres.sh
```

The live gate writes fixture rows and must not target production.
