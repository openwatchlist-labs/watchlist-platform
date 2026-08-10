# Phase 8B — real-time and batch screening API

Phase 8B exposes the accepted Phase 7C control plane and Phase 8A Rust candidate runtime through a bounded HTTP service. It does not create a second catalog-selection mechanism and does not treat a no-candidate response as a regulatory clearance.

## Runtime path

```text
POST /v1/screenings or /v1/screenings/batch
  -> exact (source_system_id, raw_list_name) resolution
  -> stable catalog component ID
  -> current Phase 7C-B active version and epoch
  -> exact component/version Rust runtime binding
  -> persistent read-only mmap worker pool
  -> bounded candidate retrieval
  -> Go response and lineage envelope
```

The service reloads catalog and mapping registry snapshots for each request. A promoted or rolled-back active version is therefore observed without restarting the HTTP process when a corresponding runtime package binding is already configured. If the active version has no exact package binding, readiness fails and the service returns `RUNTIME_UNAVAILABLE`; it never falls back to another catalog version.

## Endpoints

- `GET /healthz` reports process liveness.
- `GET /readyz` validates control-plane snapshots and confirms that every active catalog component has an exact Rust package binding.
- `POST /v1/screenings` performs one candidate lookup.
- `POST /v1/screenings/batch` performs an ordered, atomic batch. Runtime or state failure returns no partial batch response.

POST requests require `Idempotency-Key`. `X-Correlation-ID` is optional; when absent, the API derives a stable correlation ID from the request bytes. Reusing an idempotency key with different bytes returns HTTP 409. Completed responses are persisted as immutable local idempotency records beneath the configured ignored state directory.

## Request contract

A request contains the alert's exact source-system and raw list reference plus one lookup query:

```json
{
  "schema_version": "screening-request/v1alpha1",
  "request_id": "payment-20260720-0001",
  "source_system_id": "fircosoft-prod",
  "raw_list_name": "WLS_OFAC_001",
  "effective_at": "2026-07-20T12:00:00Z",
  "query": {
    "kind": "name",
    "value": "ACME IMPORTS",
    "target_entity_types": ["organization"],
    "limit": 20
  }
}
```

Supported query kinds are:

- `name`: exact normalized primary/alias lookup, or prefix lookup when `prefix` is true;
- `identifier`: exact typed identifier lookup and a required `identifier_type`;
- `record_id`: exact provider/runtime record identity lookup.

The initial Phase 8B API intentionally exposes the retrieval capabilities accepted in Phase 8A. It does not claim fuzzy, transliterated, phonetic, contextual, or multilingual matching. Those features require later derived indexes and remain separate from the API transport.

## Response semantics

Responses are one of:

- `matched`: at least one bounded candidate was returned;
- `no_candidates`: the selected exact/prefix runtime lookup returned no candidate;
- `blocked`: list resolution did not produce an available active component.

`no_candidates` is not `clear`. Disposition, false-positive classification, policy routing, RAG, and analyst notes remain Go-owned stages outside this candidate retrieval API.

Every successful lookup includes:

- raw and resolved alert-list identity;
- stable mapping, component, and active catalog-version IDs;
- activation ID and component epoch;
- catalog ID, version, checksum, and mode;
- Rust worker protocol and package SHA-256;
- content-addressed screening and candidate IDs.

Unmapped, future, expired, retired, missing-component, and inactive-catalog results preserve the Phase 7C-C blocker code and do not invoke Rust.

## Rust worker protocol

The Phase 8A binary now includes a long-lived `worker` command. Go starts a configured pool per immutable component/version package. The dependency-free line protocol is private to the process boundary and uses hexadecimal UTF-8 fields so tabs, newlines, and source Unicode cannot corrupt framing.

The worker maps and validates the package once, emits a package hello record, and then handles ordered record, name, prefix, and identifier requests over stdin/stdout. Go verifies the hello metadata against both the configured package checksum and the active catalog-version metadata before serving traffic.

## Configuration and security boundary

The example configuration is `configs/screening-api/example.json`. Production deployments should bind to a private interface or loopback and place authentication, TLS, tenant routing, rate limits, and external authorization at the deployment gateway. Phase 8B does not add public exposure or multi-tenant authorization.

Request body size, batch size, candidate count, worker count, and request timeout are all bounded. JSON decoding rejects unknown fields and trailing values. The API sends `X-Content-Type-Options: nosniff` and never returns local package paths.

## Storage boundary

Phase 8B writes only local idempotency response records. It does not persist screening cases or audit history in PostgreSQL. Durable screening/review persistence remains Phase 8C. Full watchlist entities remain inside immutable `.owmmap` artifacts and are never loaded into PostgreSQL.
