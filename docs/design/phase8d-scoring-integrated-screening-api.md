# Phase 8D — Scoring-integrated screening API and policy-bound response contract

Phase 8D promotes the deterministic Phase 8C scorer into the public screening
response path without weakening the accepted Phase 8B retrieval boundary.

## Deployment boundary

The accepted Phase 8B `cmd/screening-api` remains the retrieval backend and is
bound to a loopback or private service address. The Phase 8D
`cmd/screening-api-v8d` process is the public screening front door and exposes:

- `GET /healthz`
- `GET /readyz`
- `POST /v1/screenings`
- `POST /v1/screenings/batch`

Requests are forwarded byte-for-byte to Phase 8B. Candidate identifiers and
retrieval reasons are then joined to a bounded candidate projection registry,
scored by the immutable Phase 8C engine, canonically ordered, and returned under
the Phase 8D response contract.

The Phase 8B backend should not be exposed directly once Phase 8D becomes the
public endpoint.

## Readiness contract

`/readyz` is successful only when:

1. the checksum-addressed scoring policy loads and validates;
2. the bounded projection registry loads and validates;
3. the projection normalization profile matches the policy;
4. the Phase 8B backend reports ready.

The readiness response publishes the policy identifier, version, policy SHA-256,
normalization profile, projection-set SHA-256, and configured upstream address.

## Candidate projection boundary

The projection registry contains only attributes needed by the deterministic
scorer:

- candidate identifier;
- names and aliases;
- typed identifiers;
- countries;
- dates of birth;
- entity type.

It is not a catalog export and must not contain full source records, sanctions
program narratives, addresses, document blobs, or provider payloads. Missing
projections produce the explicit blocker `candidate_projection_unavailable`.
They are never silently ignored as successfully evaluated candidates.

## Response contract

`POST /v1/screenings` returns
`openwatchlist.screening-response.v2`. Each response contains:

- request and correlation identifiers;
- SHA-256 of the exact request bytes received by Phase 8D;
- explicit blockers;
- screened field path and bounded value projection;
- immutable scoring-policy reference;
- active catalog component/version/activation lineage;
- canonically ordered scored candidates.

Each candidate contains integer score components, stable reason codes, bounded
evidence, retrieval routes, and one non-dispositive similarity band:

| Phase 8C strength | Phase 8D response band |
| --- | --- |
| `strong_candidate` | `high_similarity` |
| `review_candidate` | `possible_similarity` |
| `weak_candidate` or below | `low_similarity` |

These bands describe candidate similarity only. They are not alert decisions,
regulatory clearance, case disposition, or analyst conclusions.

## Batch behavior

`POST /v1/screenings/batch` forwards one ordered batch to Phase 8B and requires
one retrieval result for every input item. Input item order is retained. Within
each item, candidate order is deterministic: score descending, exact identifier
support, exact name support, and candidate identifier tie-break.

The same policy object and scoring engine are used for real-time and batch
execution.

## Idempotency

Phase 8D keeps its own file-backed idempotency state at the public API boundary.
For the same route and idempotency key:

- identical request bytes replay the exact previously returned response bytes;
- different request bytes return HTTP `409`;
- the replay does not call the Phase 8B backend again.

The request is also forwarded with its original idempotency key on first
execution, preserving Phase 8B protection behind the façade.

## Example operation

Start the accepted Phase 8B retrieval backend on its private address:

```bash
go run ./cmd/screening-api serve --config configs/screening-api/example.json
```

Start the Phase 8D public front door:

```bash
go run ./cmd/screening-api-v8d serve \
  --config configs/screening-api/phase8d-example.json
```

Check configuration and immutable bindings without starting a listener:

```bash
go run ./cmd/screening-api-v8d check \
  --config configs/screening-api/phase8d-example.json
```

## Explicit exclusions

Phase 8D does not add:

- regulatory clearance or denial;
- alert or case disposition;
- analyst decision automation;
- LLM-only matching;
- complete catalog rows in API responses or PostgreSQL;
- mutation of the active catalog pointer.
