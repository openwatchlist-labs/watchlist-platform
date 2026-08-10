# Phase 8C — deterministic candidate scoring and evidence projection

Phase 8C adds a deterministic scoring boundary after Phase 8B candidate
retrieval. It does not make regulatory clearance decisions and does not expose
full catalog records.

## Scope

The phase adds:

- one immutable JSON scoring policy with a canonical SHA-256 identity;
- integer-only candidate scoring from names, typed identifiers, date of birth,
  country, and entity type;
- stable reason codes and immutable score components;
- bounded evidence projection;
- explicit catalog component/version/activation and normalization lineage;
- canonical candidate ordering and deterministic tie-breaking;
- one engine shared by real-time and ordered batch execution;
- replay goldens and strict unknown-field rejection;
- a typed `internal/screeningapi` bridge for the Phase 8B service.

## Boundary

The scorer accepts only a bounded candidate projection:

- candidate ID;
- names;
- typed identifiers;
- countries;
- dates of birth;
- entity type;
- retrieval routes and retrieval reason codes;
- active catalog lineage.

It does not accept or return a full provider/catalog row. It does not return
`clear`, `investigate`, `escalate`, analyst disposition, or regulatory
clearance. `strength_band` describes candidate support only.

## Score model

The reference policy uses integer points with a 0–1000 range.

| Component | Reference points |
| --- | ---: |
| Exact typed identifier | +550 |
| Exact normalized name | +400 |
| Equal normalized token set | +340 |
| Name prefix | +250 |
| Name containment | +180 |
| Exact date of birth | +120 |
| Same birth year | +60 |
| Exact country | +60 |
| Exact entity type | +40 |
| Date-of-birth contradiction | -180 |
| Country contradiction | -60 |
| Entity-type contradiction | -100 |

Only the strongest name shape is awarded. Exact typed-identifier support is
awarded at most once. Supporting and contradiction components are retained in
the evidence projection even when the final score is clamped to policy bounds.

Reference candidate-strength bands:

- `strong_candidate`: 700–1000;
- `review_candidate`: 400–699;
- `weak_candidate`: 1–399;
- `no_candidate_support`: 0.

These bands are retrieval/scoring metadata, not case decisions.

## Deterministic ordering

Candidates are ordered by:

1. score descending;
2. exact typed-identifier match before non-exact;
3. exact name match before non-exact;
4. candidate ID ascending.

Batch items preserve request order. Each item independently applies canonical
candidate ordering.

## Evidence projection

Each candidate response includes:

- candidate ID and score;
- candidate-strength band;
- exact-identifier and exact-name flags;
- stable, sorted reason codes;
- ordered score components;
- bounded evidence items with subject value, candidate value, outcome, points,
  and reason code;
- retrieval routes/reasons;
- provider, catalog, component, version, activation, and normalization lineage;
- scoring policy ID, version, and SHA-256 at response level.

## API integration seam

`internal/screeningapi.Phase8CCandidateScorer` is the typed bridge for Phase 8B.
The real-time route calls `Score`; the batch route calls `ScoreBatch`. Both use
the same immutable engine and policy reference.

The service adapter should project Phase 8B runtime candidates into
`candidatescoring.CandidateEnvelope`, call the bridge, and place the resulting
candidate projections under the screening result. The idempotency layer must
persist and replay the byte-exact final response as it already does in Phase
8B.

## Commands

Validate the policy:

```bash
go run ./cmd/candidate-score check-policy \
  --policy configs/scoring/candidate-scoring-r1.json
```

Score one candidate set:

```bash
go run ./cmd/candidate-score score \
  --policy configs/scoring/candidate-scoring-r1.json \
  --input test/fixtures/candidate-scoring/realtime.request.json
```

Score an ordered batch:

```bash
go run ./cmd/candidate-score batch \
  --policy configs/scoring/candidate-scoring-r1.json \
  --input test/fixtures/candidate-scoring/batch.request.json
```

Run the phase gate:

```bash
./scripts/validate_phase8c.sh
```
