# H1 governed real-source binding selection and acceptance

## Purpose

This gate turns the r1.12 `binding-candidates.v2.json` evidence into one manually reviewed, atomically accepted 35-archetype binding set. It does not treat quality rank as approval and never releases a partial set.

H1 r1.13.1 binds the reviewer to the actual r1.12 v2 field contract. The compact review and accepted state must preserve:

- `display_order` as the deterministic workbook position;
- `quality_rank` as the score-derived rank, including explicit ties;
- `normalized_entity_type` or `opensanctions.entity_schema` as normalized schema evidence;
- `mechanic_evidence.selected_real_source_feature` as the exact mechanic feature;
- typed OFAC and OpenSanctions identifiers, programs, dates, countries, locations, and gender as complexity inputs.

Blank schema or exact-mechanic fields are contract failures and cannot be selected, reviewed, or finalized.

## States

1. `review_open` — proposals may exist, but every H1 execution remains blocked.
2. `reviewed_pending_set` — all 35 selections passed per-binding validation and a named reviewer approved the complete selection digest. Executions still remain blocked.
3. `bound` — a named approver accepted the unchanged complete set and immutable acceptance evidence was written.

The prior `binding-candidates.v1` format is rejected. Only candidate-set IDs beginning with `binding_candidates_v2_` are selectable.

## Governance controls

- Exactly one candidate must be selected for each of `fp-001` through `fp-035`.
- Every selection records a named reviewer, timestamp, exact candidate snapshot, snapshot hash, normalized schema, display order, quality rank, exact mechanic, and substantive rationale.
- Selecting below the highest **quality rank** requires a written reason for rejecting higher-ranked candidates. A later display order in the same tied rank does not require a false rejection rationale.
- Reusing an OFAC UID or OpenSanctions entity across archetypes requires a written justification on every affected selection.
- A deterministic proposal is advisory only. `propose` never writes a selection.
- The candidate pack SHA-256 is pinned when review starts. Any byte change invalidates the review state.
- Candidate-pack field-contract validation runs before initialization or state access.
- Acceptance is atomic. There is no command for accepting one binding.
- Final evidence contains no regulatory disposition.

## Workflow

After applying r1.13.1, refresh proposal-only metadata and inspect the repaired rendering:

```bash
./scripts/homelab/h1-governed-binding.sh propose
./scripts/homelab/h1-governed-binding.sh show fp-001
./scripts/homelab/h1-governed-binding.sh status
```

Expected `show` fields include separate `order=<n> rank=<n>`, non-empty `schema=<type>`, and a non-empty JSON `Exact mechanic` value.

Record a selection only after reviewing the real source evidence:

```bash
./scripts/homelab/h1-governed-binding.sh select \
  fp-001 <candidate-id> \
  --reviewer "Piyush Daiya" \
  --rationale "The official OFAC name or alias contains the required mechanic token and the crosswalked record supplies independent secondary biography."
```

For a genuinely lower quality rank, add:

```bash
--higher-ranked-rejection "The higher-ranked candidates add confounding source complexity or conflict with the archetype-specific mechanic."
```

After all 35 are selected:

```bash
./scripts/homelab/h1-governed-binding.sh review-set \
  --reviewer "Piyush Daiya" \
  --statement "Reviewed every binding, exact mechanic, schema, source crosswalk, rejection rationale, and reuse disclosure as one complete set."
```

Finalize without changing the repository binding file:

```bash
./scripts/homelab/h1-governed-binding.sh finalize \
  --approver "Piyush Daiya" \
  --statement "Approve this immutable 35-binding set for H1 qualification evidence."
```

To materialize the repository's pre-existing `real-ofac-bindings.v1.template.json` and promote it only after repository validators pass, add `--promote`. A failed validator causes automatic rollback. A set finalized without promotion can later be promoted with `./scripts/homelab/h1-governed-binding.sh promote`. Until promotion succeeds, all 315 executions must remain blocked.

## Evidence

Finalization writes:

```text
var/homelab/evidence/binding-acceptance-<UTC>/
├── governed-real-ofac-bindings.v1.json
├── binding-acceptance-report.v1.md
├── real-ofac-bindings.v1.materialized.json   # when a legacy template exists
├── repository-validator.log
└── SHA256SUMS
```

The mutable review state remains under:

```text
var/homelab/binding-review/<candidate_set_id>/governed-selection-state.v1.json
```

Once the state is `bound`, it is immutable. A binding change requires a new candidate set and a new review.
