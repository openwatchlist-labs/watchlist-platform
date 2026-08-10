# H1 r1.13.2 governed selection recommendations

## Scope

This layer records a complete reviewer-attributed 35-archetype selection set from the immutable r1.12 v2 candidate pack. It does not review the complete set, accept it, promote a legacy binding file, or unblock H1 qualification executions.

Pinned inputs:

- Candidate set: `binding_candidates_v2_1bc7a328177b167ffd77_20260722T171954Z`
- Candidate-pack SHA-256: `d042921d1e28dd91da86078c221d7ccda585f837f37c5c20cb72cdc896694cf9`
- Repaired review ZIP SHA-256: `3b8b9757a815ce6087957416908a0df07f68b8a62aece6783f9223c2d9a22aba`
- Recommendations: `testdata/homelab/real-ofac-governed-selection-recommendations.v1.json`

## Selection policy

The recommendation set requires exactly one hard-eligible candidate for each `fp-001` through `fp-035`, 35 unique OFAC UIDs, 35 unique OpenSanctions entities, zero candidate warnings, reviewer attribution, and lower-rank rejection rationale. It performs no set review, acceptance, or promotion as a side effect.

Thirty-one proposals are retained. Four are replaced: `fp-001`, `fp-004`, `fp-012`, and `fp-027`.

## Lifecycle-safe validation repair

H1 r1.13.3 repairs the recommendation contract test so it remains valid after selections, complete-set review, acceptance, and promotion.

The validator:

1. treats the live governed state as immutable input;
2. verifies the pinned candidate pack and recommendation document;
3. verifies acceptance evidence and the promoted binding when present;
4. creates an isolated clone with selections, set review, and acceptance cleared;
5. tests the 35-selection transaction only in that clone;
6. tests rerun, reviewed-state, bound-state, and tampered-input refusal;
7. proves the live state, promoted binding, and acceptance evidence are byte-for-byte unchanged.

The validator must not require the live repository to remain in the pre-selection `0/35` state.

## Validation

```bash
./scripts/validate_homelab_binding_review.sh
./scripts/validate_homelab_governed_binding.sh
./scripts/validate_homelab_governed_binding_recommendations.sh
```

There is no repository command named `scripts/validate_homelab_testdata.sh` in this workstream. The canonical homelab test-data Go contract is exercised with:

```bash
go test ./cmd/homelab-qualification
```

## Accepted and promoted state

Once the governed set is `bound`, recommendation application remains forbidden. The lifecycle-safe validator tests the original transaction in a temporary clean-state clone; it never reopens, replaces, or mutates the accepted set.
