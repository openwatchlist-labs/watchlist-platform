# Phase 3A: Deterministic name matcher baseline

Phase 3A adds the first fuzzy matcher without changing the accepted list-ingestion, runtime-package, activation, or update-manager boundaries.

The `ofac-baseline` provider consumes the same portable `.owpcat` package used by the exact-only runtime. Identifier, date, address, and other non-name routes continue through the exact index. `normalized_name`, `alias`, and `transliteration` routes use deterministic integer feature scoring.

## Feature evidence

Each name candidate records token-alignment, edit, ordered-token, phonetic, and length similarity in basis points. Weights total 10,000. Contributions, penalties, threshold, reason codes, matcher version, and profile-set checksum are part of the candidate identity and output contract. Floating point is not used.

The accepted profile set is `configs/matcher-profiles/ofac-name-baseline-r1.json`, with separate party-name and financial-institution thresholds. It is strict JSON and content-addressed. This controls retrieval only; it is not the later decision-policy layer.

## Entity-type mismatch

A strong name match whose catalog entity type is incompatible with the ISO 20022 field is suppressed. The result remains `no_candidates` for that record and carries an `entity_type_mismatch` diagnostic with score, threshold, feature evidence, source assertions, and request lineage.

## Backward compatibility

Evidence and diagnostics are optional contract fields. Legacy fixture, direct-list, and exact compiled-runtime providers retain their accepted byte-identical goldens.

## Deliberate limits

Phase 3A does not add fuzzy addresses or identifiers, embargo-geography catalogs, narrative scoring, false-positive classification, decision policy, or LLM decisions.
