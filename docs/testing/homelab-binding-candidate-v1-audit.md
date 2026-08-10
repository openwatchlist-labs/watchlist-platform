# Homelab binding candidate v1 audit

## Audited evidence

- Candidate ZIP SHA-256: `77de465ba119c7aa42eed3747ea05cc99db552ec36a2fcdd93e4986ebee235dc`
- `binding-candidates.v1.json` SHA-256: `abf1df2c21bb14b137ee0af491c191edf43c685a85f32bc00a33fcce5a8eb9cb`
- `binding-candidates-review.md` SHA-256: `39a44c34aeb96adf875874478f011fd60b7c1d4efc1e119195492179206feed5`
- Candidate set: `binding_candidates_1bc7a328177b167ffd77_20260722T164710Z`
- Frozen lock: `frozen_5ca7d77862f9976ac1bd257b`

## Verdict

The v1 pack is structurally complete and preserves the frozen source lock, but it is **not review-eligible** and must not be used to select or finalize bindings. All 315 executions remain blocked.

## Findings

### 1. Advisory rank is mostly OFAC UID order

- 34 of 35 archetypes have one score value across all eight candidates.
- Only `fp-034` has more than one score value.
- All 35 lists are ordered by descending score and then numeric OFAC UID.
- Therefore rank 1 is not generally stronger than ranks 2–8 when scores tie.

### 2. Candidate pools are over-reused

The pack has 280 rows but only 88 unique candidate IDs; 192 rows are repeated assignments. Only 19 unique ordered candidate lists exist across 35 archetypes.

Identical candidate-list groups include:

- `fp-002`, `fp-007`, `fp-016`, `fp-025`, `fp-028`
- `fp-004`, `fp-005`, `fp-017`, `fp-022`, `fp-024`
- `fp-003`, `fp-018`, `fp-021`, `fp-029`
- `fp-009`, `fp-019`, `fp-030`
- `fp-001`, `fp-023`
- `fp-010`, `fp-015`
- `fp-012`, `fp-027`

Sharing a real record can be valid, but identical pools across different failure mechanics require explicit mechanic-specific evidence. V1 does not provide that evidence.

### 3. Provider evidence is mixed

The v1 generator combines official OFAC aliases and OpenSanctions names into `ofac.selected_aliases`. It also stores the OpenSanctions FollowTheMoney schema in `ofac.entity_type`. This blurs provider lineage and prevents a reviewer from distinguishing official OFAC fields from provider-normalized fields.

### 4. Evidence is flattened and loses semantics

- Identifiers are untyped strings.
- Dates are untyped and can include separately extracted year, month and day values.
- Countries do not preserve their role, such as nationality, address country or vessel flag.
- Addresses and locations are omitted from the candidate projection.
- Gender evidence needed by `fp-027` is not represented.
- Critical missing qualifiers needed by `fp-010`, `fp-015`, `fp-034` and `fp-035` are not explicitly selected.
- The exact token, alias or typed identifier that will drive each synthetic collision is not recorded.

### 5. Selection strategies are often scoring hints instead of hard eligibility rules

Candidates can rank despite not naturally supporting the archetype. For example, the intermediary-bank acronym archetype can include non-bank organizations when a generic word such as `fund` triggers a finance score. The sovereign-debt archetype can reuse candidates that satisfy a broader keyword rule but lack a government or ministry qualifier.

### 6. The 13-UID population delta is not reconciled

The pack reports 19,182 OpenSanctions exact OFAC UID referents against 19,169 current OFAC `DistinctParty` records, but does not provide set differences. Final evidence must separately record:

- current OFAC UIDs with an exact crosswalk;
- current OFAC UIDs without one;
- exact OpenSanctions OFAC referents absent from the current frozen OFAC snapshot;
- balancing equations and bounded samples.

### 7. Record hash label is inaccurate

`source_record_sha256` is computed over an ElementTree serialization, not exact source bytes. It must be labeled as a parser serialization or canonical projection hash and must not imply byte-exact source-subtree hashing.

## Required repair

The replacement candidate pack must:

1. enforce hard archetype-specific eligibility before ranking;
2. preserve official OFAC and OpenSanctions evidence in separate objects;
3. retain typed identifiers, dates, countries, locations, programs and gender;
4. record the exact real-source feature and a synthetic collision seed;
5. disclose score components and ties;
6. require selection by immutable candidate ID, not display rank;
7. reconcile current OFAC and OpenSanctions UID sets;
8. block review when any archetype has no hard-eligible candidate or any exact crosswalk is ambiguous;
9. preserve named manual review and all-35 atomic finalization.
