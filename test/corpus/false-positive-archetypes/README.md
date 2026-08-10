# False-positive archetype corpus

**Status: ported, unbound.** The archetype registry and its governing schemas
are ported from the legacy repository. No archetype is bound to a frozen OFAC
snapshot yet — every `real_data_binding` in `archetypes.v1.json` still points
at `frozen_real_ofac_snapshot` as a *requirement*, not a resolved record.
Binding archetypes to real data is a separate, later issue that requires a
frozen OFAC snapshot; this port does not attempt it (see "What this port does
not do" below).

## Origin

Ported under SAL-2/SAL-3 (S0-5) from the frozen legacy repository
(`watchlist-platform-legacy`, commit `31aa23f516018f7577f4dcec95142f981142a6f8`),
where it lived at `testdata/homelab/`. It did not migrate during the clean
restart because the import gate blocks `testdata/homelab/` and `cmd/homelab*/`
by path prefix — a placement problem, not a decision that the content was
unsafe. It contains no secrets and no real PII: archetype definitions,
binding recipe templates, and JSON schemas only.

Per the corpus's own `source_note`: it is "derived from 35 user-provided
Fircosoft-style industry false-positive examples. The original illustrative
watchlist IDs, biographies, scores, and release decisions are not
qualification truth." The supplied examples are pattern evidence for the
failure modes that recur in production transaction screening — common names,
transliteration, field-type errors, substrings, acronyms, missing qualifying
words, narrative context, and asset/person/company confusion — not a source
of watchlist truth in themselves. The corpus converts each into a durable
industry archetype, to be bound (later, separately) to real watchlist records
from a frozen snapshot.

The full design rationale lives in
[`docs/testing/homelab-ofac-opensanctions-functional-test-plan.md`](../../../docs/testing/homelab-ofac-opensanctions-functional-test-plan.md)
(itself a ported, historical document — see `docs/design/README.md` for the
caveats that apply to it).

## Why this corpus matters

`internal/adversarialtest` currently exercises `internal/matcherbaseline`,
which is explicitly off the production path (see the top-level `CLAUDE.md`).
That means, until this corpus is bound to a live provider path, **the
repository has no recall measurement against the production matching path at
all.** This corpus is the instrument intended to close that gap once binding
work lands.

## Governing principles

Carried over unchanged from the legacy functional test plan:

1. **Real watchlist truth only.** OFAC names, aliases, UIDs, entity types,
   programs, dates, countries, addresses, and identifiers must come from a
   frozen official snapshot — never invented.
2. **Synthetic innocent side.** Payment parties, payment messages, KYC
   conflicts, and controlled mutations are synthetic and must not represent a
   real innocent person or company.
3. **No invented provider lineage.** OpenSanctions entities must be
   cross-walked to the same OFAC source record and retain their own provider
   identifiers.
4. **No regulatory disposition.** Scenarios may assert candidate tiers,
   mismatch evidence, reason codes, or review recommendations. They must never
   expect auto-release, regulatory clearance, or a confirmed false-positive
   decision.
5. **Paired controls.** Every false-positive archetype has a true-positive and
   a near-negative control using the same real watchlist record.

(A sixth principle from the legacy plan — "frozen qualification, separate
freshness" — governs the binding step this port does not perform, so it isn't
restated here as a constraint on this directory's contents.)

## Corpus shape

- **35 archetypes** (`archetypes.v1.json`), each with paired
  `false_positive` / `true_positive` / `near_negative` controls across 3
  provider modes (`native_ofac`, `opensanctions_ofac`, `dual_provider`) —
  105 core scenarios, 315 minimum provider-mode executions.
- Archetype families include (non-exhaustive; 17 distinct families total in
  the current registry): substring collision, transliteration, entity-type
  conflict, typed-identifier collision, name permutation, acronym collision,
  narrative context, and denial context.
- Every archetype's `expected_invariants.regulatory_disposition` is
  `"not_provided"` and every `forbidden_outcomes` list includes
  `regulatory_clearance`, `regulatory_release`, `auto_release`, and
  `confirmed_false_positive` — the schema-level enforcement of governing
  principle 4.

## Layout

```
test/corpus/false-positive-archetypes/
├── README.md                                   (this file)
├── archetypes.v1.json                          (the 35-archetype registry)
├── schemas/                                    (JSON schemas; not yet wired to a validator library — no new dependency)
│   ├── false-positive-archetypes.v1.schema.json
│   ├── frozen-source-lock.v1.schema.json
│   ├── real-ofac-binding-candidates.v1.schema.json
│   ├── real-ofac-binding-candidates.v2.schema.json
│   ├── real-ofac-bindings.v1.schema.json
│   └── real-ofac-governed-bindings.v1.schema.json
└── bindings/                                   (unpopulated templates only)
    ├── frozen-source-lock.v1.template.json
    └── real-ofac-bindings.v1.template.json
```

`cmd/corpus-validate` (ported from the legacy `cmd/homelab-testdata-validate`)
validates `archetypes.v1.json` and `bindings/real-ofac-bindings.v1.template.json`
against the structural rules the schemas describe, and exits non-zero on any
violation. Run it with `go run ./cmd/corpus-validate` from the repository
root.

## What this port does not do

- Does not bind any archetype to real OFAC data. `frozen-source-lock.v1.json`
  and `real-ofac-bindings.v1.json` (the *populated* evidence files, as
  opposed to the `.template.json` files above) were deliberately not copied —
  binding requires a frozen snapshot and is a separate issue.
- Does not modify archetype content or add archetypes. All 35 are
  byte-identical to the legacy source.
- Does not wire this corpus into `internal/adversarialtest` or any live
  screening path. It is data and a validator, not yet a recall measurement.
