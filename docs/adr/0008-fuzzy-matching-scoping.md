# ADR-0008: Variant-tolerant matching — scope, shape, and staging

- **Status:** Proposed
- **Date:** 2026-08-14
- **Issue:** DOM-1 (P0), scoping only
- **Related:** DOM-2 (catalog format v2, not yet designed), DOM-3 (ADR-0004, accepted),
  DOM-10, DOM-13, SEC-1b (ADR-0003), SEC-7 (ADR-0007), SAL-1/2/3, PR #113, issue #115
  (DOM-3 projection name coverage — split out of §6.3(c), blocks a projection-based
  rescorer)
- **Supersedes:** nothing. No prior ADR is modified. ADR-0004 is cited for the scoring
  contract it established, not amended.

## Context

`README.md:12-24` (Table 1, "Matching capability") lists eleven variant classes and marks
seven of them "Not supported" on the live screening path: typo/character transposition,
token reordering, name particles and compounds, concatenation splitting,
transliteration/cross-script, phonetic, and non-ASCII case variants. PR #113 turned that
table into an executable claim: `internal/screeningapi/dom1_unsupported_regression_test.go`
runs one case per unsupported row through the real `StartRuntimeManager` wiring against the
real compiled Rust package, and asserts each returns zero candidates today.

DOM-1 is the initiative to close those rows. This document does not close them. Under
CLAUDE.md rule 7 the deliverable at this stage is a written, reviewed decision record; the
implementation PRs reference it.

Every claim below was verified against the working tree at `527f61f`. Where the assumption
already on record turned out to be wrong, §3 and §4 say so rather than designing quietly
around it.

The assumption on record is that DOM-1 is mostly plumbing. The private register states it
directly: "The matcher capable of doing the job (`internal/matcherbaseline`) already exists
in this repository and is deliberately excluded from the production path — so Sprint 4 is
largely integration, not invention" (`docs/backlog/issue-register.md:396`; the register is
deliberately excluded from version control, `.gitignore:27`, so it is cited by line for
traceability but cannot be opened from a clone). Its proposed mechanism is to "promote
`matcherbaseline` to a **second-stage rescorer**: widen retrieval with token-signature +
n-gram blocking keys in the compiled index, then apply token alignment +
Damerau-Levenshtein/Jaro-Winkler + phonetic" (`:310`).

That assumption is half right, and the wrong half changes both the size and the risk
profile of the work. The scoring engine really does exist and really is better than the
register credits it for (§2). But it cannot be "wired in", because the live retrieval path
returns nothing for it to rerank (§3) — and the register's proposed fix, blocking keys in
the compiled index, is the most expensive of three available options rather than the only
one (§4).

## 1. What the live path actually does

`Service.screenAt` builds a single `runtimemmapclient.Query` from the request and issues
exactly one lookup (`internal/screeningapi/service.go:85-96`). The worker accepts three
query verbs and no others — `record`, `name` (with an exact/prefix flag), and `identifier`
(`runtime/catalog-mmap/src/worker.rs:57-84`). Each resolves by binary search over a sorted,
memory-mapped section: `lookup_record` at `runtime/catalog-mmap/src/format.rs:476-498`,
`lookup_name` at `:500-562`, `lookup_identifier` at `:564-615`.

Both index and query are normalized by the same function, `normalize_ascii`
(`runtime/catalog-mmap/src/format.rs:769-800`), which case-folds only bytes below `0x80`
and passes every byte at or above `0x80` through unchanged (`:774-781`).

There is no scan verb, no enumerate verb, and no similarity verb. This is the single most
consequential fact in this document and §3 is entirely about its implications.

## 2. What `internal/matcherbaseline` actually implements

The package exists, is 1,343 lines across 12 files, and its tests pass today
(`go test ./internal/matcherbaseline/ ./internal/adversarialtest/ ./internal/matchercontext/`
— all `ok` at `527f61f`).

Read from the source rather than from its doc comment, it implements:

**Normalization** (`internal/matcherbaseline/normalize.go`):

- `fold` (`:22-70`) applies Unicode `ToUpper`, folds Latin diacritics, and applies a
  transliteration map that includes **the full Cyrillic alphabet** mapped to Latin
  digraphs — `Ж → ZH`, `Х → KH`, `Щ → SHCH`, `Ю → YU` (`:15-19`). It deletes Unicode
  format characters and decorative connector punctuation (`:140-149`).
- `resolveBidiOverrides` (`:95-135`) reverses RLO/LRO-wrapped spans before folding, which
  defeats the "Trojan Source" name-spoofing technique.
- `tokens` (`:151-160`) splits, then canonicalizes nicknames
  (`internal/matcherbaseline/nicknames.go:29`), canonicalizes the `EL → AL` transliteration
  variant (`internal/matcherbaseline/transliteration_variants.go:36-38`), drops corporate
  suffixes (`internal/matcherbaseline/corporate_suffixes.go`), and drops person honorifics
  (`internal/matcherbaseline/person_honorifics.go`).

**Similarity** (`internal/matcherbaseline/similarity.go`), five weighted features combined
in `scoreName` (`:13-37`):

- `editSimilarity`/`levenshtein` (`:82-112`) — plain Levenshtein. Note for the record: this
  is **not** Damerau. There is no transposition operator, so a two-character transposition
  costs 2 edits, not 1. The register's `:310` deliverable text names
  "Damerau-Levenshtein/Jaro-Winkler"; neither is implemented.
- `bestEditSimilarity` (`:64-74`) — the max of raw and token-sorted edit similarity.
- `tokenAlignmentSimilarity` (`:140-162`) — bidirectional per-token best match.
- `orderedTokenSimilarity` (`:163-187`) — LCS over tokens at a 7000 bp per-token gate.
- `phoneticSimilarity`/`soundex` (`:188-244`) — Soundex, greedy per-token code equality.
- `lengthSimilarity` (`:125-139`).

**Penalties**: single-token (`similarity.go:28-31`) and weak-alias
(`internal/matcherbaseline/provider.go:101-107`).

**Governance**: threshold profiles are checksum-bound and validated on load
(`internal/matcherbaseline/profile.go:35-94`, `:96-113`), which means the engine already
matches this repository's convention that a scoring artifact carries a verifiable digest.

It is exercised by a real scenario bank: 42 adversarial scenarios across
`test/fixtures/adversarial/adversarial-scenarios-v1.json` and `-v2.json`, of which 29
stress cases (variants *not* registered as aliases) pass today, with the remainder tracked
by an explicit `known_status` field rather than hidden
(`internal/adversarialtest/adversarial_test.go:7-36`).

### 2.1 Measured: what it would do to Table 1's rows

To answer "which rows can this engine actually close", the six pure-scoring source files
(`similarity.go`, `normalize.go`, `nicknames.go`, `corporate_suffixes.go`,
`person_honorifics.go`, `transliteration_variants.go` — none of which import anything
outside the standard library) were copied verbatim into a scratch program, given the
shipped `party_name_r1` profile from
`configs/matcher-profiles/ofac-name-baseline-r1.json:21-30` (threshold 7800, diagnostic
floor 6800), and run over all eight name entries in the compiled fixture's source
(`test/golden/ofac-advanced/ofac-sdn-catalog.json`) using the exact seven queries PR #113
uses.

| Table 1 row (PR #113 query) | best score vs. intended record | verdict at 7800 |
| --- | --- | --- |
| Typo / transposition (`ACME IMPROTS`) | 9070 | match |
| Token reordering (`IMPORTS ACME`) | 9250 | match |
| Particles and compounds (`EXAMPLE`) | 5957 | no |
| Concatenation splitting (`ACMEIMPORTS`) | 4669 | no |
| Transliteration / cross-script (`DZHORDAN EKZAMPL`) | 10000 | match |
| Phonetic (`AKMEE IMPORTZ`) | 7665 | no (above the 6800 diagnostic floor) |
| Non-ASCII case (`джордан экзампл`) | 10000 | match |
| Control: exact alias (`ACME IMPORTS`) | 10000 | match |
| Control: exact Cyrillic alias (`Джордан Экзампл`) | 10000 | match |

Four of the seven rows score above threshold with the engine and profile as they ship
today. The cross-script row scores a perfect 10000 because `fold`'s Cyrillic map turns the
stored alias `Джордан Экзампл` (`test/golden/ofac-advanced/ofac-sdn-catalog.json:109`) into
exactly `DZHORDAN EKZAMPL`. The non-ASCII case row scores 10000 because `fold` applies
Unicode `ToUpper` rather than ASCII-only folding.

Two rows the engine genuinely does not handle: concatenation splitting (there is no split
step anywhere in `normalize.go`) and particles/compounds (no particle table exists; see
§7.1 on why that query is not a valid test of it anyway).

One row is a calibration question, not a capability question: the phonetic case scores 7665
against a 7800 threshold — 135 bp short. Soundex agrees on both tokens; the composite is
dragged under by edit similarity on `AKMEE` vs `ACME`. Whether that row closes depends on
moving a checksum-governed threshold, which is a measurement decision, not an engineering
one (§8.3).

**Honest caveat, stated once and load-bearing for everything below:** this fixture is 3
records and 8 names. The table proves the engine has the *capability* to recall these
variants. It proves nothing whatsoever about precision — with 8 names there is no
opportunity for a false positive. Precision requires SAL-1 (§7.2).

## 3. The blocker is recall, not scoring

`matcherbaseline` cannot be "wired into" the live path, for a structural reason that is
easy to miss because both things are called "the matcher".

`matcherbaseline.NewProvider` takes an `ofacruntime.RuntimePayload` — the pure-Go `.owpcat`
compiled format (`internal/matcherbaseline/provider.go:22-52`,
`internal/ofacruntime/doc.go:1-11`) — and `SearchWithDiagnostics` scores the query against
**every** name entry in that payload in a linear scan
(`internal/matcherbaseline/provider.go:90-132`). It is a scanner. It has always been a
scanner, because the analysis tool it serves (`cmd/matcher-run`) works over a whole
compiled catalog offline.

The live path is a binary-search index over a different compiled format (`.owmmap`) reached
over a stdio protocol with three exact-lookup verbs (§1). `docs/ARCHITECTURE.md:164-183`
documents all three compiled formats and states the separation explicitly.

The practical consequence is the finding this ADR exists to record:

> **Post-retrieval reranking over exact-match candidates is not an available design.** When
> a fuzzy variant is queried, exact retrieval returns the empty set. There is nothing to
> rerank. Any DOM-1 stage must first solve *candidate generation*, and only then apply
> scoring.

This reframes the question the investigation was asked. It is not "Go-side reranking versus
Rust format change". It is: **what is the cheapest mechanism that produces a candidate set
at all**, and the answer determines whether Rust and re-qualification are involved.

### 3.1 Measured: why the naive answer is unavailable

The naive answer — hand the Go side the whole catalog and let `matcherbaseline` scan it —
was costed. `scoreName` issues 29 `levenshtein` calls per candidate for a
three-token-vs-three-token comparison (two whole-string, two directions of
`directedTokenScore`, plus `orderedTokenSimilarity`'s grid). A scratch cost model
replicating that call shape measures roughly 6 µs per candidate:

| catalog names | full-scan scoring, single-threaded |
| --- | --- |
| 1,000 | 18 ms |
| 10,000 | 86 ms |
| 40,000 | 246 ms |
| 100,000 | 610 ms |

OFAC SDN alone is on the order of 40k name entries once aliases are counted; adding the
lists Table 2 marks unsupported pushes past 100k.

Against `request_timeout_ms` — 5000 in `test/fixtures/screening-api/config.json:20`, 10000
in `configs/screening-api/example.json:20` — a single `POST /v1/screenings` survives at
40k. `POST /v1/screenings/batch` does not: `ScreenBatch` calls `screenAt` serially per item
(`internal/screeningapi/service.go:231-232`) and `max_batch_items` may be as high as 10,000
(`internal/screeningapi/config.go:58`). A 1,000-item batch at 246 ms per item is 246
seconds inside a 5-second timeout.

**Blocking is mandatory, not an optimization.** Every design below is a blocking strategy.

## 4. Three candidate-generation strategies, and the rule-6 boundary between them

All three were checked against the real compiled fixture
(`test/golden/runtime-mmap/ofac-fixture.owmmap`, `package_sha256 8c5e581a…`) using the
`catalog-mmap` binary built from source at `527f61f`.

### 4.1 Strategy A — Go-side query expansion over the existing protocol

Rewrite the query into a bounded set of deterministic variants and issue one existing
`name` lookup per variant, then union the results and rescore.

Observed against the live worker:

| probe | exact | prefix |
| --- | --- | --- |
| `ACME IMPORTS` | 1 match | 1 match |
| `IMPORTS ACME` | 0 | 0 |
| `ACMEIMPORTS` | 0 | 0 |
| `ACME` | 0 | **1 match** |
| `EXAMPLE` | 0 | **1 match** |

So: the reordered query misses, but reissuing the sorted permutation `ACME IMPORTS` hits.
The concatenated query misses, but reissuing the split `ACME IMPORTS` hits. And a
**first-token prefix probe is a working blocking key today** — `ACME` recalls
`ofac:sdn:1001` — which recalls candidates for typos that fall after the blocked prefix.

`Query.Prefix` is already plumbed end to end (`internal/screeningapi/service.go:90`), so
the server can set it internally rather than relying on the client.

Cost: Go only. No Rust change, no recompile, no binding re-qualification, no scoring
activation re-issue.

Limits, stated honestly: expansion is a one-way function. It cannot generate the Cyrillic
byte sequence a cross-script query needs to reach, it cannot enumerate the strings sharing
a Soundex code, and a first-token prefix block misses any typo in the blocked prefix
itself.

### 4.2 Strategy B — a new worker query kind, protocol bump only

Add a blocking-key verb to the worker: given a computed key (sorted-token signature,
n-gram, or Soundex bucket), return the bounded set of name entries that share it. The
worker already holds the whole names section mmapped; the scan happens in Rust at a cheap
per-entry cost, and only the surviving candidates cross the stdio boundary into Go's
expensive Levenshtein scoring.

This bumps `WORKER_PROTOCOL_VERSION` from `"1"` (`runtime/catalog-mmap/src/worker.rs:5`),
which the Go client checks on the hello frame (`internal/runtimemmapclient/worker.go:63-66`)
and the screening service checks again at bind time
(`internal/screeningapi/runtime.go:126-128`).

It does **not** bump `PACKAGE_SCHEMA_VERSION` (`runtime/catalog-mmap/src/format.rs:9`), does
not change the section directory, does not change `normalize_ascii`, and does not change
any `PackageSHA256`. **CLAUDE.md rule 6 does not fire**, because rule 6 governs
`normalize_ascii` and the compiled package layout, neither of which this touches. Existing
compiled catalogs keep working; only the worker binary and the client advance together.

### 4.3 Strategy C — blocking keys baked into the compiled package

Precompute keys into new sorted sections of the `.owmmap` package. This is the register's
`:310` proposal.

This **is** a rule-6 release event: `PACKAGE_SCHEMA_VERSION` bump, full catalog recompile,
and re-qualification of every runtime binding's `PackageSHA256`. It additionally
invalidates the DOM-3 scoring activation, which pins `catalog_package_sha256` (§6.3).

Recommendation: never ship Strategy C as an independent release event. DOM-2 already
requires exactly this bump for format v2. If Strategy C is needed, it ships merged into
DOM-2's bump so the platform absorbs one recompile-and-re-qualify cycle, not two.

### 4.4 Where the boundary actually falls

The row that genuinely requires index-side change is **non-ASCII case folding**. Verified:
neither `джордан экзампл` nor `ДЖОРДАН ЭКЗАМПЛ` matches the stored `Джордан Экзампл`; only
the exact stored casing does, because `normalize_ascii` leaves bytes at or above `0x80`
untouched (`runtime/catalog-mmap/src/format.rs:774-781`). Go-side case permutation is not a
strategy — it is exponential in name length.

That row is **DOM-13's**, not DOM-1's (`docs/backlog/issue-register.md:155`, `:312`), and
DOM-13 is already classified as a coordinated release event. One of Table 1's seven
"Not supported" rows therefore does not belong to this issue at all — a scoping correction
worth making explicit, because a DOM-1 plan that silently owns it inherits a release event
it does not need.

Worth recording as the useful corollary: once *recall* exists by any mechanism,
`matcherbaseline`'s Go-side `fold` closes that row anyway at scoring time, without touching
`normalize_ascii` (§2.1, 10000 bp). DOM-13 remains the correct owner of index-side
Unicode correctness; DOM-1 gets the row's practical effect for free as a side effect of
Stage 2.

## 5. Decisions

- **D1.** DOM-1 is scoped as a *candidate-generation* problem with a *rescoring* second
  stage, not as an integration of `matcherbaseline` into the request path. §3 is the
  justification.
- **D2.** DOM-1 ships in stages that are individually revertible, ordered by rising blast
  radius: Go-only, then protocol-only, then (conditionally) format change. §7.
- **D3.** `internal/matcherbaseline` is the rescorer. It is not rewritten for DOM-1; it is
  called. Its concatenation-splitting and particle gaps are closed inside it, as normalizer
  additions in the style of the existing `corporate_suffixes.go` / `nicknames.go` tables.
- **D4.** Table 1's non-ASCII case row is reassigned to DOM-13 in DOM-1's tracking. DOM-1
  does not modify `normalize_ascii`.
- **D5.** Each stage's acceptance is the corresponding PR #113 case flipped from "asserts no
  match" to "asserts match", per that file's own instruction
  (`internal/screeningapi/dom1_unsupported_regression_test.go:14-22`) — with the two
  exceptions §7.1 and §7.2 identify.
- **D6.** No stage merges without a stated precision result. A recall-only acceptance gate
  is exactly the "flatteringly low FP rate and unmeasured FN rate" failure the register's
  DOM-1 row warns about (`docs/backlog/issue-register.md:67`), inverted.

## 6. Coupling with already-shipped work

Four surfaces were checked. One is clean, one is clean with an operational hazard, one has
three real couplings, and one general property applies to every stage.

### 6.1 SEC-7 (ADR-0007) — no coupling

`internal/screeningapi` does not import `internal/screeningledger` anywhere. The audit and
event chains are written on the vendor-adapter and ledger-CLI paths
(`cmd/screening-ledger/main.go`), not on the screening request path. Nothing DOM-1 does at
any stage touches the keyed chain or its anchor.

### 6.2 SEC-1b (ADR-0003) — no tenancy coupling, one operational hazard

Tenant identity is resolved from the verified token and used **only** to scope the
idempotency record path (`internal/screeningapi/http.go:91`, `:96-97`, `:156`).
`Service.Screen` takes no tenant, and the compiled catalog is shared across tenants. Adding
candidate generation does not touch the tenant boundary.

The hazard is elsewhere. Idempotency records key on a digest of endpoint plus request body
(`internal/screeningapi/http.go:97`) and replay verbatim on a matching key
(`internal/screeningapi/idempotency.go:39-46`). A record written before a DOM-1 stage lands
will keep replaying its stale pre-fuzzy `no_candidates` response afterwards. Each stage
needs an explicit disposition — expire, namespace by matcher version, or accept and
document. This ADR does not choose; it requires the choice (§8.5).

### 6.3 DOM-3 (ADR-0004) — three real couplings

**(a) Activation pinning.** `ValidateScoringRuntimeProfile`
(`internal/screeningapi/scoring.go:54-65`) requires the runtime package's own
`normalization_profile` to equal the scoring policy's. The activation additionally pins
`catalog_package_sha256`, `retrievable_candidate_count`, and
`retrievable_candidate_ids_sha256`
(`test/fixtures/scoring-activation/state-ofac-sdn-direct/activations/activation-dom-3-ofac-sdn-direct.json`).
Strategy C invalidates all of them and forces a new scoring activation. Strategies A and B
invalidate none.

**(b) The scoring vocabulary has no word for "fuzzy".** `candidatescoring.bestNameMatch`
(`internal/candidatescoring/engine.go:332-392`) independently recomputes a name shape and
recognizes exactly four: `exact`, `token_set`, `prefix`, `containment`. It already has a
concept for token reordering (`equalTokenSet`,
`internal/candidatescoring/normalize.go:67-79`), which is convenient for Stage 1. It has
**none** for typo, phonetic, or cross-script. A fuzzy candidate surfaced today would fall
through all four cases, contribute zero name points, and be returned scored as though the
name had not matched at all.

Retrieval routes are passed through as free-form strings and merely normalized
(`internal/screeningapi/service.go:157`, `internal/candidatescoring/engine.go:218`), so
nothing *fails* — which is the problem. The scoring vocabulary must extend in lockstep with
each stage, and the extension is a policy change: a new weight is a new
`policy_sha256`.

This collides with DOM-10, which wants `prefix` and `containment` *removed* as scoring
shapes because they score substring accidents as identity evidence
(`docs/backlog/issue-register.md:141`). Stage 1's prefix-probe blocking is a *retrieval*
mechanism, not a scoring shape, so the two are compatible — but only if that distinction is
made deliberately rather than discovered later (§8.6).

**(c) The compiled catalog can match on names the scoring projection cannot see — tracked
separately as issue #115.** Found while scoping DOM-1 and moved out of this ADR, because it
is a live DOM-3 defect on today's path rather than a DOM-1 dependency. Summarized here only
as far as DOM-1 needs it; #115 carries the full characterization and the reproduction.

The divergence is one-directional and confined to one record: for `ofac:sdn:2002` the
compiled `.owmmap` carries the Cyrillic alias `Джордан Экзампл`
(`test/golden/ofac-advanced/ofac-sdn-catalog.json:109`) and the projection does not
(`test/fixtures/projection-package/ofac-sdn-direct-canonical-input.json:22-24`). The catalog
is a strict superset — 8 names to the projection's 7. No name exists in the projection that
the catalog lacks, and no record ID has conflicting content.

It is not latent. Because `candidatescoring.bestNameMatch` recomputes the name shape from
the projection rather than trusting the retrieval hit, a live exact-alias query on that name
returns `status: "matched"` with `score: 0`, `strength_band: "no_candidate_support"`, and
empty `reason_codes`, `components`, and `evidence`, where the correct value is `name_exact`
= 400 — the `review_candidate` threshold exactly. Nothing catches it: the coverage checksum
`retrievable_candidate_ids_sha256` digests record IDs only
(`internal/projectionpackage/package.go:99-106`), and `validateInputBinding` (`:322-340`)
compares metadata identity, never name content.

Consequence for DOM-1, which is all this ADR needs from it: a rescorer that reads candidate
names from the projection index is blind to names retrieval can see. Any stage that rescores
must read matched values from the runtime result
(`internal/screeningapi/service.go:113-134`, which carries `MatchedValue` and `PrimaryName`
per candidate), or wait on #115. This is a genuine prerequisite, not a nicety — but it is
#115's prerequisite to clear, not DOM-1's to carry.

**(d) A non-finding, recorded so it is not re-derived.** Widening retrieval *within the same
catalog* does not trip `BlockerCandidateProjectionUnavailable`
(`internal/screeningapi/service.go:160-172`), because the activation binds the projection to
the package's complete retrievable record set. Any record the runtime can return is already
in the index.

### 6.4 Screening identity changes, by construction

`screeningID` digests the entire response including the candidate list
(`internal/screeningapi/id.go:18-25`). Every stage that changes which candidates come back
changes the screening ID for an otherwise identical request. This is correct behavior — the
ID is content-addressed on purpose — but it means a stage is not replay-compatible with
screenings taken before it, and any downstream comparison of screening IDs across a stage
boundary is invalid.

## 7. Staged breakdown

### Stage 1 — Go-only: query expansion plus rescoring

Deterministic query expansion (Strategy A) inside the screening service: token permutation,
concatenation split, particle/suffix strip, and a first-token prefix probe, each issued as
an existing `name` lookup, results unioned and deduplicated by record ID; then
`matcherbaseline` rescoring over the union; then the `candidatescoring` vocabulary
extension for the shapes produced.

Closes: token reordering, concatenation splitting, and particles/compounds (the last
conditional on §7.1).

Requires no Rust change, no recompile, no binding re-qualification, no scoring activation
re-issue. Bounded and revertible: the expansion set is a fixed, enumerable function of the
query, so the worst-case lookup count per request is known at review time rather than
discovered in production.

Prerequisite from §6.3(c): rescoring reads matched values from the runtime result, or issue
#115 closes first.

### Stage 2 — Rust protocol bump: blocking-key recall

Add the blocking-key verb (Strategy B), bump `WORKER_PROTOCOL_VERSION` `"1"` → `"2"`, and
feed its bounded output to the Stage 1 rescorer.

Closes: typo/character transposition, transliteration/cross-script, phonetic (subject to
§8.3), and — as the §4.4 corollary, without touching `normalize_ascii` — the practical
effect of the non-ASCII case row that formally belongs to DOM-13.

`PACKAGE_SCHEMA_VERSION` untouched; CLAUDE.md rule 6 does not fire.

Gated on the §8.1 spike. If the Rust scan cannot meet the latency budget at production
catalog size, Stage 2 as specified does not ship and Stage 3 becomes mandatory rather than
conditional.

### Stage 3 — conditional: blocking keys in the compiled package

Only if Stage 2 misses its budget. Strategy C, shipped merged with DOM-2's format v2 bump
as a single release event, never as a second independent one.

### Why this order

Typo tolerance is the highest-value single row — it is the variant class that dominates
real screening traffic — but it is Stage 2's, because it is the row that most needs
index-side recall. Stage 1 is nonetheless first, and the argument is not close: it buys two
and a half rows at zero format risk, and it builds the rescoring seam, the reason-code
vocabulary, and the precision-measurement harness that Stage 2 then reuses. Landing the
seam under a cheap, revertible change and *then* pointing an expensive recall mechanism at
it is strictly safer than doing both at once. It also front-loads the DOM-3 coupling work
(§6.3) into the stage where a mistake costs nothing to unwind.

### 7.1 One PR #113 case cannot serve as acceptance criteria

The `name_particles_and_compounds` case declares itself a synthetic stand-in
(`internal/screeningapi/dom1_unsupported_regression_test.go:220-232`): no fixture record
carries a true `AL`/`BIN`/`VAN DER` particle, so it substitutes the semantically-void `MV`
prefix on the vessel alias `MV EXAMPLE` and queries the bare `EXAMPLE`.

That query does not test particle handling. Verified against the live worker: a prefix probe
for `EXAMPLE` returns `ofac:sdn:3003` — but by matching the *unrelated primary name*
`Example Vessel`, not by any particle-aware treatment of `MV EXAMPLE`. Stage 1's prefix
probe would flip this case for entirely the wrong reason.

The row needs a fixture record carrying a genuine particle before its acceptance criterion
means anything. Adding one is in Stage 1's scope.

### 7.2 PR #113 measures recall, and only recall

The regression suite proves a variant now matches. It cannot show what that match costs in
false positives, because the fixture is 3 records and 8 names.

The instrument for that is SAL-1/2/3, which is ported but **unbound**:
`test/corpus/false-positive-archetypes/` holds 35 archetypes across 17 families —
`substring_collision` ×5, `transliteration` ×3, `entity_type_conflict` ×3,
`typed_identifier_collision` ×3, `missing_qualifying_terms` ×3, `name_permutation` ×2, and
eleven more — and every one carries `status: "planned_unbound"`
(`test/corpus/false-positive-archetypes/archetypes.v1.json:46`). Its own README states the
position exactly: "until this corpus is bound to a live provider path, **the repository has
no recall measurement against the production matching path at all**"
(`test/corpus/false-positive-archetypes/README.md:36-46`).

D6 requires a precision result per stage. Whether that means binding SAL-1 first, or
standing up an interim measurement against the adversarial bank, is §8.4's open question.

## 8. What is genuinely uncertain

These are named, not solved. Each blocks scoping of the stage it belongs to, and each
needs its own investigation before an implementation PR opens.

1. **Rust blocking-key scan cost at 40k–100k names.** Stage 2's gating measurement, and it
   was not taken here. The Go-side scoring cost is measured (§3.1); the Rust-side key-scan
   cost is not. A spike against a synthetic catalog of realistic size decides whether Stage
   2 or Stage 3 is the real Stage 2.
2. **Blocking-key selection.** Sorted-token signature, character n-gram, Soundex bucket, or
   a union. Each has a different recall/candidate-count curve, and no data exists anywhere
   in this repository to choose between them. This is the substantive design content of a
   follow-on ADR, not something to settle in an implementation PR.
3. **Phonetic threshold recalibration.** The phonetic row misses by 135 bp (§2.1). Closing
   it means moving `threshold_basis_points` in a checksum-governed profile
   (`configs/matcher-profiles/ofac-name-baseline-r1.json:22`), which changes
   `profile_set_checksum` and cannot responsibly be done without the precision instrument
   §7.2 says does not exist yet.
4. **Whether SAL-1 binding is a hard prerequisite for Stage 1** or may trail it. D6 requires
   *a* precision result; it does not currently specify that it must come from SAL-1.
5. **Disposition of pre-DOM-1 idempotency records** at each stage boundary (§6.2).
6. **Sequencing against DOM-10.** DOM-10 removes `prefix`/`containment` as *scoring* shapes;
   Stage 1 introduces prefix probing as a *retrieval* mechanism. The two are compatible, but
   only if the distinction is designed in rather than discovered when DOM-10 lands.
7. **Whether `matcherbaseline`'s edit distance should become Damerau.** A transposition
   currently costs 2 (§2). The typo row passes anyway at this fixture size. Whether that
   holds under real data is a measurement question, and the register's `:310` text assumes
   an algorithm that is not present.

## 9. Accepted risks and non-goals

- **R1.** The §2.1 measurements are taken against 3 records and 8 names. They establish
  capability and nothing about precision. No stage may cite them as evidence of fitness.
- **R2.** The §3.1 latency figures are a cost model of `scoreName`'s call shape, not a
  benchmark of `matcherbaseline` itself (its internal packages cannot be imported from
  outside the module). They are order-of-magnitude evidence that full-scan rescoring is
  unavailable, and are used for nothing finer than that.
- **R3.** Stage 1 changes recall on the live path without a bound precision instrument. This
  is a real, accepted risk of the staging, mitigated only by D6 and by the platform's zero
  deployed traffic (`README.md:105-106`).
- **R4.** Closing Table 1's rows on this repository's synthetic fixture does not entitle the
  README to claim variant-tolerant screening. Table 1 changes when a stage ships **and** its
  precision result is recorded, not when a regression case flips.
- **N1.** Non-goal: this ADR does not select a blocking key (§8.2), does not recalibrate any
  threshold (§8.3), and does not design DOM-2's format v2.
- **N2.** Non-goal: index-side Unicode correctness. That is DOM-13's, and it stays there
  (D4).

## Consequences

DOM-1 is smaller than the register's "L" estimate for its first stage and larger than
"largely integration" overall. The scoring engine is real, tested, and closes four of seven
rows as it ships — that part of the assumption on record holds, and holds more strongly
than the register credits. But the engine cannot be wired to anything, because the live path
returns nothing to rerank, and the register's proposed remedy (blocking keys in the compiled
index) is the most expensive of three options rather than the only one.

The practical result of this scoping is that most of DOM-1's value is reachable without a
release event. Stage 1 is Go-only. Stage 2 bumps a worker protocol version, not a package
schema version, and leaves every compiled catalog and every binding `PackageSHA256` intact.
Only Stage 3 is a rule-6 event, it is conditional on a measurement not yet taken, and if it
is needed it should be absorbed into DOM-2's bump rather than spending a second
recompile-and-re-qualify cycle.

Three things surface as prerequisites that were not previously tracked as such. One of them
turned out not to belong to DOM-1 at all: the catalog/projection name divergence is a live
DOM-3 scoring defect, now issue #115, and it blocks any projection-based rescorer until it
closes (§6.3(c)). The other two are DOM-1's own — the particle regression case (§7.1) cannot
accept its own row, and the precision instrument (§7.2) is unbound, so today a stage can be
shown to find more and cannot be shown to be right. Two scoping corrections follow: Table 1's
non-ASCII case row belongs to DOM-13, and
the register's serialization of DOM-2 before DOM-1
(`docs/backlog/issue-register.md:386`) binds Stage 3 only — Stages 1 and 2 need names,
which the compiled catalog already carries.

Nothing in this document changes behavior. `README.md` Table 1 stands unmodified until a
stage ships with a precision result behind it.

## Addendum: Stage 1 mechanism decisions (2026-08-14)

- **Status:** Proposed
- **Trigger:** an implementation attempt at Stage 1 (§7) stopped before writing code, per this
  project's standing rule to report rather than guess when a specification is ambiguous. Two
  pieces of §7's mechanism turned out to have no implementable answer in the base document,
  and a third row's acceptance vehicle turned out to have an unmet prerequisite. This addendum
  resolves all three. It is a pure addition — no existing decision (D1-D6) is revised, and
  nothing above this section is edited.
- Every claim below was verified against the working tree at `7561e84` (current tip of `main`
  at the time this addendum was written), the same standard §Context sets for the base ADR.

### Addendum context: §7's two silent gaps

§7 Stage 1 states the mechanism as: query expansion and lookup, "then `matcherbaseline`
rescoring over the union; then the `candidatescoring` vocabulary extension for the shapes
produced." Two things in that sentence have no implementable answer as written:

1. `matcherbaseline` has no call surface for "rescore this union." Its only exported
   entry points are `NewProvider`, `LoadProfileSet`, `ValidateProfileSet`, and
   `StableProfileSetChecksum` (`internal/matcherbaseline/provider.go:22`,
   `profile.go:17,37,96`); `scoreName` and `fold` are package-private
   (`similarity.go:13`, `normalize.go:22`). `Provider.SearchWithDiagnostics` always scans
   every entry in the `ofacruntime.RuntimePayload` it was constructed from
   (`provider.go:90`) — it has no notion of "score this query against this specific small
   candidate list."
2. `candidatescoring.bestNameMatch` recognizes exactly four shapes —
   `exact`/`token_set`/`prefix`/`containment` (`internal/candidatescoring/engine.go:332-372`)
   — and none of them fire for a concatenation-split or particle-stripped match. Concretely
   verified: normalizing `"Klaas Berg"` and `"Klaas van der Berg"`
   (`candidatescoring/normalize.go:9-25`) gives `"KLAAS BERG"` and `"KLAAS VAN DER BERG"`,
   which are not equal, not equal token sets, not a prefix of each other, and — because
   `"VAN DER"` interrupts the shared words — not a substring of each other either
   (`strings.Contains`, `engine.go:355`). A retrieved particle candidate would find *no
   shape at all* and fall straight into #116's `BlockerNameMatchUncorroboratedByProjection`
   (`internal/screeningapi/service.go:204-220`) — correctly, since that guard cannot tell a
   real data gap from a genuinely unmatched name, but that means Stage 1's retrieval half
   is not sufficient by itself to flip this row from "Not supported" to "Supported."

Also worth surfacing before either decision, because it bears on both: `docs/ARCHITECTURE.md:16-43`
currently states, as a committed architectural fact, that "**two genuinely different
retrieval/matching paths exist in this codebase, by design** ... `screeningapi` does not
import `matcherbaseline`, `matcherprovider`, or `matchercontext` at all," and
`docs/ARCHITECTURE.md:90-100` states `matcherbaseline` "does not feed into `candidatescoring`,
`policyengine`, or any part of the live request lifecycle ... and there is no expectation that
it should." `internal/matcherbaseline/doc.go:1-6` says the same thing from the other side:
the package "is intentionally NOT the retrieval path production `cmd/screening-api` uses."
D3 already commits DOM-1 to making this false — `matcherbaseline` becomes "the rescorer"
(§5, D3) — but no document currently says so. **Whichever mechanism AD1 below picks,
`docs/ARCHITECTURE.md`'s "two genuinely separate paths" framing and its "does not feed into
`candidatescoring`" claim must be corrected in the same PR that lands Stage 1's rescoring
call**, or committed documentation becomes wrong the moment the code merges. This is not a
new open question — it is a known, textual edit — but naming it here means it isn't
rediscovered post-hoc the way issue #115 was found only after digging into a different
feature (§6.3(c)).

### AD1. The `matcherbaseline` call mechanism

**Option (a): export a new pair-scoring function.** Something in the shape of
`ScorePair(query, candidateName string, profile ThresholdProfile) (score int, evidence
[]FeatureEvidence, penalty int)`, added to `matcherbaseline` as a thin wrapper around the
existing unexported `fold` (`normalize.go:22-70`) and `scoreName`
(`similarity.go:13-37`) — the same two calls `Provider.SearchWithDiagnostics` already makes
per candidate (`provider.go:84,94,100`), just addressed at one caller-supplied pair instead
of a whole scanned payload. `ThresholdProfile` values load and checksum-validate once, at
process startup, via the existing `LoadProfileSet`/`ValidateProfileSet` path
(`profile.go:17-34`, `:37-94`) — the same "validate once at load, call cheaply per request"
shape `internal/screeningapi` already uses for `candidatescoring`'s policy
(`NewScoringBinding`, `internal/screeningapi/scoring.go:25-45`, wrapping a `LoadedPolicy`
whose SHA256 is verified once inside `NewEngine`, `candidatescoring/engine.go:20-36`). No
`ofacruntime.RuntimePayload` construction, no synthetic `SourceAssertions`, no per-request
schema validation.

**Option (b): synthesize a per-request `ofacruntime.RuntimePayload`.** Build a payload from
the live candidate union and run it through the already-exported `NewProvider`/`Search`
(`matcherbaseline/provider.go:22`,`54`). No new exported surface on `matcherbaseline` itself.
But `ofacruntime.ValidatePayload` (`internal/ofacruntime/validate.go:67-97`) requires every
entry to set `Exact: true` and carry a non-empty `SourceAssertions` list
(`validate.go:94`), and requires `NormalizedQuery == normalize(MatchedValue)`
(`validate.go:91-93`) — fields that assert a compiled, source-confirmed catalog entry, not a
live retrieval hit whose exactness is precisely what the rescoring step exists to determine.
Setting `Exact: true` on a query-expansion candidate to satisfy the validator would write a
false claim into a schema whose whole purpose is provenance integrity. `NewProvider` also
re-runs both `ValidatePayload` and `ValidateProfileSet` on every construction
(`matcherbaseline/provider.go:22-28`) — validation work sized for compiling a whole offline
catalog, paid again per request for a union of a handful of live candidates. And it pulls
`internal/screeningapi` into a dependency on `internal/ofacruntime`'s compiled-package types
(`RuntimePayload`, `CompiledEntry`, `SourceAssertions`) purely to satisfy a schema those types
were never meant to carry live retrieval data through.

**Decision: (a).** Option (b)'s validator is not a neutral compatibility shim — `Exact: true`
and non-empty `SourceAssertions` are true, meaningful claims about how a compiled catalog
entry was produced, and forcing them onto a live fuzzy candidate to pass validation means
writing false provenance data to satisfy a checksum-adjacent structure — the same
"flatteringly low FP rate" corner-cutting D6 already warns against in the recall-vs-precision
context, here in the schema-integrity context instead. Option (a) is a narrower,
purpose-built surface change; it costs zero per-request re-validation because profile
loading already follows the codebase's existing load-once convention; and it leaves
`internal/ofacruntime`'s compiled-catalog contract describing only actual compiled catalogs.
It is also the smaller of the two changes to the architecture-boundary text flagged above —
one new pure function, not a live-request dependency on offline-catalog-compilation types.

### AD2. The `candidatescoring` vocabulary extension

Two new name shapes, added to `bestNameMatch` (`candidatescoring/engine.go:332-372`):

- **`concatenation_normalized`** — subject and candidate names compared with
  `normalizeText` (`candidatescoring/normalize.go:9-25`) and then with spaces removed
  entirely, so `"ACMEIMPORTS"` and `"ACME IMPORTS"` compare equal. This is symmetric (it
  closes the row regardless of which side is concatenated) and needs no new normalization
  table — a straightforward addition alongside the existing `equalTokenSet`
  (`normalize.go:67-79`). Evidence rank: stronger than `prefix`/`containment` and arguably as
  strong as `token_set` (it is the identical name, modulo whitespace only) — recommend
  ranking it immediately below `exact`, i.e. inserting it into the existing rank ladder
  (`engine.go:350-356`: `exact`=4, `token_set`=3, `prefix`=2, `containment`=1) as a new
  rank between `exact` and `token_set`, renumbering the rest down by one.
- **`particle_stripped`** — token-set equality (`equalTokenSet`) after dropping a small,
  fixed, single-token particle list from both sides (starter set, matching Table 1's own
  named examples: `AL`, `BIN`, `VAN`, `DER`, `DE`, `DA`, `DEL`, `DOS`, `DAS`, `LA`, `LE`,
  `VON`, `IBN`). Applied at the token level so a two-word particle like "VAN DER" is handled
  as two independently-droppable tokens — `"KLAAS VAN DER BERG"` token-set-drops to
  `{KLAAS, BERG}`, matching `"KLAAS BERG"`'s token set exactly. Evidence rank: weaker than an
  unmodified `token_set` match (it required removing tokens to agree), stronger than a raw
  `prefix`/`containment` accident — recommend ranking it between `token_set` and `prefix`.

  **Placement of the particle table:** `candidatescoring` should own an independent copy of
  this list (in `candidatescoring/normalize.go`, mirroring the pattern of
  `matcherbaseline/corporate_suffixes.go`), not import `internal/matcherbaseline`'s (once D3
  adds one there). `candidatescoring`'s own doc comment
  (`internal/candidatescoring/doc.go:1-13`) and `docs/ARCHITECTURE.md:142-144` both frame it
  as a small, independently-consumed leaf package (imported by `screeningapi`,
  `scoringactivation`, and `projectionpackage` — none of which otherwise touch
  `matcherbaseline`); AD1 gives `screeningapi` a narrow call into `matcherbaseline` for
  rescoring, but that is not a reason for `candidatescoring` itself to gain a
  `matcherbaseline` dependency merely to detect a shape. This does mean two
  independently-maintained particle lists can drift apart over time — an accepted, named
  risk, in the same spirit as §9's R1-R4, not resolved here.

**New reason codes:** `name_concatenation_normalized` and `name_particle_stripped`, following
the existing convention (`name_exact`, `name_token_set_exact`, `name_prefix`,
`name_containment`) and wired into the `switch nameShape` in `scoreCandidate`
(`engine.go:154-163`). **Both new codes must also be added to
`isNameRetrievalMatch`'s companion check, `hasNameMatchReasonCode`**
(`internal/screeningapi/service.go:390-397`) — without that second edit, a correctly-matched
concatenation or particle candidate would still trip #116's
`BlockerNameMatchUncorroboratedByProjection` after correctly scoring, silently defeating the
row instead of closing it. This is a two-sided wire and both sides land in the same PR.

**Policy weight change — a `policy_sha256`-changing contract change.** `Policy.Weights`
(`candidatescoring/types.go:34-47`) gains two new integer fields,
`name_concatenation_normalized` and `name_particle_stripped`, alongside the existing four
name weights. Every policy document that sets weights —
`configs/scoring/candidate-scoring-r1.json`, `configs/scoring/candidate-scoring-r1-ascii-v1.json`,
and any activation-bound copy under `test/fixtures/scoring-activation/**` — needs explicit
values for both new fields; a policy that omits them decodes the fields to `0`
(`encoding/json`'s ordinary missing-field behavior), silently scoring the new shapes as
worthless rather than erroring — exactly the "silent absence" failure class CLAUDE.md rule 5
names as this repository's dominant bug pattern. `validatePolicy`
(`candidatescoring/policy.go:54-102`) already enforces that supporting weights are
non-negative but not that they are *present*; this addendum's implementation should close
that gap for any policy that declares these two shapes reachable. Because `Policy`'s SHA256
is computed over the full canonical JSON (`policy.go:46-51`) and re-verified at
`NewEngine` (`engine.go:27-34`), adding these fields with any nonzero value changes
`policy_sha256` for every policy document that sets them, which means every activation
pinning one — e.g.
`test/fixtures/scoring-activation/state-ofac-sdn-direct/activations/activation-dom-3-ofac-sdn-direct.json`,
whose `policy.policy_sha256` field is exactly this checksum
(`internal/scoringactivation/manager.go:86-92` writes it, `:234-239` re-verifies it) — must
be re-activated with the new value. This is §6.3(b)'s "a new weight is a new `policy_sha256`"
cost, now named concretely rather than left general.

**The point values themselves are explicitly not decided here.** Consistent with §8.3's
treatment of the phonetic-threshold question ("a measurement decision, not an engineering
one") and D6 ("no stage merges without a stated precision result"), the actual basis-point
weight for `name_concatenation_normalized` and `name_particle_stripped` is a calibration
decision gated on the same precision instrument D6 already requires for Stage 1 as a whole.
This addendum specifies the shape, the reason codes, and the schema change; it does not
invent numbers. The implementation PR carries the calibration alongside its stated precision
result, not ahead of it.

### AD3. The #117 fixture needs a scoring projection before it can serve as Stage 1's acceptance vehicle — small enough to be part of Stage 1's own scope

`dom1ParticleService`'s own comment
(`internal/screeningapi/dom1_unsupported_regression_test.go:538-546`) states record
`ofac:sdn:4004` was "deliberately never added to test/fixtures/scoring-activation's
projection index," so today the particle fixture only proves retrieval — the control case
observes `BlockerCandidateProjectionUnavailable`, not a score. AD2's new shapes cannot flip
`TestDOM1UnsupportedMatchingVariantParticleAndCompoundProducesNoMatchToday`'s
`name_particles_and_compounds` case to a real match until this record is scoreable, i.e.
present in a projection package bound to an activation, the same way `ofac:sdn:1001/2002/3003`
already are for the shared fixture (`test/fixtures/scoring-activation/state-ofac-sdn-direct/`).

This is small, not a separate undertaking: it is one record, the tooling already exists
(`cmd/projection-package`, `cmd/scoring-activation`; `projectionpackage.Compile`,
`LoadPackage`, and `ValidateCatalogPackageFile` at `internal/projectionpackage/package.go:69,198,311`),
and `test/fixtures/scoring-activation/state-ofac-sdn-direct/` is a direct template to mirror.
`dom1ParticleService` (`dom1_unsupported_regression_test.go:379-500`) already builds an
equivalent from-scratch `catalogregistry`/`alertlistmapping` state in a `t.TempDir()` for this
exact fixture; extending it with an equivalent from-scratch `projectionpackage`/
`scoringactivation` state is the same shape of work, not a new category of it.

**Decision: bind it as part of Stage 1's implementation PR**, not a separate follow-up. It is
a prerequisite for Stage 1's own acceptance criterion (D5) to mean anything for the
particles/compounds row — the same posture this ADR already took toward issue #115 in
§6.3(c) (named and tracked as a blocking prerequisite, not deferred as unrelated cleanup).

### Addendum summary

AD1 (export a narrow `matcherbaseline.ScorePair`), AD2 (two new `candidatescoring` shapes,
reason codes, and a named-but-uncalibrated policy schema change), and AD3 (bind #117's
fixture to a projection inside Stage 1's own PR) unblock Stage 1's implementation without
revising any of D1-D6. `docs/ARCHITECTURE.md`'s two-separate-paths framing needs a
corresponding edit in the same PR (addendum context, above) — that edit is a consequence of
D3's existing decision, not a new one made here.

## Addendum 2: concatenation-splitting's generation rule (2026-08-14)

- **Status:** Proposed
- **Trigger:** the first addendum's own implementation PR (#119, `fb6b0f2`) landed token
  reordering and particles/compounds — two of Stage 1's three rows — and explicitly declined
  to implement concatenation splitting, stating in its commit message and in a code comment
  that "no generation algorithm for turning a single concatenated query token into split
  lookup candidates is specified anywhere in ADR-0008 or its addendum"
  (`internal/screeningapi/service.go:465-473`; the same sentence is echoed in
  `README.md:21`'s Table 1 row). That claim was re-verified for this addendum: a repo-wide
  search for "concatenat" (`grep -rn oncatenat`) turns up AD2's *scoring* shape
  (`concatenation_normalized`, comparing two already-known names with whitespace stripped,
  `docs/adr/0008-fuzzy-matching-scoping.md:691-700` above) and nothing anywhere that
  specifies how to turn *one* opaque query token into a *set of candidate lookup strings*
  in the first place. The gap is real. This addendum is a pure addition — it resolves that
  one gap and revises nothing else in this document, including nothing in Addendum 1.
- Every claim below was verified against the working tree at `e824ee1` (current tip of
  `dom-1-stage1-addendum-2-split-rule`'s base, i.e. `main` after PR #120 merged), the same
  standard §Context and Addendum 1 set for their own claims.

### AD4. The split-candidate generation rule

**Decision: single-space insertion at every character boundary of the query string.** For
an N-character query token, generate the N-1 strings formed by inserting one space at each
position between two characters, and issue each as an additional runtime `name` lookup
alongside the mechanisms `nameQueryExpansions` already issues
(`internal/screeningapi/service.go:474-491`). For `"ACMEIMPORTS"` (11 characters) this
generates 10 candidates — `"A CMEIMPORTS"`, `"AC MEIMPORTS"`, ... `"ACMEIMPORT S"` — one of
which, `"ACME IMPORTS"`, is the catalog's stored two-token form
(`test/golden/ofac-advanced/ofac-sdn-catalog.json`, the same fixture §4.1 probed).

Two alternatives were considered and rejected, for two independent reasons:

1. **This platform is not building a configurable matching engine with tunable
   risk-appetite parameters.** Bounded multi-gap search (inserting more than one space, or
   searching for the best of several segmentations by some scored criterion) and
   dictionary-anchored splitting (segmenting only at boundaries confirmed by a lookup
   dictionary or corpus frequency table) both introduce a knob — a gap-count bound, a
   dictionary, a scoring threshold for accepting a segmentation — that this project has
   nowhere established a governance story for. Every other tunable surface in this
   repository's matching path is checksum-bound and change-controlled (threshold profiles,
   `internal/matcherbaseline/profile.go:35-94`; policy weights, AD2 above,
   `candidatescoring/policy.go:54-102`). A configurable segmentation policy would need the
   same treatment, and building that treatment is a different product decision than closing
   one Table 1 row — a decision this ADR's own stated scope does not extend to (its header
   line names the issue "DOM-1 (P0), scoping only," `docs/adr/0008-fuzzy-matching-scoping.md:5`).
   Single-space-insertion needs no such governance: it is a fixed function of the query
   string alone, with no parameter to bind, checksum, or drift.
2. **Multi-gap search grows combinatorially with query length; single-insertion does not.**
   Inserting up to *k* gaps into an N-character string is `C(N-1, k)` candidates — for a
   fixed small *k* this is still polynomial, but the useful case (splitting a name that
   should be three or more tokens) requires *k* to grow with the number of intended tokens,
   and nothing about a query string tells the generator how many gaps are needed in advance
   without trying all of them. Single-insertion fixes *k*=1 unconditionally, which is
   exactly `N-1` — linear in query length, matching §7's framing of Stage 1's expansion set
   as "a fixed, enumerable function of the query" whose "worst-case lookup count per request
   is known at review time rather than discovered in production"
   (`docs/adr/0008-fuzzy-matching-scoping.md:437-438` above). A combinatorial candidate count
   does not preserve that guarantee, and re-establishing an equivalent bound for a
   combinatorial generator is exactly the kind of governance work reason (1) says this
   project is not taking on right now.

### AD5. Accepted limitation: two-word concatenations only

This mechanism closes `concatenation_splitting` **only for two-word concatenations** — a
query token that should split into exactly two catalog tokens. A name that should split
into three or more tokens (e.g. a concatenation of three words) is not closed by single-gap
insertion: inserting one space into an N-character string can only ever produce a
two-token candidate, never a three-token one, so no candidate in the generated set can match
a three-token stored form.

This is stated here as an **accepted scope boundary, not a silently-dropped gap** — the same
posture §9 takes toward non-ASCII case folding (N2) and blocking-key selection (§8.2).
Consistent with reason (1) above: closing three-or-more-word compounds with this same
mechanism would require multi-gap insertion, which is the combinatorial-growth case AD4
rejected. If three-or-more-word concatenation splitting is needed later, that is a distinct
future decision — evaluated on its own, with its own governance story for whatever bound or
heuristic it needs — not an implicit TODO carried by this addendum or implemented as a
quiet extension of AD4's mechanism.

### Addendum 2 summary

AD4 (single-space-insertion at every character boundary, generating N-1 candidates for an
N-character query token) gives Stage 1's concatenation-splitting row an implementable
generation rule, chosen over bounded multi-gap search and dictionary-anchored splitting for
the two reasons stated. AD5 records, as an explicit accepted limitation rather than an
unstated gap, that the rule closes two-word concatenations only. Neither AD4 nor AD5 revises
D1-D6, Addendum 1, or any other decision in this document; both are additions scoped to the
one gap named in the Trigger above.

## Addendum 3: Stage 2 is not one stage (2026-08-14)

- **Status:** Proposed
- **Trigger:** a scoping pass over §7's Stage 2 paragraph, taken before any implementation PR
  opens against it, on the same standing rule that produced Addenda 1 and 2 — report rather
  than guess when a specification has no implementable answer. §7 Stage 2 (`:443-456`) states
  the mechanism in two sentences: "add the blocking-key verb (Strategy B), bump
  `WORKER_PROTOCOL_VERSION` `"1"` -> `"2"`, and feed its bounded output to the Stage 1
  rescorer." Each clause of that sentence turned out to rest on something that is either
  unspecified, already deferred elsewhere in this document, or no longer true after Stage 1
  actually shipped. This addendum records what was found and re-partitions the stage. It is a
  pure addition — no existing decision (D1-D6, AD1-AD5) is revised and nothing above this
  section is edited.
- Every claim below was verified against the working tree at `19c64c6` (tip of `main` after
  PR #123 merged), the same standard §Context and both prior addenda set for their own claims.

### Addendum 3 context: what Stage 2's paragraph already deferred

Before anything new: §4.2 and §7 do not under-specify Stage 2 by oversight. They specify it as
far as this document decided to, and then say so. §4.2 gives the verb's semantics — "given a
computed key (sorted-token signature, n-gram, or Soundex bucket), return the bounded set of
name entries that share it" (`:250-251`) — and §8.2 immediately withholds the only choice that
makes those semantics executable: which key, on the stated ground that "no data exists anywhere
in this repository to choose between them. This is the substantive design content of a
follow-on ADR, not something to settle in an implementation PR" (`:516-519`). §8.1 withholds
the measurement that decides whether the verb is viable at all (`:511-515`).

**This document already says Stage 2 needs its own ADR.** Everything below is an argument about
how much of Stage 2 that sentence covers, and the answer is: most of it, but not all of it, and
the part it does not cover is the part that has to ship first.

### AD6. Stage 2 is re-partitioned into Stage 2a (Go-only, scoring) and Stage 2b (Rust, recall)

**Decision: split it.** Stage 2's three target rows in `README.md:18`, `:22`, `:23` — typo /
character transposition, transliteration / cross-script, phonetic — do not share a blocker.

**Finding 1: the typo row is already retrieved on the live path today, and is blocked at
scoring.** `TestDOM1UnsupportedMatchingVariantTypoCharacterTranspositionIsRetrievedButBlocked`
(`internal/screeningapi/dom1_unsupported_regression_test.go:376-404`) asserts that the query
`ACME IMPROTS` returns `ofac:sdn:1001` today, retrieved by Stage 1's unconditional first-token
prefix probe (`internal/screeningapi/service.go:501`), and is then blocked by #116's
`BlockerNameMatchUncorroboratedByProjection` because `candidatescoring` has no name shape that
fires for it. §4.1 anticipated exactly this leakage (`:236`), and PR #119 handled it correctly.
Its consequence for staging was not drawn: the typo row splits in two, and only one half is a
recall problem.

- A typo **outside** the first token is retrieved today. It needs a *scoring* shape and
  nothing else. Go-only.
- A typo **inside** the first token is not retrieved, because the prefix probe blocks on the
  whole first token (`service.go:501`) — §4.1's own stated limit (`:246-247`).

**Finding 2: D3's rescoring seam does not exist. `ScorePair` has no non-test caller.** AD1
decided the mechanism and PR #118 exported the function
(`internal/matcherbaseline/score_pair.go:16`), but its only callers are its own test. Verified
directly: `internal/screeningapi`'s imports do not include `internal/matcherbaseline`, and
`docs/ARCHITECTURE.md:35-37` states that as current fact. Stage 1 closed all three of its rows
with exact boolean predicates added to `candidatescoring` instead — `equalSpacesStripped`
(`internal/candidatescoring/normalize.go:86`) and `equalParticleStrippedTokenSet` (`:109`) —
and never scored a similarity.

This corrects a claim in §7's "Why this order" (`:468-472`), which argued Stage 1 should go
first partly because "it builds the rescoring seam, the reason-code vocabulary, and the
precision-measurement harness that Stage 2 then reuses." Stage 1 built the reason-code
vocabulary. It did not build the rescoring seam, and §7.2's precision instrument is still
unbound. The ordering argument was still right; the inheritance it promised did not arrive, so
Stage 2 starts with more unbuilt work than §7 assumed, not less.

**Finding 3, which forces the order between the two halves: recall without a corroborating
scoring shape makes the live path worse, not better.** Scoring compares the *original* query
against the candidate's projected names — `scoringSubject` sets `Names` to `query.Value`
(`service.go:390`), not to whichever expansion retrieved the record. So a fuzzy candidate
retrieved by any Stage 2b mechanism still falls through all six shapes in `bestNameMatch`
(`internal/candidatescoring/engine.go:353-364`), still produces no name reason code, and still
trips `hasNameMatchReasonCode` (`service.go:422-430`) into blocking the whole item. §6.3(b)
predicted the zero-points version of this (`:363-366`); since #116 the failure is louder and
worse — the item is blocked, not merely mis-scored.

**Shipping Stage 2b before Stage 2a would therefore convert `no_candidates` responses into
`blocked` responses and close no row at all.** The split is not a convenience; the dependency
runs one way.

### AD7. Stage 2a — Go-only: the rescoring seam and a continuous-similarity scoring shape

Scope: build D3's seam by calling `matcherbaseline.ScorePair` from `internal/screeningapi` over
the retrieved candidate union, extend `candidatescoring` with a shape that can express "similar
but not equal", and close the typo row for typos outside the first token (AD6, finding 1). No
Rust change, no protocol bump, no recompile, no binding re-qualification.

**The hard part is not retrieval — it is that this scoring model has no continuous-similarity
concept anywhere.** All six shapes `bestNameMatch` recognises are exact boolean predicates
(`engine.go:353-364`), and `Weights` is a set of additive integer point values carrying the
comment "Exactly one name-shape weight is used"
(`internal/candidatescoring/types.go:32-41`). `ScorePair` returns a 0-10000 basis-point score
plus per-feature evidence (`score_pair.go:16`). Those two shapes do not compose.

Two designs, neither decided here:

1. **Bucket the continuous score into discrete shapes** (e.g. `name_fuzzy_strong` /
   `name_fuzzy_moderate`) at a threshold, and give each bucket a weight. This preserves the
   existing policy contract exactly, at the cost of introducing a *new checksum-governed
   tunable*: the bucket boundary. That is the same governance obligation AD4 declined to take
   on for segmentation (`:836-846`), except here it is unavoidable rather than optional, and
   the repository already has the pattern for it — threshold profiles are checksum-bound and
   validated on load (`internal/matcherbaseline/profile.go:35-94`), and
   `configs/matcher-profiles/ofac-name-baseline-r1.json:22` is exactly such a boundary today.
2. **Extend the policy contract to carry a scaled contribution**, so a 9070 bp match and a 7810
   bp match do not earn identical points. Strictly more faithful to the evidence, and a larger
   change to `Weights`, `validatePolicy` (`internal/candidatescoring/policy.go:54-102`), and
   every consumer of `Components`.

Either way the cost is AD2's, restated: a new weight is a new `policy_sha256`
(`policy.go:46-51`, re-verified at `engine.go:27-34`), so every policy document under
`configs/scoring/` and every activation pinning one must be re-issued. And either way both
sides of AD2's two-sided wire land together — a new shape in `bestNameMatch` **and** its reason
code in `hasNameMatchReasonCode` (`service.go:422-430`) — or the row is defeated by the #116
blocker after scoring correctly.

**No numbers are decided here**, on the same grounds AD2 gave for its own two shapes and §8.3
gave for the phonetic threshold: the weight and any bucket boundary are calibration decisions
gated on D6's precision instrument, which §7.2 records as still unbound
(`test/corpus/false-positive-archetypes/archetypes.v1.json:46`).

Stage 2a is addendum-sized and Stage-1-shaped. It is the only part of Stage 2 that is.

### AD8. Stage 2b requires its own ADR. This addendum does not specify the verb's wire format

**Decision: Stage 2b — index-side recall for transliteration / cross-script, phonetic, and
first-token typos — is a separate initiative and gets its own ADR (proposed ADR-0009). This
addendum deliberately does not invent its request/response wire format**, on rule 7 grounds
(do not invent a protocol and implement it in the same pass) and because §8.2 already assigned
that content to a follow-on ADR.

What was verified, and is the justification: **Go-side query expansion — the entire mechanism
Stage 1 is built from — is unavailable for all three of these rows, for three independent
reasons.** Stage 1 worked because its variant sets were small, deterministic, and *forward*
functions of the query: N-1 for AD4's split rule, one for the token-sorted permutation. Each
row below breaks that in a different way.

**Transliteration / cross-script — the inverse image is infinite, not merely large.** Closing
this Go-side means running `fold`'s transliteration map (`internal/matcherbaseline/normalize.go:15-19`)
*backwards*, from the Latin query to the Cyrillic byte string the index actually stores. Three
compounding obstacles, all verifiable by reading:

- `'Ь': ""` and `'Ъ': ""` (`normalize.go:19`) delete their input. Any number of soft or hard
  signs may sit at any position in the stored name and fold to the same Latin string —
  `ИГОРЬ` and `ИГОР` both fold to `IGOR`. The preimage of any Latin string is therefore
  **unbounded by construction**; there is no N to enumerate.
- The map is many-to-one elsewhere too: `E` has preimages Е, Ё and Э (`:15`, `:19`), `I` has
  И and Й (`:16`), and the Latin diacritic block above contributes more (È É Ê Ë, Ì Í Î Ï).
  Segmentation is ambiguous as well — `TS` is Ц or Т+С, `YA` is Я or Ы+А.
- Even a correct letter sequence is not enough, because `normalize_ascii` passes every byte at
  or above `0x80` through **unchanged, including its case**
  (`runtime/catalog-mmap/src/format.rs:774-781`). The generator must reproduce the stored
  casing exactly: 2^L candidates for an L-letter name, 2^14 = 16,384 for this repository's own
  fixture alias `Джордан Экзампл` (`test/golden/ofac-advanced/ofac-sdn-catalog.json:109`).
  §4.4 already recorded that case permutation is not a strategy (`:286-287`); this is the same
  finding reached from the transliteration side.

**Phonetic — the inverse image is unbounded by construction.** `soundex`
(`internal/matcherbaseline/similarity.go:220-244`) is a four-character many-to-one hash over an
unbounded input. Enumerating the strings that share a Soundex code is not a bounded operation
in any length regime.

**First-token typo — bounded, but two orders of magnitude past Stage 1.** See AD10.

**What is genuinely settled for Stage 2b, and belongs in ADR-0009's context rather than being
re-derived:** AD9's protocol-bump verification, AD10's cost ceilings, and the following four
questions, which are what makes it an ADR rather than an implementation PR:

1. §8.2's blocking-key selection, still undecided and still without data.
2. §8.1's Rust scan-cost spike at 40k-100k names, still not taken.
3. **Whether any matching algorithm gets a second implementation in Rust.** A Soundex-bucket
   key or a transliteration-fold key must be computed over *stored* names inside the worker,
   which means porting `soundex` or `fold`'s map into `runtime/catalog-mmap`. That creates two
   independent implementations of a matching-critical function that must agree forever — a new
   correctness hazard of exactly this repository's dominant class (CLAUDE.md rule 5), and one
   the base ADR never weighs. An n-gram or length-band key needs no such port. This trade-off
   is a first-class input to key selection, not a downstream detail of it.
4. **A candidate-pool limit distinct from `max_candidates`** — see AD9.

Note for ADR-0009's scope, not a decision here: §4.4's corollary (`:295-299`) holds. Once recall
exists by any mechanism, `fold` closes the practical effect of the non-ASCII case row at scoring
time without touching `normalize_ascii`. D4 stands; that row remains DOM-13's.

### AD9. The `WORKER_PROTOCOL_VERSION` bump mechanism, verified end to end

§4.2 asserts the bump is cheap. It is, and the assertion is confirmed — with two consequences
and two ceilings the base document does not name.

**Confirmed.** `WORKER_PROTOCOL_VERSION` is a Rust constant (`runtime/catalog-mmap/src/worker.rs:5`)
emitted as field 1 of the hello line (`:13-25`). The Go client pins its own copy
(`internal/runtimemmapclient/types.go:6`), parses the field (`protocol.go:36`), and enforces
strict equality — killing the worker process on mismatch (`worker.go:63-67`);
`internal/screeningapi` checks it again at bind time (`runtime.go:126-128`). There is **no
negotiation and no range**: it is a fail-closed lockstep, so worker binary and Go client must
ship together. That is the correct shape for this repository and worth keeping.

**Confirmed independent of the package.** `PACKAGE_SCHEMA_VERSION` is a separate constant
(`format.rs:9`) carried in package metadata and validated there (`:421`), and `package_sha256`
is a digest of the package **file** (`:447`) — which is what `RuntimeBinding` pins
(`runtime.go:137`). A protocol bump changes neither, so no catalog recompiles, no binding
re-qualifies, and no scoring activation re-issues (§6.3(a)'s pins are untouched). **Rule 6 does
not fire**, exactly as §4.2 claims. This is materially different from baking keys into the
package, which changes `package_sha256` by definition and is why Strategy C is a release event.

**Consequence 1, not previously named: the bump alone changes every screening ID.**
`WorkerProtocol` is written into every response's `RuntimeLineage` (`service.go:101`,
`internal/screeningapi/types.go:140`) and `screeningID` digests the whole response
(`internal/screeningapi/id.go:18-25`). §6.4 establishes that a stage which changes candidates
changes screening IDs; a protocol bump changes them even for a request whose candidate list is
byte-identical. Any cross-boundary screening-ID comparison is invalid from the bump forward,
including for rows Stage 2 does not touch.

**Consequence 2, mechanical:** several fixtures hard-code the version and move with it —
`internal/screeningapi/service_test.go:46`, `:90`, `auth_test.go:82`,
`scoring_integration_test.go:33`.

**Ceiling 1: a blocking verb cannot return an unbounded candidate set.** `limit` is validated
to 1..10,000 on both sides of the wire (`worker.rs:117-125`, `protocol.go:51`), and the
response is a single framed batch read synchronously (`worker.go:123-155`). There is no
streaming or paging frame in this protocol. Whatever ADR-0009 designs must bound its output
inside 10,000 entries per call, or add paging as part of the same bump.

**Ceiling 2: the candidate pool has no limit of its own.** Every lookup today takes its `Limit`
from `effectiveLimit(request.Query.Limit, service.MaxCandidates)` (`service.go:92`), which
defaults to 20, and Stage 1's expansions inherit it verbatim (`:120-123`). A blocking verb
exists precisely to return *many* candidates so the rescorer can rank them down to few, so
reusing the response-facing limit as the retrieval-facing limit would silently truncate the
blocking set to the response size. Stage 2b needs a separate, explicitly configured pool
bound. This is a new field on a public config surface, not an internal constant.

**Ceiling 3, worth stating because it sets the unit of cost:** each `Lookup` is one synchronous
request/response round-trip taken under a per-worker mutex (`worker.go:110-156`), served from a
pool of at most 64 workers (`internal/runtimemmapclient/pool.go:20-21`). Lookups do not
pipeline. One extra query variant is one extra round-trip, always.

### AD10. Cost model: Stage 2b needs its own bounding strategy, and Stage 1's bound is unstated rather than small

§7 describes Stage 1's expansion set as "a fixed, enumerable function of the query" whose
"worst-case lookup count per request is known at review time rather than discovered in
production" (`:436-438`). That is true in form. The value of the bound was never stated, and it
is not small.

**Stage 1, as shipped.** `query.value` is validated only as 1..4096 bytes, with no bound on
token count or token length (`service.go:323-325`). AD4's split probe fires on any single-token
query and emits N-1 expansions (`:503-509`), issued one at a time in a serial loop
(`:119-129`), each a full round-trip (AD9, ceiling 3). A 4,096-byte single-token name query
therefore issues **4,095 additional round-trips**. `ScreenBatch` runs items serially
(`:286-301`) and `max_batch_items` may be as high as 10,000
(`internal/screeningapi/config.go:58`), inside a 5,000 ms `request_timeout_ms`
(`test/fixtures/screening-api/config.json:20`). Separately, each expansion's results are
appended to the response without re-truncation (`:132-159`, counted at `:262`), so a name query
can return up to `limit * (N+1)` candidates — `max_candidates` no longer bounds a name
response. Both are shipped defects rather than Stage 2 questions, and are filed as issues #124
and #125 rather than fixed here; they are recorded in this addendum because they remove the
option of reasoning "Stage 1's cost model held, so reuse it."

**Stage 2b, if it were attempted Go-side.** The index alphabet is what `normalize_name`
produces: 36 ASCII alphanumerics plus the space, everything else stripped or passed through
(`format.rs:757-758`, `:782-794`). Edit-distance-1 over that alphabet on an N-character query
is `36N` substitutions + `N` deletions + `37(N+1)` insertions = **74N + 37** lookups — about
1,500 for a twenty-character name, against Stage 1's N-1 of 19. Edit-distance-2 is that
squared, order 10^6. Neither fits: at any plausible per-round-trip cost, 1,500 serialized
round-trips per item multiplied across a 1,000-item batch is far outside a 5-second timeout,
and that is before the cross-script and phonetic rows, whose variant spaces AD8 shows are not
finite at all.

**Statement, plainly: Stage 2b does not fit inside the existing 5-second timeout and 10,000-item
batch constraints under any Go-side generation strategy, and it needs its own bounding strategy
rather than an inherited one.** That strategy is ADR-0009's to design, and it has at least three
parameters to bind — the blocking-key selectivity, the candidate-pool limit (AD9, ceiling 2),
and the per-request round-trip budget. §8.1's unmeasured Rust scan cost decides whether such a
strategy exists at Stage 2b's scale at all; if it does not, §7's Stage 3 becomes mandatory, as
§7 already states (`:454-456`).

**Stage 2a carries no comparable cost.** It adds no lookups. `ScorePair` runs over the
already-retrieved union, and §3.1's measured ~6 µs per candidate applies to a union of tens of
candidates, not to a 40k-name scan.

### AD11. Accepted limitation: the transposition-only shortcut, considered and rejected

There is a cheap Go-side variant rule that would appear to close half of Stage 2's headline
row, and it is recorded here so it is evaluated rather than rediscovered.

The row is named "Typo / **character transposition**" (`README.md:18`) and its regression query
is a pure adjacent transposition: `ACME IMPROTS` is `ACME IMPORTS` with `O` and `R` swapped
(`dom1_unsupported_regression_test.go:379`). Generating the N-1 adjacent-transposition variants
of a query is exactly AD4's shape and exactly AD4's cost — a fixed, enumerable, linear function
of the query with no parameter to bind — and one of those variants is the stored alias.

**Decision: rejected, and not merely deferred.** Two reasons, the second decisive:

1. It closes the *case* without closing the *row*. Transposition is one of several typo classes;
   substitution, insertion and deletion are untouched. Flipping the regression case on a
   mechanism that handles none of the others is §7.1's "right result for the wrong reason" trap,
   which this ADR has already had to correct once for the particle row.
2. **It does not even flip the case.** Per AD6's finding 3, scoring compares the original query
   against the projected name (`service.go:390`). Retrieving `ofac:sdn:1001` via the variant
   `ACME IMPORTS` still leaves `bestNameMatch` comparing `ACME IMPROTS` against `ACME IMPORTS`,
   which is not equal, not equal spaces-stripped, not an equal token set, not particle-stripped
   equal, not a prefix and not a containment (`engine.go:353-364`). The response would remain
   blocked. The shortcut buys N-1 additional round-trips and no behavior change whatsoever.

This is stated as an accepted scope boundary in AD5's style, not a silently dropped option: the
typo row does not get a cheap partial close, and the reason is that Stage 2a's scoring shape is
load-bearing for it, exactly as AD6's finding 3 establishes for Stage 2b generally.

### Addendum 3 summary

AD6 re-partitions Stage 2 into **Stage 2a** (Go-only: the rescoring seam D3 decided and Stage 1
did not build, plus a scoring shape for similar-but-not-equal names) and **Stage 2b** (index-side
recall for cross-script, phonetic, and first-token typos), and establishes that the dependency
runs one way — 2b before 2a would turn `no_candidates` into `blocked` and close no row. AD7
scopes 2a and names its real difficulty: this scoring model has no continuous-similarity concept,
so a policy-contract decision, not retrieval, is 2a's hard part. AD8 records that Go-side
expansion is unavailable for every one of 2b's rows — the inverse of `fold` is infinite, the
inverse of Soundex is unbounded, edit-distance-1 is 74N+37 — and assigns 2b its own ADR
(proposed ADR-0009) without inventing a wire format here. AD9 verifies the protocol-bump
mechanism end to end and adds two consequences and three ceilings the base document does not
name. AD10 states plainly that 2b needs its own bounding strategy and that Stage 1's bound was
unstated rather than small. AD11 records a cheap shortcut as considered and rejected.

The honest summary of the sizing question this addendum was written to answer: **"a new worker
protocol verb" undersells Stage 2 in the same way "largely integration" undersold DOM-1**, and
in the same direction. One half of it is genuinely Stage-1-shaped. The other half is a design
initiative whose two gating inputs — a blocking key and a latency measurement — this document
has been recording as absent since §8.1 and §8.2 were written.

Nothing here revises D1-D6, AD1-AD5, or any other decision above; all of it is addition, and
nothing in it changes behavior. `README.md` Table 1's three Stage 2 rows stand unmodified.
