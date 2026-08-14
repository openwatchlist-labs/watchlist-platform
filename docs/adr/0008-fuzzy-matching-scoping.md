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
