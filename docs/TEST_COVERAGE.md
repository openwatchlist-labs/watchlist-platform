# Test coverage documentation

This document was missing from the repository. It covers **every internal
package with tests** (existing coverage, verified by actually running
`go test ./...`) and the **new adversarial/messy-data test bank** added
2026-07-30 (`internal/adversarialtest`).

Descriptions marked **(verified)** were confirmed by reading the actual
test code. Descriptions marked **(inferred)** are a reasonable read of the
package name and its role in the pipeline, but weren't individually
read line-by-line - most internal packages currently have no
package-level doc comment (`// Package x ...`) at all, which is itself
worth fixing as a follow-up; it would make this table easier to keep
honest over time.

## How to run

```
go build ./...
go vet ./...
go test ./...                        # everything, 54 packages as of this writing
go test ./internal/adversarialtest/... -v   # just the new adversarial bank, verbose
```

All of the above pass cleanly as of this writing (Go 1.23, no external
services, no Rust toolchain required for anything under `internal/` or
`cmd/` - the Rust `catalog-mmap` runtime used by `cmd/screening-api`'s
default production config is a separate, undocumented-status piece; see
the note at the bottom).

## Existing test coverage, by package

| Package | Tests | What it covers |
|---|---|---|
| `activationpromotion` | 4 | (inferred) Promoting a compiled catalog generation from staged to active. |
| `adapters/iso20022` | 5 | (inferred) ISO 20022 message-field adapter; missed on first pass since it's nested under `internal/adapters/`, not a top-level `internal/` package - a reminder that a scan script, not a manually-maintained list, should generate this table going forward. |
| `adversarialtest` | 1 (39 subtests) | **New.** See dedicated section below. |
| `alertcase` | 6 | (inferred) Alert/case lifecycle data model and transitions. |
| `alertcaseapi` | 2 | (inferred) HTTP surface for alert-case operations. |
| `alertlistmapping` | 6 | (inferred) Mapping raw vendor alert fields to canonical fields. |
| `analystnote` | 3 | (inferred) Analyst note/annotation storage on cases. |
| `assistanceapi` | 1 | (inferred) HTTP surface for case-assistance/RAG features. |
| `assistancerag` | 7 | (inferred) RAG-based case assistance: retrieval, citation, relevance. |
| `candidatescoring` | 3 | **(verified)** Converts matcher output into a final candidate score; checked exact score values, evidence-length limits, and that forbidden fields never leak into a response. |
| `canonical` | 1 | **(verified)** Shared enums/types (`CandidateType`, `MatchRoute`, etc.) used across the whole matching pipeline. |
| `catalogrefresh` | 4 | (inferred) Scheduling/triggering catalog re-ingestion. |
| `catalogregistry` | 5 | (inferred) Tracking which compiled catalog generation is registered/active. |
| `catalogruntime` | 3 | (inferred) Generation-stamp validation, used to bind a matcher run to a specific compiled package (`GenerationStamp`, `ActivePointer`). |
| `catalogsource` | 2 | (inferred) Generic source-acquisition abstraction (OFAC-specific version is `ofacsource`). |
| `falsepositive` | 10 | **(verified)** Classifies common false-positive patterns (e.g. common names, technical tokens); includes golden-pattern classification tests. |
| `iso20022coverage` | 6 | (inferred) Tracks which ISO 20022 payment message fields are mapped/covered by the matcher. |
| `matcherbaseline` | 6 | **(verified)** The real fuzzy/phonetic/token-alignment name matcher. Reads a compiled `ofacruntime` payload + threshold profiles. This is the engine the new adversarial tests exercise directly. |
| `matchercontext` | 2 | (inferred) Contextual matching layer (jurisdiction policy, address/phrase evidence) built on top of `matcherbaseline`. |
| `matcherprovider` | 9 | **(verified)** Shared `Provider` interface, `Runner`/`Execute`/`Replay` orchestration, and the simpler **exact-match-only** `FixtureProvider` used for JSON-fixture-based testing/demos. Important: this package's `FixtureProvider` is NOT the same matching engine as `matcherbaseline` - see the adversarial section below, this distinction is easy to miss. |
| `matcherrequest` | 7 | (inferred) Request/response contract types (`CandidateSearchRequest`, `RequestBatch`, replay envelopes). |
| `mmapcatalogcontract` | 2 | (inferred) Contract/schema for the Rust-side memory-mapped catalog format. |
| `normalization` | 1 | **(verified)** Deliberately minimal: whitespace collapsing and case-folding per field profile (name, IBAN, country code, etc.). No diacritic stripping, no Unicode-confusable folding, no phonetic logic - all of that lives one layer up, in `matcherbaseline`. |
| `ofacadvanced` | 8 | (inferred) Parser for OFAC's newer "Advanced XML" source format, as opposed to the legacy XML parser. |
| `ofaccatalog` | 3 | **(verified)** The direct-list catalog contract: strict validation (`ValidateCatalog`), deterministic checksum computation, and the provider adapter. This is what the adversarial catalog had to satisfy exactly. |
| `ofacruntime` | 2 | **(verified)** Compiles a validated `ofaccatalog.Catalog` into the portable `.owpcat` binary package format (`Compile`) and loads it back (`Load`) - pure Go, no Rust dependency. |
| `ofacsource` | 6 | **(verified)** Source-acquisition manifest validation: enforces exact dataset ID, parser version, XML namespace, and a content-derived deterministic `manifest_id`. |
| `platformapi` | **0 - no test files at all** | (inferred) Top-level API composition/routing. Verified: `internal/platformapi/` has no `*_test.go` file. Worth flagging as a real gap, not a documentation oversight. |
| `policyengine` | 6 | **(verified)** YAML/checksum-gated policy evaluation with deliberate negative tests (checksum-drift rejection). |
| `productionops` | 4 | (inferred) Production configuration/operational types (`ScreeningAPIConfig` lives here). |
| `projectionpackage` | 3 | (inferred) "Fully verified immutable projection package" - has the only package-doc comment found in the whole `internal/` tree. |
| `providerentity` | 8 | (inferred) The simpler provider-entity catalog format (used by `synthetic-catalog-v1.json` and the hybrid-overlay provider). |
| `providerrefresh` | 5 | (inferred) Provider-catalog refresh scheduling, parallel to `catalogrefresh`. |
| `rag` | 3 | (inferred) Lower-level RAG primitives underlying `assistancerag`. |
| `releaseartifact` | 1 | (inferred) Packaging a release artifact/tarball. |
| `releasebenchmark` | 3 | (inferred) Benchmark harness types, e.g. for the p95-latency/throughput qualification gates. |
| `releasequalification` | 3 | **(verified)** Evaluates a scenario suite against qualification gates and produces a pass/blocked report; genuinely computes results rather than just parsing a fixture, and includes a deliberate negative test (flip one scenario, confirm status flips to `blocked`) and a tamper-detection test. |
| `reviewauth` | 1 | (inferred) Authorization for the analyst review console. |
| `reviewconsole` | 1 | (inferred) Review console backend logic. |
| `reviewconsoleapi` | **0 - no test files at all** | (inferred) HTTP surface for the review console. Verified: `internal/reviewconsoleapi/` has no `*_test.go` file. |
| `revieworchestrator` | 4 | (inferred) Coordinates the four-eyes/escalation workflow mentioned in project docs. |
| `runtimecataloginput` | 2 | (inferred) Input-side contract for the compiled catalog runtime (possibly the `.owcin` fixture format seen under `test/fixtures/runtime-mmap`). |
| `runtimemmapclient` | 1 | (inferred) Go client for the Rust-compiled memory-mapped catalog runtime used by `cmd/screening-api`. |
| `scoringactivation` | 3 | (inferred) Activating a scoring-model version into production use. |
| `screening` | 8 | (inferred) Core screening-plan/request domain types shared across the screening API versions. |
| `screeningapi` | 5 | **(verified, current version)** The live HTTP screening API service; depends on a compiled Rust `catalog-mmap` runtime binary for its documented default config - see note below. |
| `screeningapiv8d` / `v8e` / `v8f` / `v8g` | 5 / 3 / 2 / 1 | (inferred) Earlier iterations of `screeningapi` retained in the tree. Worth a deliberate decision on whether to keep, archive, or delete these - four live prior versions of the same service is exactly the kind of accumulated surface area the "Clean Restart" was meant to reduce, and it's crept back in already. |
| `screeningledger` | 5 | (inferred) Append-only record of screening decisions, parallel in spirit to the audit-log pattern. |
| `screeningplan` | 2 | (inferred) The `PlanReference` type used in matcher requests to identify which screening plan produced a request. |
| `updatemanager` | 3 | (inferred) Coordinates rollout of new catalog/model/policy versions. |
| `vendoradapter` | 3 | **(verified, fixtures only)** Adapters for vendor alert formats (Actimize, generic) - I read the fixture files (`test/fixtures/vendor-adapters/*.json`) directly; didn't read the adapter test code itself. |
| `vendoradapterapi` | 1 | (inferred) HTTP surface for vendor-adapter ingestion. |

**Total: 205 test functions across 54 packages with tests (53 pre-existing + this new one), all passing, zero skipped**, as of this writing - independently verified by actually running the suite (`go test ./... 2>&1 | grep -c "^ok"` and `grep -rh "^func Test" --include="*_test.go" internal/ cmd/ | wc -l`), not read off documentation. Note: this table only lists `internal/` packages; there is also exactly one `cmd/` package with its own tests, `cmd/live-catalog-sync` (4 tests), not reproduced here since every other `cmd/` package has none.

A caution about this table itself: it was hand-assembled by scanning `internal` at depth 1, which **initially missed** `internal/adapters/iso20022` (nested one level deeper) entirely. That's now been corrected, but it's worth treating as a live warning: a hand-maintained inventory like this one will silently drift out of date. A short script that runs `go list ./...` plus a per-package test count, checked into `docs/` or `scripts/`, would make this table self-verifying instead of something a person (or an assistant) has to remember to update by hand.

## New: adversarial/messy-data test bank (`internal/adversarialtest`)

### Why this exists

The table above shows real, passing, meaningfully-designed tests - but
almost all of them test the matcher against **clean data or data already
registered as a known alias**. That's necessary but insufficient: it
doesn't tell you whether the matcher *generalizes* to a name variant
nobody thought to pre-register, which is what a live sanctions list
screening real, messy, sometimes adversarial data actually requires.

### What was added

- `test/fixtures/adversarial/adversarial-catalog.direct-list.json` - 12
  synthetic entities (1 reused from the existing `ofac-sdn-fixture`, 11
  new) in the real `ofaccatalog` direct-list schema, satisfying its
  strict header/checksum/manifest validation.
- `test/fixtures/adversarial/adversarial-scenarios-v1.json` and
  `-v2.json` - 39 scenarios across four categories (`transliteration`,
  `incomplete_record`, `obfuscation`, `multi_vector`), each tagged
  `baseline` (tests alias lookup - the easy case) or `stress` (tests
  generalization to an unregistered variant - the real test), each with a
  `known_status` field captured from an actual run and a `rationale`
  explaining what real-world pattern it simulates.
- `test/golden/adversarial/adversarial.runtime.owpcat` - the compiled
  runtime package, built with the module's own existing `cmd/ofac-runtime
  -command compile` (pure Go, no Rust dependency, fully reproducible -
  recompiling from the source catalog JSON produces an identical
  checksum).
- `cmd/adversarial-checksum-fix` - a small dev tool that computes the
  correct `catalog_checksum` and `manifest_id` for a hand-authored
  catalog (both are content-derived and the loader rejects anything that
  doesn't match exactly).
- `internal/adversarialtest/adversarial_test.go` - the actual `go test`
  wiring. Runs every scenario as a subtest against the real
  `matcherbaseline` engine (loaded from the compiled runtime package, not
  the simpler exact-match-only `matcherprovider.FixtureProvider` used
  elsewhere in the project - **this distinction matters and is easy to
  get wrong**; see the callout below).

### Regression-lock design (why this is safe to merge as-is)

Every scenario's `known_status` reflects what actually happened in a real
run. The test asserts *consistency* with that known state, not that
everything passes:

- `known_status: "pass"` that now fails -> **hard test failure** (a real
  regression in matching behavior - this is the thing that would actually
  break CI).
- `known_status: "fail"` that now passes -> logged as an improvement, not
  a failure. Confirm it's intentional, then flip `known_status` to
  `"pass"` in the fixture so it becomes a locked-in regression guard going
  forward.
- `"ambiguous_by_design"` scenarios -> logged; whether the system
  correctly routes to human review is a policy-layer decision this test
  can observe partially (candidate count) but not fully judge.
- `"unscored"` -> logged only; `truth: "clear"` scenarios aren't wired
  into pass/fail logic yet (see Known limitations below).

This means the suite passes cleanly today (`go test
./internal/adversarialtest/...` is green) while making every current gap
visible in verbose test output, and it will start failing the moment a
real regression happens on something that currently works.

### Actual results as of 2026-07-30

| | Result |
|---|---|
| Baseline (pre-registered alias) | 2 / 2 passed |
| Stress - transliteration | 6 / 11 |
| Stress - incomplete record | 2 / 5 |
| Stress - obfuscation | 5 / 14 |
| Stress - multi-vector (2 techniques stacked) | 0 / 3 |
| **Stress overall** | **13 / 33 (39%)** |
| Ambiguous-by-design, handled correctly | 3 / 3 |

**Highest-priority gaps** (cheap to fix, affect ordinary messy data, not
just deliberate evasion): zero-width-space characters, punctuation noise,
and token reordering all currently defeat the matcher entirely.

**Also failing, more specialized:** RTL Unicode override injection,
corporate-suffix swaps (GmbH -> Ltd), honorific/padding dilution,
nickname/diminutive substitution (no dedicated table exists), and every
multi-vector combination tested.

**Worth independently re-verifying, not just trusting:** one homoglyph
case (Cyrillic О for Latin O) and one mixed-script case both passed at a
perfect score, which doesn't obviously follow from reading
`internal/normalization`'s code (whitespace/case folding only, no
Unicode-confusable handling visible there). Either there's a real
capability living somewhere else in the pipeline, or these two cases
happened to pass for an unrelated reason. Test with a few more distinct
homoglyph pairs before concluding either way.

### Important callout: two different "providers", two different rigor levels

This project has **two** provider implementations that both read JSON
catalogs and both implement the same `matcherprovider.Provider`
interface, but they are not equivalent:

- `matcherprovider.FixtureProvider` (`--provider fixture` in
  `cmd/matcher-run`, used by `synthetic-catalog-v1.json` and the
  `clawbot-gateway` demo integration) does **exact match only** -
  case/whitespace-normalized string equality, nothing else.
- `matcherbaseline.Provider` (`--provider ofac-baseline`) is the real
  fuzzy/token-alignment/phonetic engine, but it only loads from a
  *compiled* `.owpcat` runtime package, not directly from JSON.

A pass or fail against `FixtureProvider` says nothing about
`matcherbaseline`'s actual matching capability. This is an easy mistake
to make (a demo "screening" call and a real matching-engine test can look
superficially identical from the outside), so it's worth being explicit
about which one is in play whenever "the matcher passed/failed X" comes
up in a conversation with a design partner or in future documentation.

### How to extend this

1. Add new synthetic entities to a new
   `adversarial-catalog-vN.direct-list.json` (must satisfy the strict
   OFAC direct-list header conventions - copy the pattern in the existing
   file exactly: `catalog_id: "ofac-sdn-direct"`, `provider_record_id:
   "ofac:sdn:<uid>"`, `source_assertion.source_id: "ofac-sls"`,
   `list_id: "SDN"`, ascending numeric `source_uid` ordering).
2. Run `go run ./cmd/adversarial-checksum-fix <file>` to stamp the
   correct `manifest_id` and `catalog_checksum`.
3. Recompile: `go run ./cmd/ofac-runtime -command compile -catalog <file>
   -package test/golden/adversarial/adversarial.runtime.owpcat`.
4. Add scenarios referencing the new entities to a new
   `adversarial-scenarios-vN.json`, add the file to `scenarioFiles` in
   `internal/adversarialtest/adversarial_test.go`, add new entries to
   `recordIDMap`.
5. Run `go test ./internal/adversarialtest/... -v`, read the actual
   result for each new scenario, and set `known_status` accordingly
   before merging - don't guess at what "should" happen; capture what
   actually did.

## Known limitations of this documentation and test bank

- `truth: "clear"` scenarios (things that should NOT match) aren't wired
  into automated pass/fail yet - currently logged as `unscored`. Worth a
  follow-up: assert either zero candidates or a score below threshold.
- The 12-entity adversarial catalog is small and entirely synthetic. It's
  sufficient to find real gaps (and it did), but it is not a substitute
  for testing against a larger, more diverse, or adversarially-generated
  dataset before making any claim about production readiness.
- This document's "inferred" package descriptions are exactly that -
  inferred from names and directory context, not individually verified by
  reading each package's test code line by line. Treat them as a starting
  map, not a certified inventory. Adding real `// Package x ...` doc
  comments across `internal/` would make future versions of this table
  self-maintaining rather than hand-authored.
- The `screeningapiv8d`-`v8g` packages sitting alongside current
  `screeningapi` are a real, existing question of what to keep versus
  retire; this document surfaces it but doesn't resolve it.
