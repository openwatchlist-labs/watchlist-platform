# Architecture

This document explains how a screening request actually flows through this
system, what the major components are, and how they relate. It's meant to
answer the question a new contributor currently has to answer by reading
Go source and tracing imports by hand - which is exactly how the facts
below were established, not assumed from package names.

Everything below was verified against actual import statements
(`grep -h "watchlist-platform/internal" internal/<pkg>/*.go`), not inferred
from naming conventions - naming conventions in this codebase have been
misleading before (see issue #12's `FixtureProvider` rename).

## The most important thing to understand first

**Two genuinely different retrieval/matching paths existed in this
codebase historically, serving different purposes - not one "finished"
path and one "not yet wired in." DOM-1 (ADR-0008, plus its addenda) is
actively closing that gap in staged, revertible steps; this section
describes the state after Stage 1 (query expansion closing all three of
its rows - token reordering, name particles/compounds, and concatenation
splitting), not the pre-DOM-1 baseline:**

1. **Production `cmd/screening-api`** retrieves candidates via
   `internal/runtimemmapclient`, a Go client for the Rust-compiled
   `catalog-mmap` runtime (see the Go/Rust boundary section below). Its
   `Query` type has exactly one matching-behavior flag - `Prefix bool` -
   and nothing else. This is still **exact-name, prefix, or
   exact-identifier lookup only** - DOM-1 does not add a new query verb.
   What changed in Stage 1: `screeningapi` now issues *more than one* such
   lookup per name query - a token-sorted reordering, a first-token prefix
   probe, and (addendum 2's AD4) a single-space-insertion concatenation-
   split probe for single-token queries - in addition to the caller's
   original query - unions the results, and deduplicates by record ID
   (ADR-0008 §7 plus addendum 2). `screeningapi` still does not import
   `matcherbaseline`, `matcherprovider`, or `matchercontext` - confirmed by
   checking its actual imports, not assumed. This remains the live,
   real-time path.
2. **`internal/matcherbaseline`** (with `internal/matchercontext` layered
   on top) is the fuzzy/token-alignment/phonetic matching engine - the one
   issues #8, #9, #10, and #11 improved. Historically it was scoped purely
   as a post-processing/analysis tool over matches the live system has
   already produced (`cmd/matcher-run`, `internal/adversarialtest`), with
   no integration into the live path expected. ADR-0008 D3 changes that
   expectation: `matcherbaseline` is planned to become DOM-1's rescorer
   for variant classes retrieval alone can't close (typo, phonetic,
   cross-script - Stage 2). As of Stage 1, `matcherbaseline` has gained a
   narrow exported call surface for this purpose,
   `ScorePair(query, candidate string, profile ThresholdProfile)`
   (ADR-0008 addendum AD1), but `screeningapi` does not call it yet -
   Stage 1's three closed rows (token reordering, name particles/compounds,
   concatenation splitting) are corroborated entirely by
   `internal/candidatescoring`'s own shape detection (`token_set`,
   `particle_stripped`, and `concatenation_normalized` - ADR-0008 addendum
   AD2 and its addendum 2 extension), which needs no fuzzy scoring.
   `ScorePair` is a shared prerequisite sitting unused until a later stage
   calls it.

Practically: live screening decisions are made on exact/prefix/identifier
matches retrieved from the Rust runtime (now via Stage 1's query
expansion, not a single lookup), then scored with additional evidence by
`internal/candidatescoring` (which scores a *bounded, already-retrieved*
candidate set - it does not search a catalog itself). The fuzzy-matching
robustness work (issues #8-#11) still targets a deliberately separate tool
for deeper, retrospective analysis - `matcherbaseline` is not imported by
the live request path today - but treating the two paths as permanently,
by-design separate is no longer accurate: DOM-1 is a tracked, in-progress
effort to close that gap where retrieval and scoring can support it, one
revertible stage at a time.

## Request lifecycle, end to end (verified via actual import chains)

This is the **live** path - what happens when a real screening request
comes in:

```
Vendor alert (Actimize, Fircosoft, generic)
        │  internal/vendoradapter
        ▼
Alert / Case record created
        │  internal/alertcase (imported by alertcaseapi, reviewconsoleapi,
        │  assistanceapi, reviewconsole, vendoradapter itself)
        ▼
Screening request → candidate retrieval (exact/prefix/identifier ONLY)
        │  cmd/screening-api / internal/screeningapi
        │    → internal/runtimemmapclient → Rust catalog-mmap runtime
        ▼
Candidate scoring
        │  internal/candidatescoring (imported by screeningapi,
        │  scoringactivation, projectionpackage, cmd/candidate-score)
        │  Scores a bounded candidate set using retrieval evidence
        │  (DOB, identifiers, jurisdiction) - does not search itself.
        ▼
False-positive classification
        │  internal/falsepositive (imported by policyengine,
        │  revieworchestrator, cmd/false-positive-classify)
        │  Flags known FP patterns (e.g. substring false positives like
        │  "SCUBA contains CUBA").
        ▼
Policy evaluation
        │  internal/policyengine (imports falsepositive directly)
        │  Produces a disposition: clear / investigate / escalate,
        │  against a versioned, checksummed policy document.
        ▼
Review orchestration
        │  internal/revieworchestrator (imports falsepositive,
        │  policyengine, matcherprovider, analystnote, rag)
        │  Coordinates the human review workflow: four-eyes controls,
        │  escalation, and RAG-assisted analyst context.
        ▼
Review console (where an analyst actually works a case)
        │  internal/reviewconsole (imports alertcase, assistancerag)
        │  internal/reviewconsoleapi (HTTP surface)
```

### Separate: post-processing/analysis tooling over live-system matches

`cmd/matcher-run` → `internal/matcherbaseline` (+ `matchercontext`) →
`internal/matcherprovider` → `internal/ofacruntime` (`.owpcat`, pure Go,
no Rust) remains a separate tool for deeper, retrospective analysis of
matches the live system has already produced - robustness testing,
investigating edge cases, and the kind of adversarial stress-testing
`internal/adversarialtest` does (see issues #8-#11). It does not feed into
`candidatescoring`, `policyengine`, or any part of the live request
lifecycle above *today*, but - unlike when this section was first written
- there now **is** an expectation that a narrow slice of it will: ADR-0008
D3 commits `matcherbaseline` to becoming DOM-1's rescorer, and Stage 1
already exported the call surface for it (`ScorePair`, addendum AD1), even
though no Stage-1 row ends up calling it. Treat "does not feed into the
live path" as accurate for `cmd/matcher-run`'s own `SearchWithDiagnostics`
full-catalog-scan entry point specifically - ADR-0008 §3 explains why that
entry point in particular can never be pointed at the live retrieval path
- not as a statement that no part of this package's code will ever be
called live.

## Package responsibilities, by cluster

### Catalog & sanctions data (feeds the matcher/retrieval side)

- `internal/ofaccatalog` - the direct-list catalog contract: strict
  validation, deterministic checksums. Source format for the OFAC SDN
  synthetic fixture used throughout this repo's tests.
- `internal/ofacadvanced` - parser for OFAC's newer "Advanced XML" format.
- `internal/ofacsource` - source-acquisition manifest validation (exact
  dataset ID, parser version, deterministic manifest ID).
- `internal/ofacruntime` - compiles a validated catalog into the portable
  `.owpcat` binary package. **Pure Go, no Rust dependency** - this is the
  format `matcherbaseline` reads.
- `internal/catalogregistry`, `catalogrefresh`, `providerrefresh`,
  `activationpromotion`, `scoringactivation`, `updatemanager` - the
  catalog/model lifecycle machinery: versioning, refresh scheduling,
  promotion readiness, activation. Large cluster, least approachable to a
  newcomer - see `docs/TEST_DATA.md`'s catalog-lifecycle section before
  digging in here.

### Matching (two genuinely different engines - see above)

- `internal/matcherprovider` - the shared `Provider` interface and
  `ExactMatchFixtureProvider` (exact-match only, see issue #12).
- `internal/matcherbaseline` - the real fuzzy/phonetic engine, reads
  `.owpcat`.
- `internal/matchercontext` - adds jurisdiction/address/contextual-phrase
  evidence on top of `matcherbaseline`.
- `internal/canonical`, `internal/normalization`, `internal/matcherrequest`
  - shared types and string normalization used across the matching stack.
- `internal/runtimemmapclient` - Go client for the Rust `catalog-mmap`
  runtime; what production `screeningapi` actually calls for retrieval.
- `internal/projectionpackage` - compiles the intermediate JSON format
  that bridges Go-produced candidate data to the Rust `catalog-mmap`
  compiler. See `internal/projectionpackage/rust_compat_test.go` and
  `scripts/dev/verify-rust-mmap-compatibility.sh` (issue #13) for the
  cross-language compatibility story here.

### Scoring, false positives, policy

- `internal/candidatescoring` - scores a bounded, already-retrieved
  candidate set using additional evidence.
- `internal/falsepositive` - classifies common false-positive patterns.
- `internal/policyengine` - policy-driven disposition decisions.

### Case, review, and analyst assistance

- `internal/alertcase` - the central case data model.
- `internal/revieworchestrator` - coordinates the review workflow.
- `internal/reviewconsole` / `reviewconsoleapi` - where analysts work
  cases (currently the other zero-test `internal/` package alongside the
  now-covered `platformapi` - see issue #15).
- `internal/analystnote`, `internal/rag`, `internal/assistancerag`,
  `internal/assistanceapi` (surfaced via `cmd/case-assistance` and
  `cmd/case-assistance-api`) - RAG-assisted analyst context. Notably
  includes a deliberate prompt-injection test fixture
  (`test/fixtures/rag/documents/hostile-content.md`) - worth knowing about
  if extending RAG safety tests.
- `internal/vendoradapter` - ingests third-party vendor alerts (Actimize,
  Fircosoft, generic) into the case model.
- `internal/screeningledger` - append-only record of screening decisions.

### The Go/Rust boundary, precisely

Three different compiled/binary formats exist - easy to conflate, so
worth being explicit:

- **`.owpcat`** - pure-Go-compiled, read by `matcherbaseline`. Built via
  `cmd/ofac-runtime -command compile`. No Rust anywhere in this path.
- **`.owmmap`** - Rust-compiled, read by production `screeningapi` via
  `runtimemmapclient`. Built by the Rust crate at
  `runtime/catalog-mmap` (binary: `cmd/bin/catalog-mmap.rs`, subcommands
  `compile`, `lookup-name`, `lookup-identifier`, `inspect`).
- **`.owcin`** - a deterministic, hex-encoded "compiler input" fixture
  format, used as input to Rust-side test tooling.

`internal/projectionpackage` is the Go-side bridge that produces the JSON
projection `catalog-mmap compile` consumes. As of issue #13's
investigation: Go's projection compiler is verified deterministic and the
committed `.owmmap` test fixture is verified to match its own recorded
checksum (both confirmed with no Rust toolchain needed - see
`internal/projectionpackage/rust_compat_test.go`), but whether running the
*actual* Rust compiler today reproduces that checksum from fresh Go output
remains genuinely unverified pending a working Rust toolchain (see
`scripts/dev/verify-rust-mmap-compatibility.sh`).

## Where this document might already be out of date

This was written from a snapshot of the codebase and won't track future
changes automatically. If a described import relationship looks wrong,
trust `grep -h "watchlist-platform/internal" internal/<pkg>/*.go` over
this document, and update this file to match - the same principle
`docs/TEST_COVERAGE.md` and `docs/TEST_DATA.md` already state for
themselves.
