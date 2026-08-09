# cmd/ package testing pattern (issue #15)

46 of 49 `cmd/` packages had zero test coverage before this. This document
records the pattern used to start closing that gap, so it can be copied to
the remaining packages rather than reinvented each time.

## Why black-box subprocess tests, not in-process unit tests

Every `cmd/` package's `main()` calls `os.Exit` directly (usually via a
local `fatal()`/`check()` helper). Testing that logic in-process would kill
the test runner itself the first time a failure path is exercised. The
standard, safe pattern instead: build the actual binary once, then invoke
it as a real subprocess with different arguments, checking exit code and
stdout/stderr. This has a real advantage over in-process testing, not just
a workaround: it tests the actual artifact that gets deployed, flag
parsing included, rather than internal functions that happen to back it.

## The pattern (see cmd/platform-api/main_test.go, cmd/policy-evaluate/main_test.go)

```go
package main_test

var binaryPath string

func TestMain(m *testing.M) {
    dir, _ := os.MkdirTemp("", "<name>-test-*")
    defer os.RemoveAll(dir)
    binaryPath = filepath.Join(dir, "<name>")
    build := exec.Command("go", "build", "-o", binaryPath, ".")
    if out, err := build.CombinedOutput(); err != nil {
        panic("failed to build: " + err.Error() + "\n" + string(out))
    }
    os.Exit(m.Run())
}

func run(args ...string) (stdout, stderr string, exitCode int) {
    cmd := exec.Command(binaryPath, args...)
    // set cmd.Dir if the binary resolves relative paths (e.g. a default
    // config flag value) from the working directory
    ...
}
```

Then individual `Test*` functions call `run(...)` and assert on exit code
and output content.

## What to test in each package, roughly in priority order

1. **No arguments / missing required flags** - should fail cleanly with a
   usage message and nonzero exit, not panic.
2. **A required input file that doesn't exist** - clean error, not a
   panic or hang. This is the single highest-value case: it's the
   scenario most likely to actually happen in production (a bad path in
   a config or a deploy script) and the one most likely to have never
   been exercised at all before now.
3. **Malformed input** (invalid JSON/YAML) - clean error, not a panic.
4. **Strict-decoding rejection**, if the package uses
   `DisallowUnknownFields` (many do, following this project's own
   convention) - verify it actually fires, don't just assume the source
   code calling it means it works. Verify the SPECIFIC error message
   mentions the unknown field, not just that *some* error occurred - a
   payload can fail for multiple independent reasons, and a vague
   assertion can pass for the wrong reason (this happened while writing
   the policy-evaluate tests - see git history/commit message for
   specifics).
5. **A real happy path**, IF a suitable existing fixture is already
   committed somewhere in the repo. Check `test/fixtures/` and
   `test/golden/` for something already shaped correctly before
   constructing new fixture data by hand - `cmd/policy-evaluate`'s happy
   path test reuses `test/golden/false-positive/pattern-classifications.json`,
   which already existed as another package's own golden output and
   happens to be exactly the input shape `policy-evaluate` expects.
   If nothing suitable exists and the package's own config/input chain is
   deep (several linked config files, as with `cmd/platform-api`), it's
   reasonable to skip the happy-path case for now rather than guess at a
   fixture's schema from scratch - see the explicit scope note in
   `cmd/platform-api/main_test.go` for why that one stops at
   failure-mode coverage only.

## Progress so far

- `cmd/platform-api` - 4 tests (failure modes only; happy path skipped,
  see file for why).
- `cmd/policy-evaluate` - 5 tests, including a real happy-path case.
- `cmd/screening-api` - 5 tests, failure modes only. Happy path is a hard
  blocker, not a choice: `load()` unconditionally starts the real Rust
  catalog-mmap runtime as a subprocess (`runtimemmapclient.StartPool`) -
  the same Rust-toolchain dependency documented as unverified in issue
  #13. `internal/screeningapi`'s own tests avoid this via a Go-level
  `fakeRuntime` interface mock, which isn't reachable from the compiled
  CLI. Add a real happy-path test here once #13's Rust question is
  resolved.
- `cmd/matcher-run` - 6 tests, including TWO genuine happy-path cases
  (`ofac-baseline` real fuzzy matching, and `fixture` exact-match-only -
  see issue #12 for why those two are meaningfully different engines).
  No Rust dependency at all for this package, unlike screening-api.
- `cmd/ofac-runtime` - 5 tests, including a real compile-then-inspect
  happy path. No Rust dependency (pure-Go `internal/ofacruntime`).
  `readiness`/`activate`/`rollback` subcommands (`internal/catalogruntime`)
  not covered yet.
- `cmd/projection-package` - 6 tests, including a real compile-then-verify
  happy path reusing the same fixture pair independently verified during
  the #13 investigation, and a test confirming `inspect` is genuinely a
  byte-identical alias of `verify` (not just assumed from reading the
  source). No Rust dependency for this step - it only produces the
  intermediate JSON, not the Rust-compiled `.owmmap` binary.
- `cmd/false-positive-classify` - 5 tests, including a real happy path
  against the existing `pattern-observations.json` fixture. Every failure
  mode here exits code 1, not 2 - no separate usage-specific exit code,
  different from several other `cmd/` packages already covered. Verified
  directly rather than assumed consistent.
- `cmd/candidate-score` - 8 tests, covering all three subcommands
  (`score`, `batch`, `check-policy`) with real fixtures, including the
  `dob-contradiction` scenario specifically since it's the kind of case
  most likely to reveal a scoring regression.
- `cmd/alert-case` - 7 tests, including a full stateful-workflow happy
  path (create-alert, replay against the same input, alert, status,
  verify-alert, verify-audit, all against one shared `--state-dir`) -
  this project's first genuinely stateful `cmd/` package tested, not just
  a stateless transform. `migrate` (needs a live PostgreSQL DSN and
  `psql`) not covered - a real integration test waiting to be written,
  out of scope for this batch's black-box unit-level approach.
- `cmd/vendor-adapter` - 10 tests, including the same
  ingest-then-replay-then-verify stateful pattern as `cmd/alert-case`,
  plus stateless `profiles`/`check-profile`/`convert`/`batch` happy
  paths. `submit` (makes a real HTTP call to a live `--alert-case-url`)
  not covered, for the same reason `migrate` isn't above.
- `cmd/review-console-api` - 5 tests, INCLUDING a real happy path. This
  package's config chain (`RuntimeConfig`-equivalent ->
  `reviewauth.Registry` -> `assistancerag.CorpusSnapshot` -> signing key
  -> security audit dir) looked at least as deep as `cmd/platform-api`'s
  documented blocker, but a full working config WAS successfully
  assembled - reusing existing fixtures
  (`test/fixtures/alert-case/policy.json`,
  `test/fixtures/case-assistance/corpus/snapshot.json`,
  `test/fixtures/review-console/signing-key.hex`) plus one piece built
  programmatically in the test itself: a valid `reviewauth.Registry` with
  a correctly computed checksum, using the package's own exported
  `HashObject` function rather than guessing at the hash algorithm.
  `model_mode: "fixture"` avoids needing a live Ollama instance. Includes
  a deliberate negative test (a structurally-valid registry with only the
  checksum wrong) proving the checksum validation actually fires - the
  first version of that test was itself wrong (the "bad" registry failed
  on missing fields before ever reaching the checksum check), caught and
  fixed before committing. This directly closes the
  `internal/reviewconsoleapi` zero-test gap named in the original issue.
- `cmd/review-console` - 9 tests, reusing the same config-assembly recipe
  (duplicated, not shared - each `cmd/` package compiles as its own
  `main`), covering all 5 subcommands including a genuine issue-token ->
  verify-token round trip (both via the `-token` flag and via stdin,
  since `main.go` falls back to reading `/dev/stdin` when the flag is
  omitted - verified from source before testing, not assumed).
- `cmd/ofac-ingest` - 6 tests, including real manifest/catalog happy
  paths. Important: without `--input`, this binary defaults to
  downloading from a real external URL - every test passes `--input`
  pointing at a local fixture specifically to avoid a live network
  dependency, verified this default by reading main.go first.
- `cmd/update-manager` - 5 tests, including a real `simulate` happy path
  using this binary's own built-in flag defaults, which already point at
  committed fixtures.
- `cmd/screening-ledger` - 7 tests, reusing the real, pre-populated
  ledger state committed at `test/fixtures/screening-ledger/state/`
  (copied into a fresh temp dir per test, since some commands mutate
  state). `migrate`/`sync`/`import-audit` (live PostgreSQL) and `replay`
  (live HTTP backend) not covered, same category as `cmd/alert-case`'s
  skipped `migrate`.
- `cmd/catalog-refresh` - 4 tests, including a real `simulate` happy path
  using built-in fixture defaults.
- `cmd/catalog-registry` - 5 tests, including a full
  init -> register-component -> register-version -> activate -> verify
  -> snapshot happy path, using real committed component/version input
  fixtures whose IDs are deterministically derived from content (verified
  the fixture's hardcoded `component_id` actually matches what
  registering the component fixture produces, rather than assuming).
- `cmd/provider-catalog` - 7 tests, covering all 4 subcommands. Found and
  documented a real schema incompatibility: `internal/providerentity`'s
  catalog format is NOT the same as `matcherprovider`'s
  `ExactMatchFixtureProvider` format (see issue #12) - a catalog valid for
  one is rejected by the other. Includes a test asserting this rejection
  explicitly, not just working around it silently.
- `cmd/provider-refresh` - 6 tests. Scope: `init` (needs a
  catalog-registry store as its one prerequisite) plus failure modes and
  `postgres-schema`. `analyze`/`decide`/`promote`/`rollback` need a THIRD
  chained subsystem (an alert-list-mapping store) plus specific analysis
  input - a fuller multi-system integration test, not attempted here.
- `cmd/scoring-activation` - 5 tests, including a real
  activate-then-status happy path reusing the exact projection-package
  fixture pair independently verified during the #13 investigation.
- `cmd/activation-promotion` - 8 tests. The most complex remaining `cmd/`
  package (12 subcommands, a full canary/shadow-testing promotion
  lifecycle). Scope: the read/record-oriented subcommands (`status`,
  `verify-audit`, `compare-shadow`, `summarize-shadow`) using the real,
  pre-populated promotion state committed at
  `test/fixtures/activation-promotion/state/` - its own golden README
  says this fixture "is never promoted in place," which matches this
  scope exactly. `stage`/`prepare`/`evaluate`/`start-canary`/`ack`/
  `promote`/`rollback`/`recover` (the full lifecycle mutations) not
  covered - a bigger, separate integration test.
- `cmd/rag-corpus` - 6 tests. Found and worked around a real fixture/code
  drift: the committed `test/fixtures/rag/corpus-manifest.json` and
  `test/golden/rag/corpus-snapshot.json` use a richer, DIFFERENT schema
  than what `LoadManifest`/`LoadSnapshot` currently accept (discovered by
  running the commands against them and reading the actual "unknown
  field" errors, not assumed compatible). Built a minimal, schema-correct
  manifest programmatically instead, using real document text from
  `test/fixtures/rag/documents/approved-policy.md` rather than synthetic
  content. Also found `test/fixtures/rag/entity-type-query.json` uses an
  older `query_text`-based query schema; the current `RetrievalQuery`
  needs `terms []string` - added a test asserting the old-schema query is
  correctly rejected, not silently mishandled.
- `cmd/rag-index` - 4 tests, including a real happy path proven
  BYTE-IDENTICAL to `test/golden/rag/corpus-snapshot.json` (aside from a
  randomly-generated `snapshot_id`). Important architectural finding:
  this repo has TWO separate, parallel RAG implementations -
  `internal/rag` (this package, and `cmd/rag-query`) and
  `internal/assistancerag` (`cmd/rag-corpus`) - and the original
  committed fixtures that `cmd/rag-corpus` couldn't use are correctly
  shaped for `internal/rag` instead. Confirmed directly, not assumed.
- `cmd/rag-query` - 6 tests, covering both mutually-exclusive input modes
  (`--query` and `--decision-batch`). The decision-batch test chains a
  REAL decision batch generated by actually running `cmd/policy-evaluate`
  against its own known-working fixture, rather than hand-authoring one.
- `cmd/iso20022-family` - 8 tests, covering all 5 subcommands
  (matrix/inspect/project/batch/verify) plus a real inspect-then-verify
  chain, using extensive existing pacs.008 XML fixtures and this
  binary's own default matrix config.
- `cmd/iso20022-inspect` - 8 tests, covering all 5 `--output` modes
  (canonical/evidence/inspection/matcher-requests/replay) against the
  same real pacs.008 fixture and this binary's own default screening-plan
  config.
- `cmd/release-config` - 6 tests, both subcommands (`seal-runtime`,
  `seal-quotas`) against real committed production config examples
  (`configs/production/phase9g-example.json`,
  `configs/production/tenant-quotas-r1.json`) rather than hand-authored
  configs, given this project's history with strict,
  `DisallowUnknownFields` config schemas.
- `cmd/release-artifact` - 5 tests, a full manifest -> verify -> bundle ->
  verify-bundle happy path against a small synthetic directory tree
  (deliberately not this actual repo - slow and fragile against unrelated
  changes for no real benefit), plus a genuine tamper-detection test
  (modify a file after the manifest is built, confirm `verify` catches it
  with a content-mismatch error).
- `cmd/release-benchmark` - 3 tests. This tool always makes real HTTP
  requests with no fixture/dry-run mode at all (verified by reading
  main.go). Every test points `--url` at `127.0.0.1:1`, a reserved port
  nothing ever listens on - a fast, deterministic, guaranteed-refused
  connection, not a live external dependency - which still exercises the
  real benchmark runner, JSON report shape, and the
  qualified/exit-code-1 logic end to end. A genuinely successful run
  against a live target is a separate integration test, not attempted.
- `cmd/release-qualification` - 6 tests, including a real
  evaluate -> verify happy path. Confirmed the real committed fixture
  suite genuinely qualifies against the real gate set (status
  "qualified", exit 0) before writing that assertion - a "not qualified"
  (exit 2) case isn't covered, since no stricter gate config or worse
  suite currently exists as a fixture to exercise it.
- `cmd/container-healthcheck` - 5 tests, using a real local
  `httptest.Server` for genuine 2xx and non-2xx happy/failure paths, plus
  the guaranteed-refused-local-port pattern for the connection-error
  case.
- `cmd/adversarial-checksum-fix` - 5 tests. IMPORTANT: this tool mutates
  its input file in place - every test copies the real committed
  adversarial catalog fixture into a fresh temp file first, never points
  the binary at a fixture path directly. A real, self-caught test-design
  mistake here: the first version of the happy-path test wrongly
  asserted the file's bytes must change after running - but the
  committed fixture is already checksum-correct (this is the tool that
  originally produced it), so re-running it against already-correct
  content is a legitimate no-op, and the test failed for the wrong
  reason. Fixed by testing determinism (same output on repeated runs)
  plus a separate test that deliberately corrupts the checksum field
  first and confirms the tool actually corrects it back - the real proof
  the tool works, not just that it runs without error.
- `cmd/matcher-project` - 6 tests, chaining a real evidence bundle
  generated by actually running `cmd/iso20022-inspect -output evidence`
  rather than hand-authoring one.
- 9 of 49 `cmd/` packages remain: `cmd/alert-case-api`,
  `cmd/case-assistance-api`, `cmd/case-assistance`,
  `cmd/vendor-adapter-api`, `cmd/alert-list-mapping`, `cmd/analyst-note`,
  `cmd/platform-ops`, `cmd/review-run`, `cmd/runtime-catalog-input`. Plus
  the legacy `screeningapiv8d`-`v8g` wrappers, deliberately deferred
  pending the separate #14 keep/archive/delete decision.

## Suggested order for remaining work

Production-facing and fixture-rich packages are covered through batch 4
(`cmd/screening-api`, `cmd/matcher-run`, `cmd/ofac-runtime`,
`cmd/projection-package`, `cmd/candidate-score`,
`cmd/false-positive-classify`, `cmd/alert-case`, `cmd/vendor-adapter`).
Next: `cmd/ofac-ingest`, then `cmd/review-console-*` - a priority given
`internal/reviewconsoleapi` is the other zero-test `internal/` package
named in the original issue, though check first whether it has the same
kind of deep, fixture-less config chain that blocked a happy-path test
for `cmd/platform-api`.
