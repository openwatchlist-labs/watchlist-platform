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
- 44 of 49 `cmd/` packages remain. `internal/reviewconsoleapi` also still
  has zero tests (the other package noted alongside `platformapi` in the
  original issue).

## Suggested order for remaining work

Prioritize production-facing services first (`cmd/screening-api`,
`cmd/review-console-api` if it exists, `cmd/matcher-run`), then the
catalog-lifecycle cluster (`cmd/ofac-runtime`, `cmd/ofac-ingest`,
`cmd/projection-package` - though the latter already has indirect coverage
via `internal/projectionpackage`'s own tests calling its exported
functions directly), then the rest roughly by how production-critical they
are.
