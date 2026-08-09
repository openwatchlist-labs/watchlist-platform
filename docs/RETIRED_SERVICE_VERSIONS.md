# Retired screening-api versions: why they're still here

`internal/screeningapiv8d`, `v8e`, `v8f`, `v8g` (and their corresponding
`cmd/screening-api-v8d` through `-v8g` entrypoints) are earlier iterations
of the current `internal/screeningapi` / `cmd/screening-api`. This document
records the decision to keep them for now, and what's actually known and
not known about them, rather than leaving that context only in issue #14.

## What's actually verifiable about them (checked, not assumed)

- No package-level doc comment or file header comment exists in any of
  v8d/e/f/g explaining what changed or why a given version exists. This
  document exists partly because that context wasn't captured at the time.
- Their scope isn't a simple linear progression, though it's not fully
  independent parallel exploration either - checked directly, not
  assumed either way: `internal/screeningapiv8e` actually imports
  `internal/screeningapiv8d` directly (wraps its
  `NewHTTPUpstream`/`NewServer`), discovered while adding `cmd/`-level
  tests. `v8f` and `v8g` do not import any of the other retired versions.
  File listings still differ in ways that suggest not every version
  builds cleanly on the last:
  - `v8d`: config, extract, idempotency, projections, server, upstream (the
    most complete of the four - closest in shape to the current version).
  - `v8e`: config, server, upstream only (no idempotency, no
    extract/projections) - the smallest, and internally depends on v8d.
  - `v8f`: config, idempotency, server, upstream (no extract/projections) -
    independent of the others, adds a canary/shadow promotion layer.
  - `v8g`: config, idempotency, server only (no upstream, no
    extract/projections) - independent of the others.
- Each retired version has its own passing unit tests
  (`internal/screeningapiv8d/server_test.go`, etc. - all currently green as
  part of the full suite). As of this writing, all four also have
  `cmd/`-level black-box test coverage (issue #15's pattern, applied here
  on explicit request after #15 itself closed) - `cmd/screening-api-v8d`
  and `cmd/screening-api-v8g` each get a genuine full HTTP round trip
  matched against real fixtures; `cmd/screening-api-v8e` gets the same via
  cross-package reuse of v8d's and `cmd/scoring-activation`'s fixtures;
  `cmd/screening-api-v8f` (the canary/shadow variant, needing both
  activation AND promotion state plus two upstreams) is scoped to failure
  modes only - see `docs/CMD_TESTING_PATTERN.md`'s final section for the
  full detail. Originally, only `v8d` had a dedicated fixture directory
  under `test/fixtures/`/`test/golden/`; the `cmd/`-level tests for
  v8e/g work around that by reusing fixtures from other packages rather
  than requiring dedicated ones - worth knowing if extending this further.
- A shallow clone doesn't preserve enough history to establish a reliable
  chronology or commit-level rationale for why each version was kept
  rather than replaced in place - worth checking against the full git
  history (not just a shallow clone) if this question comes up again.

## The decision (as of this writing): keep, not archive or delete

Rationale, stated plainly rather than assumed with confidence:

1. **No confirmation exists that nothing still depends on a specific
   retired version.** Deleting code that a deployed environment or a
   rollback procedure might reference, without first confirming it's
   safe, is a bigger risk than the modest ongoing cost of keeping tested-
   but-unused code around.
2. **Each version costs relatively little to keep as-is**: they build,
   they have their own tests, and they don't block or complicate work on
   the current version - the two live side by side without interaction.
3. **This is not the same as saying they should stay forever.** If it's
   confirmed that nothing in any deployed environment, rollback runbook,
   or external integration references v8d/e/f/g specifically, they should
   be archived (moved out of the actively-built module tree) or deleted
   outright - carrying four retired versions of the same service
   indefinitely is exactly the kind of accumulation this project's own
   "Clean Restart" was meant to reduce, and it's already crept back in
   once.

## Suggested follow-up, not done as part of this document

- Confirm (via deployment records, rollback runbooks, or asking whoever
  operates the homelab/production environment) whether any retired
  version is an active rollback target or integration dependency.
- If none are, open a follow-up issue to actually archive or remove them,
  informed by that confirmation rather than by default inertia.
- Consider requiring a short rationale comment (a `doc.go` or top-of-file
  comment, at minimum) for any *future* version fork, so this same
  documentation gap doesn't recur for whatever comes after the current
  `screeningapi`.
