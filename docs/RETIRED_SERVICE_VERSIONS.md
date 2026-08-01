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
- Their scope isn't a simple linear progression. File listings differ in
  ways that suggest parallel exploration of different capabilities rather
  than each version strictly superseding the last:
  - `v8d`: config, extract, idempotency, projections, server, upstream (the
    most complete of the four - closest in shape to the current version).
  - `v8e`: config, server, upstream only (no idempotency, no
    extract/projections) - the smallest.
  - `v8f`: config, idempotency, server, upstream (no extract/projections).
  - `v8g`: config, idempotency, server only (no upstream, no
    extract/projections).
- Each retired version has its own passing unit tests
  (`internal/screeningapiv8d/server_test.go`, etc. - all currently green as
  part of the full suite). Only `v8d` has a corresponding fixture directory
  under `test/fixtures/` and `test/golden/`; v8e/f/g have unit tests but no
  fixture-level test data at all (see `docs/TEST_DATA.md`).
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
