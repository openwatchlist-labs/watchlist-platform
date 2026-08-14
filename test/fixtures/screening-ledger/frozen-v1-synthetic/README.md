# Synthetic frozen-v1 fixture (ADR-0007 D4/D5)

**This directory is synthetic test data. It was never live, and it does not represent this
repository's real ledger history.**

`state/events/9c151179....json` and `state/head.json` are byte-identical to what
`test/fixtures/screening-ledger/state/` held at commit `03c0f04` (this repository's
"clean-restart" baseline import) -- i.e. the genuine pre-D2 digest
(`event_sha256: 855cf134fb8eb40dff54559a6cc62834e1c861fab73f00f327e5c8048f9176cc`), computed by
the unkeyed `sha256.Sum256(json(event))` algorithm that predates ADR-0007 D2's HMAC chain.

They are copied here, rather than hand-computed, so the digest is a real, deterministically-correct
plain-SHA256 value pulled from an actual historical commit -- not a fresh one that could silently
drift from what a genuine pre-D2 event's shape actually looked like.

## Why this exists instead of reusing the real fixture

Stage 1 (PR #106, commit `9661a5a`) regenerated `test/fixtures/screening-ledger/state/`'s sole event
in place under the new HMAC scheme *before* D4's frozen-prefix migration plan (ADR-0007 §6) was
implemented -- while leaving its `schema_version` label at `v1`. That means the real committed
fixture's `v1`-labeled data was, by the time Stage 3 (D4) ran, already HMAC'd: strong data under a
label that claimed the weak guarantee. Stage 3 corrected that by relabeling it `v2` (see the
ADR-0007 §6 correction note) rather than leaving strong data mislabeled as weak.

That correction means the real fixture no longer contains any genuine pre-D2, unkeyed-digest data --
so `Store.Verify`'s frozen-prefix code path (accepting `v1` entries under the legacy algorithm,
reporting them as an unanchored weaker-guarantee prefix, and hard-failing any `v1` entry that appears
after a `v2` genesis boundary) has nothing real to exercise against the committed production fixture.
This directory supplies that coverage instead: a genuine, historically-sourced unkeyed digest, used
only by `internal/screeningledger`'s test suite (ADR-0007 §7.1 case 6, "frozen-prefix acceptance") to
prove the mechanism works, not to claim this ledger ever ran under the weak scheme in production.

**This repository has never had live traffic** (ADR-0007 §2, "Explicitly not assumed"; ADR-0002 §5;
ADR-0003 §8) -- no real production data was ever at stake in Stage 1's fixture regeneration, and
none is at stake here.

## Contents

- `state/ledger-id`, `state/snapshots/*.json` -- copied unmodified from the real fixture. Snapshot
  digests commit to plaintext, not the chain scheme, so they are identical whichever event references
  them (ADR-0007 §5.1).
- `state/events/9c151179....json`, `state/head.json` -- the recovered pre-D2 (`v1`, unkeyed) record,
  described above.

Tests using this fixture append a fresh `v2` genesis record on top of it (via the real, unmodified
`Store.Append`) to exercise the genesis boundary itself, rather than committing that step's output
here -- the boundary is the thing under test, so it is constructed live, not pre-baked.
