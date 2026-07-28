# OpenWatchlist Clean Restart R1.6

## Decision

The prior repository is preserved as a legacy/archival source. The new
`openwatchlist-labs/watchlist-platform` repository begins with no inherited Git
history, no inherited GitHub workflows, and no generated homelab evidence.

R1.6 imports only reviewed blobs from an immutable source commit. All selected
source files are preserved byte-for-byte. Repository controls and an exact Rust
`1.97.1` toolchain declaration are reconstructed from clean overlay files.

## Non-goals

R1 does not delete or rewrite the legacy repository, mutate GitHub, rotate
credentials, copy uncommitted working-tree content, restore the homelab harness,
or certify deployment readiness.

## Required sequence

1. Preserve and record the legacy repository commit and tree.
2. Generate the import plan from the committed Git tree only.
3. Review selected and excluded paths.
4. Execute into an empty, unborn, remote-free local repository.
5. Re-hash every imported destination file against the immutable manifest.
6. Run bootstrap CI and review the staged baseline and journal.
7. Create the first commit and configure a remote only after explicit local
   acceptance.

## Legacy-harness boundary

The import policy and every CI run reject:

- `var/`, evidence, materialized, generated, result, backup, build, cache, and
  archive trees;
- legacy `deploy/` and `scripts/release/`;
- H1/homelab commands, scripts, test plans, candidates, bindings, and evidence;
- inherited `.github/` workflows and stale root release documentation;
- generated Go selectors beneath evidence trees;
- nested Go modules and unmanaged Rust workspaces;
- environment files, private-key containers, and private evidence.

This blocks the historical failure in which stale generated Go under
`var/homelab/evidence/.../materialized/selector` was discovered by the root Go
module.

## Byte-preserving inherited-debt governance

The accepted source contains 14 trailing-whitespace findings across 13 Phase 9D
fixtures and eight Rust files that differ from Rust `1.97.1` rustfmt. These are
not normalized during bootstrap.

Each inherited exception is bound to the source commit, tree, path, and file
SHA-256. During bootstrap, every imported file must still match its manifest
hash. In durable CI:

- an unchanged baseline file may retain only its exact recorded debt;
- any new warning or additional Rust formatting path fails;
- when a baseline file changes, its inherited exception retires;
- the changed file must then be clean;
- Rust formatting is evaluated only in an isolated temporary copy, so CI never
  rewrites the repository.

Historical import and baseline checksum lists remain provenance records, not a
rule that future reviewed source files can never change.
