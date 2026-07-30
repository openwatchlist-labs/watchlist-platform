# R2.4 defect closure and engineering lessons

R2.4 intentionally stopped on every violated invariant and repaired the harness
before another activation attempt.

## Canonical path identity

The first offline lifecycle defect compared a canonical symlink target with an
uncanonicalized runtime path. Filesystem aliases such as `/var` and
`/private/var` could identify the same directory but fail a string comparison.

**Control added:** canonicalize both sides while retaining exact governed-runtime
ownership requirements.

## Catalog fixture byte identity

A Cyrillic alias in the copied conformance input was missing one character. The
published compiler correctly produced a package that did not match the golden
hash.

**Control added:** exact commit-pinned byte verification and structured expected
versus actual package diagnostics.

## Corpus passage integrity

Three passage texts contained newlines where the governed snapshot used spaces,
while their embedded checksums still described the original normalized text.

**Control added:** passage-level checksum validation, canonical manifest and
snapshot hashing, and exact recompilation from the source manifest.

## Temporary qualification rebinding

The temporary Opt1 qualification initially rewrote only `runtime.json` while
`review-console.json` still referenced the persistent runtime root.

**Control added:** recursively rebind every copied governed JSON configuration,
regenerate every seal already declared by a modified config, reject persistent
path residue, and verify all activation-input paths before the published check.

## Archive ordering

Earlier controllers transferred both activation archives before the Opt1
pre-mutation gate.

**Control added:** transfer the Opt1 archive, qualify Opt1, and only then transfer
the Opt2 archive.

## General rule

Duplicated metadata is not independent evidence. Every governed input must be
validated from its own bytes and, where applicable, against an immutable public
source or deterministic compiler contract.
