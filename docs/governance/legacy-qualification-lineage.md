# Sanitized legacy qualification lineage

This document records what was learned from the pre-clean-restart repository
without importing raw execution results or obsolete operational machinery.
The machine-readable authority is `legacy-qualification-lineage.json`.

## Import decision

No legacy test file is copied verbatim by this update. The clean canonical
repository already includes the reviewed production code, unit and contract
tests, synthetic/public fixtures, and goldens selected during the clean
restart. Legacy H1 scripts and results are tied to fixed hosts, generated
artifacts, or superseded architecture and are intentionally retained only in
the private archive.

Two new canonical regressions preserve lessons that were not previously tested
as explicit fixtures:

1. legacy operational, generated-evidence, and fixed-host paths may not re-enter
   canonical Git history;
2. a stale generated Go source under a legacy evidence tree must be rejected
   before the root Go module can discover it.

## Historical records

- **Phase 7C through Phase 11:** accepted historical engineering baseline;
  reviewed code and current tests were already imported through the curated
  clean restart. The historical result is superseded by canonical releases.
- **Phase 11 rc.2 publication:** accepted historical release qualification,
  superseded by the current canonical release lineage.
- **H1 source locking and governed binding selection:** accepted historical
  research lineage; raw candidates, binding evidence, and execution output are
  not imported.
- **H1 r2 provider activation failure:** safely blocked by a stale generated Go
  evidence tree. The canonical exclusion gate and the new regression preserve
  this lesson.
- **Legacy H1 fixed-host harness:** superseded by the sanitized R2.4 deployment
  harness and controlled rollback qualification.

## Interpretation

Historical acceptance means that a bounded legacy procedure produced an
accepted result at that time. It does not make the legacy repository a current
release, production deployment source, regulatory certification, or substitute
for canonical CI and current qualification.
