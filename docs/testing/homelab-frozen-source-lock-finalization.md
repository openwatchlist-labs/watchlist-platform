# Homelab frozen source-lock finalization

This gate turns the metadata candidate emitted by `h1-freeze-sources.sh` into a reviewed, metadata-only frozen source lock. It does not copy the large OFAC or OpenSanctions source files into Git.

The finalizer re-hashes the exact files on OptiPlex-2, streams and validates OFAC Advanced XML records, validates every OpenSanctions FollowTheMoney NDJSON entity, checks identifier uniqueness and dataset membership, records counts and schema distribution, and writes evidence with checksums.

## OFAC Advanced XML record identity

The Advanced XML party record is `DistinctParty`, not `SanctionsEntry`. Each OFAC-listed party is counted once from `DistinctParty`, and the pre-existing OFAC UID is read from `DistinctParty@FixedRef`. The same UID is independently checked against `Profile@ID`. `SanctionsEntry` objects are counted separately as administrative sanctions-action metadata and never used as the watchlist record count.

The census implementation is namespace-independent, accepts attribute-name case variation, stays memory-bounded by capturing record state on XML start events, and fails closed for missing or duplicate `FixedRef` values or a `FixedRef`/`Profile@ID` mismatch.

The accepted release parser lineage remains `ofac-advanced-xml/v0.2.0`. The source-census implementation records its own lineage as `homelab-ofac-advanced-census/v1.1.0`.

The OpenSanctions artifact does not embed a FollowTheMoney package version, so the default records `not_declared_in_entities_ftm_json` rather than inventing a version. An externally verified model version may be supplied through `OPENWATCHLIST_FTM_MODEL_VERSION`.

The resulting working binding file remains `unbound_review_required`. No execution becomes qualification-ready until all 35 bindings resolve to records from the frozen OFAC source, crosswalk to the corresponding frozen OpenSanctions entity, contain evidence paths, and are manually reviewed.

Run:

```bash
./scripts/homelab/h1-stage.sh
./scripts/homelab/h1-finalize-source-lock.sh
./scripts/homelab/h1-plan-tests.sh
```
