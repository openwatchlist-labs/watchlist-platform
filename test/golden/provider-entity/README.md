# Phase 7A provider-entity goldens

These files lock the provider-ready catalog boundary without using live or redistributed provider data.

- `provider-catalog.json` is the deterministic projection of the synthetic OpenSanctions-like snapshot.
- `catalog-comparison.json` compares provider source memberships with the accepted OFAC direct-list fixture.
- `provider-entity-results.json` proves the consolidated provider adapter emits the existing matcher-result schema.
- `hybrid-overlay-results.json` proves official OFAC results can be linked back to provider entities while retaining both lineages.
- `hybrid-review-run.json` proves the Phase 6B review orchestrator consumes hybrid matcher results without API or schema changes.

All identities, checksums, ordering, and output bytes are regression locked.
