# Phase 9E r1 — governed vendor adapter framework

Phase 9E introduces strict, checksum-addressed adapter profiles for generic JSON interchange and reference mappings for Fircosoft-style and Actimize-style alert exports. The vendor reference profiles are intentionally not represented as certified proprietary protocol implementations; production institutions must qualify their exact export contract against a new immutable profile and fixtures.

Every accepted source object is converted into the existing `openwatchlist.external-alert.v1` request used by Phase 9A–9B. The envelope binds source bytes, adapter profile, exact field mapping trace, active raw-list-name resolution, correlation and idempotency data, and the canonical alert request. Unknown or unmapped lists are rejected rather than guessed.

The local store provides byte-exact idempotent replay, conflict detection, immutable records and a hash-chained audit. Optional PostgreSQL tables retain the bounded canonical envelope and receipts, not complete proprietary source payloads. The CLI can submit the canonical request to the existing alert-case API, but adapters cannot change deterministic classification or policy routes and cannot record regulatory disposition.

## Supported reference profiles

- `generic-json-v1`
- `fircosoft-reference-json-v1`
- `actimize-reference-json-v1`

## Qualification boundary

A deployment must create a new versioned profile and fixture set whenever a vendor export, field meaning, list naming convention, score scale or required field changes. Profile hash mismatch, missing required fields, unsupported score values and unmapped list names block ingestion.
