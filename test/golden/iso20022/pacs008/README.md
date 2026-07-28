# Phase 1 golden JSON

These files freeze the canonical and screening-evidence contracts for representative `pacs.008.001.08` fixtures.

Do not refresh them as a routine test repair. Update a golden file only when the associated schema, parser, normalization, screening plan, or execution behavior changes intentionally and the contract diff has been reviewed.

The regression test marshals values with two-space indentation and a final newline, then requires byte-for-byte equality.

## Phase 1C contracts

- `pacs008-basic.matcher-requests.json` pins the 30-request candidate-search handoff.
- `pacs008-basic.replay.json` pins the complete replay envelope and projection policy.
- `pacs008-multi-transaction.matcher-requests.json` pins request ordering and transaction isolation.

Direct XML projection and projection from the persisted Phase 1B evidence golden must remain byte-identical.

## Phase 1D contracts

- `pacs008-basic.candidate-results.json` pins provider descriptor, request lineage, candidate ordering, source assertions, and 30 request results.
- `pacs008-basic.provider-replay.json` pins the complete Phase 1C input replay plus Phase 1D candidate-result batch.
- `pacs008-multi-transaction.candidate-results.json` pins provider behavior across two transaction indexes.

The synthetic provider catalog is test-only. Refresh these files only after an intentional provider/result schema or fixture-catalog change and review all identity and lineage diffs.
