# Synthetic pacs.008 fixtures

These messages are synthetic engineering fixtures. They contain no production customer data and are not asserted to satisfy any specific market-practice schema beyond the fields exercised by Phase 1.

- `pacs008-basic.xml` exercises names, identifiers, agents, accounts, addresses, amounts, dates, and repeated remittance text.
- `pacs008-multi-transaction.xml` proves transaction-index and repeated-field isolation.
- `pacs008-empty-name.xml` proves present-but-empty values remain distinguishable.
- `pacs008-unsafe-doctype.xml` must be rejected before semantic parsing.
- `pacs008-unsupported-version.xml` must be rejected explicitly.
- `pacs008-malformed.xml` must fail strict XML parsing.
