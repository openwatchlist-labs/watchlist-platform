# Phase 9D — complete supported ISO 20022 message-family coverage

Phase 9D expands the Phase 1 `pacs.008` implementation into one explicit, checksum-addressed project support matrix. “Complete” means complete coverage of the profiles listed in `configs/iso20022/family-matrix-r1.json`; it does not claim support for every ISO 20022 message or every historical schema version.

## Supported profile matrix

| Profile | Project role |
|---|---|
| `pacs.008.001.08` | FI-to-FI customer credit transfer |
| `pacs.009.001.08` | Financial-institution credit transfer |
| `pacs.009.001.08.cov` | `pacs.009` COV profile with underlying customer transfer |
| `pacs.004.001.09` | Payment return |
| `pacs.002.001.12` | FI-to-FI payment status report |
| `pain.001.001.09` | Customer credit-transfer initiation |
| `pain.002.001.10` | Customer payment status report |
| `camt.056.001.08` | FI-to-FI payment cancellation request |
| `camt.029.001.09` | Resolution of investigation |
| `camt.053.001.08` | Bank-to-customer statement |
| `camt.054.001.08` | Bank-to-customer debit/credit notification |
| `camt.026.001.09` | Unable-to-apply investigation message |
| `camt.027.001.09` | Claim-non-receipt investigation message |
| `camt.028.001.11` | Additional-payment-information investigation message |

Every profile receives the same bounded parser, source-byte checksum, matrix lineage, field-path evidence, transaction indexing, deterministic normalization, replay checksum, and screening-request projection.

## Contracts

The evidence contract is `openwatchlist.iso20022-family-evidence.v1`. It records:

- immutable source reference and source SHA-256;
- support-matrix ID, version, and SHA-256;
- exact profile and message-definition ID;
- COV variant discrimination;
- source XML paths with repeated-element indexes;
- transaction index, semantic role, original value, normalized value, action, and match eligibility;
- deterministic envelope SHA-256.

The projection contract is `openwatchlist.iso20022-screening-projection.v1`. It includes only match-eligible evidence and does not create a policy route, alert disposition, case decision, or LLM instruction.

## Security boundaries

The parser:

- accepts at most 16 MiB per XML document;
- limits XML depth and total element count;
- rejects `DOCTYPE`, entity declarations, and XML directives;
- requires an exact namespace, root element, and optional profile discriminator from the matrix;
- rejects unsupported message definitions rather than silently falling back;
- never resolves external entities or performs network access.

## Commands

List the immutable matrix:

```bash
go run ./cmd/iso20022-family matrix \
  --matrix configs/iso20022/family-matrix-r1.json
```

Inspect one message:

```bash
go run ./cmd/iso20022-family inspect \
  --matrix configs/iso20022/family-matrix-r1.json \
  --source-ref fixture:pacs009-cov.xml \
  test/fixtures/iso20022-phase9d/pacs009-cov.xml
```

Project match-eligible requests:

```bash
go run ./cmd/iso20022-family project \
  --matrix configs/iso20022/family-matrix-r1.json \
  --source-ref fixture:camt056.xml \
  test/fixtures/iso20022-phase9d/camt056.xml
```

Build an ordered multi-family batch:

```bash
go run ./cmd/iso20022-family batch \
  --matrix configs/iso20022/family-matrix-r1.json \
  --source-prefix fixture: \
  test/fixtures/iso20022-phase9d/*.xml
```

Validate the complete increment:

```bash
./scripts/validate_phase9d.sh
```

## Deliberate non-goals

Phase 9D does not:

- infer unsupported ISO versions;
- validate against redistributed proprietary XSD files;
- flatten messages into a single screening string;
- change Phase 9A–9B policy or case decisions;
- change Phase 9C RAG or model behavior;
- store full XML messages or watchlist rows in PostgreSQL;
- claim support for every ISO 20022 business area.

Later version additions must be explicit matrix changes with fixtures, goldens, replay checks, and downstream regression qualification.
