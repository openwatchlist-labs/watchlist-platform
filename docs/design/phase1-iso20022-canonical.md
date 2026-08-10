# Phase 1: ISO 20022 Canonical Model and Screening-Plan Engine

**Status:** Phase 1A canonical baseline; extended by Phase 1B evidence execution
**Implemented message definition:** `pacs.008.001.08`
**Plan:** `iso20022-pacs008-cbprplus@1.0.0`
**Canonical schema:** `canonical-message/v1alpha1`
**Element schema:** `screenable-element/v1alpha1`

## 1. Purpose

Phase 1A converts the Phase 0 ISO 20022 design into executable contracts. It establishes the stable boundary between native payment parsing and later list matching. The parser does not produce sanctions decisions. It emits typed, path-aware elements plus a validated screening directive resolved from a versioned plan.

The design follows the core principle that richer ISO 20022 structure should be retained and used to target screening rather than flattening an entire payment into one text field.

## 2. Implemented repository slice

```text
cmd/iso20022-inspect/
internal/
  adapters/iso20022/
  canonical/
  normalization/
  screeningplan/
configs/screening-plans/
test/fixtures/iso20022/pacs008/
scripts/validate_phase1.sh
```

All Phase 1A Go code uses the standard library. The initial plan format is strict JSON so local and CI builds do not depend on a third-party YAML package. A later YAML-facing authoring layer may compile to this same plan contract.

## 3. Canonical message contract

A parsed message records:

- canonical schema version;
- group-header message ID;
- full ISO 20022 namespace;
- message definition;
- immutable source payload reference;
- parser version;
- screening-plan ID, version, and checksum;
- ordered screenable elements; and
- parser warnings.

A screenable element records:

- deterministic element ID;
- message and transaction identity;
- transaction index;
- namespace-neutral native path;
- repeated-field occurrence;
- semantic and party roles;
- typed value and presence state;
- original and normalized values;
- XML attributes needed as evidence, such as amount currency;
- resolved screening-plan entry and directive;
- source payload reference and parser version; and
- element-level warnings.

## 4. Stable element identity

Element IDs are derived from:

```text
source payload reference
message definition
message ID
transaction index
native path
occurrence
```

Normalization output is intentionally excluded. A normalization-rule change therefore does not make a native XML element appear to be a different source element.

## 5. Presence states

Phase 1A distinguishes:

```text
present   element exists and passes initial type-format checks
empty     element exists but contains no non-whitespace value
invalid   element exists but fails an initial type-format check
absent    no canonical element is emitted for that native path
```

This is not full XSD validation. It provides enough state to prevent an empty or malformed identifier from being treated as valid match evidence.

## 6. Screening-plan contract

The plan is loaded with unknown-field rejection and compiled before parsing. Each entry defines:

- path pattern, including `[*]` for repeated indexes;
- semantic role and party role;
- value type;
- trigger policy;
- allowed match routes;
- allowed candidate types;
- normalization profile;
- threshold profile; and
- supporting semantic roles.

Compilation rejects:

- duplicate plan or path entries;
- unsupported wildcard forms;
- unknown normalization profiles;
- retain-only entries that define match routes;
- candidate-alert entries without routes; and
- incompatible route/value-type combinations.

Runtime resolution requires exactly one matching entry. Missing or ambiguous entries fail parsing instead of silently falling back to generic text screening.

## 7. Trigger-policy boundary

```text
candidate_alert       may retrieve candidates through the configured routes
supporting_evidence   may support or contradict a candidate but does not independently alert
retain_only           retained for lineage and review; no matching route is invoked
disabled              explicitly excluded by a versioned plan
```

Payment references, amounts, dates, group identifiers, transaction identifiers, and UETRs are retain-only in the initial plan. Party and financial-institution names can trigger name routes. BIC and LEI values use exact typed routes. Accounts are supporting evidence. Countries use jurisdiction-policy context. Remittance text uses a contextual phrase/window route.

## 8. Initial `pacs.008.001.08` extraction

Phase 1A extracts the following categories when present:

- group message ID, creation time, and declared transaction count;
- instruction, end-to-end, transaction, and UETR identifiers;
- interbank settlement amount, currency attribute, and settlement date;
- debtor, creditor, ultimate-debtor, and ultimate-creditor names;
- party LEIs and birth dates;
- party towns, country codes, and repeated address lines;
- debtor and creditor account IBAN or proprietary ID;
- debtor-agent and creditor-agent names, BICs, LEIs, and addresses; and
- repeated unstructured remittance lines.

Transaction paths include an explicit `CdtTrfTxInf[n]` index. Repeated address and remittance fields include their own occurrence indexes.

## 9. Normalization boundary

The initial profiles perform deterministic, dependency-free operations:

- whitespace trimming or collapse;
- Unicode-aware uppercasing;
- whitespace removal for typed identifiers; and
- preservation of original Unicode in `original_value`.

Phase 1A does **not** claim full Unicode normalization, transliteration, phonetic processing, or language-aware tokenization. Those will be introduced as versioned normalization/matching capabilities and must not overwrite the original value.

## 10. XML safety and limits

The parser:

- limits input to 8 MiB by default;
- requires a namespaced `Document` root;
- derives the message definition from the namespace;
- supports only `pacs.008.001.08` in this slice;
- requires the `FIToFICstmrCdtTrf` body;
- uses strict XML tokenization;
- rejects XML directives, including `DOCTYPE` declarations;
- rejects non-XML processing instructions; and
- rejects malformed or unsupported messages explicitly.

Go's XML decoder is not configured with external entity mappings, and the explicit directive rejection prevents a DTD from becoming part of the accepted input contract.

## 11. Fixtures and tests

Synthetic fixtures cover:

- a representative single-transaction message;
- a multi-transaction message;
- repeated remittance lines;
- a present-but-empty debtor name;
- an unsafe `DOCTYPE` payload;
- an unsupported message version; and
- malformed XML.

The tests assert:

- deterministic canonical JSON for the same source and plan;
- stable transaction indexes and transaction IDs;
- distinct semantic roles and routes;
- retain-only behavior for IDs, amount, and date;
- exact typed routes for BIC, LEI, and account evidence;
- native-path preservation;
- empty-value preservation; and
- explicit negative-path errors.

## 12. CLI inspection

```bash
go run ./cmd/iso20022-inspect \
  --plan configs/screening-plans/iso20022-pacs008-cbprplus-v1.json \
  --source-ref fixture:pacs008-basic \
  test/fixtures/iso20022/pacs008/pacs008-basic.xml
```

The default command output remains canonical JSON. Phase 1B adds `--output evidence` and `--output inspection`; see [`phase1b-screening-evidence.md`](phase1b-screening-evidence.md). None of these modes performs list retrieval, candidate comparison, policy scoring, or alert disposition.

## 13. Known limitations

Phase 1A does not yet provide:

- XSD or CBPR+ usage-guideline validation;
- Business Application Header parsing;
- complete `pacs.008` field coverage;
- `pacs.009`, `pacs.009 COV`, or `pacs.004` structural handlers;
- SWIFT MT or vendor-alert adapters;
- list retrieval or comparison;
- policy decisions;
- persistent raw-payload storage; or
- production-grade PII controls.

These limitations are explicit so downstream code cannot confuse syntactic canonicalization with validated payment acceptance or sanctions adjudication.

## 14. Phase 1A acceptance result

The slice is accepted when:

```text
Phase 0 validation passes
gofmt reports no changes
go vet ./... passes
go test ./... passes
the basic fixture emits canonical JSON
the plan contains at least 40 path-specific entries
no third-party Go module is required
```

## 15. Phase 1B extension

Phase 1B now adds independently verified plan execution, message-level evidence bundles, machine-readable output modes, and golden canonical/evidence snapshots. The remaining structural-message work is intentionally deferred to the next slice:

1. a canonical parser interface and registry shared by API, batch, and replay callers;
2. top-level detection contracts for `pacs.009`, `pacs.009 COV`, and `pacs.004`;
3. structural fixtures for those definitions;
4. Business Application Header correlation where present; and
5. explicit parser result codes for unsupported-but-recognized structures.

## 16. References

- [Swift: Guiding principles for screening ISO 20022 payments](https://www.swift.com/swift-resource/251416/download)
- [Swift: ISO 20022 standards](https://www.swift.com/standards/iso-20022/iso-20022-standards)
- [ISO 20022: Message definitions](https://www.iso20022.org/iso-20022-message-definitions)
