# ISO 20022 Screening Architecture

**Status:** Design contract updated through Phase 1B
**Initial end-to-end message:** `pacs.008`
**Initial structural fixtures:** `pacs.009`, `pacs.009 COV`, `pacs.004`

## 1. Objective

ISO 20022's richer and more granular structure should enable more targeted screening. OpenWatchlist Platform must preserve that structure rather than flattening a payment into undifferentiated text.

The parser emits canonical elements with native XML path, namespace/message version, semantic role, original value, normalized value, and screening-plan identity.

## 2. Scope model

### v0.1 end-to-end

- `pacs.008` FI-to-FI customer credit transfer;
- group-header and transaction-level identifiers;
- debtor, creditor, ultimate parties, agents, accounts, addresses, and remittance information;
- source-path-aware evidence; and
- screening-plan routes for names, identifiers, financial institutions, jurisdictions, references, and narrative.

### v0.1 structural fixture support

- `pacs.009` financial institution credit transfer;
- `pacs.009 COV` cover payment context;
- `pacs.004` payment return.

Structural support means fixtures can be detected, parsed into top-level canonical structures, and rejected safely when an unsupported element requires interpretation. It does not imply complete market-practice coverage.

## 3. Parsing rules

1. Detect the message definition from the XML namespace and document body.
2. Retain the full namespace URI and message version.
3. Disable external entity resolution and unsafe XML expansion.
4. Preserve a stable native path for every extracted value.
5. Preserve transaction repetition/index context for multi-transaction documents.
6. Distinguish absent, empty, invalid, and present values.
7. Retain original Unicode before normalization or transliteration.
8. Do not infer an entity type solely from a free-text name.
9. Record parser warnings separately from screening evidence.
10. Reject unsupported or ambiguous message versions explicitly rather than silently flattening them.

## 4. Canonical element shape

```text
message_id
transaction_id
message_definition
message_namespace
native_path
semantic_role
party_role
value_type
original_value
normalized_value
normalization_profile
screening_plan_id
source_payload_reference
parser_version
warnings
```

## 5. Path and semantic-role examples

Paths are namespace-neutral illustrations; the namespace URI and message version remain separate evidence fields.

| Native path pattern | Semantic role | Default behavior |
|---|---|---|
| `/Document/FIToFICstmrCdtTrf/CdtTrfTxInf/Dbtr/Nm` | `debtor.name` | person/entity name candidate route |
| `/Document/FIToFICstmrCdtTrf/CdtTrfTxInf/Cdtr/Nm` | `creditor.name` | person/entity name candidate route |
| `/Document/FIToFICstmrCdtTrf/CdtTrfTxInf/UltmtDbtr/Nm` | `ultimate_debtor.name` | person/entity name candidate route |
| `/Document/FIToFICstmrCdtTrf/CdtTrfTxInf/UltmtCdtr/Nm` | `ultimate_creditor.name` | person/entity name candidate route |
| `/Document/FIToFICstmrCdtTrf/CdtTrfTxInf/DbtrAgt/FinInstnId/BICFI` | `debtor_agent.bic` | exact financial-institution identifier route |
| `/Document/FIToFICstmrCdtTrf/CdtTrfTxInf/CdtrAgt/FinInstnId/LEI` | `creditor_agent.lei` | exact legal-entity identifier route |
| `/Document/FIToFICstmrCdtTrf/CdtTrfTxInf/DbtrAcct/Id/IBAN` | `debtor_account.iban` | exact account route only when enabled by policy |
| `/Document/FIToFICstmrCdtTrf/CdtTrfTxInf/CdtrAcct/Id/Othr/Id` | `creditor_account.other_id` | typed identifier route; never generic name route |
| `/Document/FIToFICstmrCdtTrf/CdtTrfTxInf/Dbtr/PstlAdr/Ctry` | `debtor.address.country` | jurisdiction/program-policy evidence route |
| `/Document/FIToFICstmrCdtTrf/CdtTrfTxInf/RmtInf/Ustrd` | `remittance.unstructured` | contextual phrase/window route |
| `/Document/FIToFICstmrCdtTrf/CdtTrfTxInf/PmtId/EndToEndId` | `payment.end_to_end_id` | retain-only by default |

A deployment may override behavior through a versioned screening plan, but it must not discard the original semantic role.

## 6. Screening-plan contract

Each plan entry defines:

```yaml
path_pattern: /Document/FIToFICstmrCdtTrf/CdtTrfTxInf/Dbtr/Nm
semantic_role: debtor.name
trigger_policy: candidate_alert
match_routes:
  - normalized_name
  - alias
  - transliteration
allowed_candidate_types:
  - individual
  - organization
  - government_entity
normalization_profile: party_name_v1
threshold_profile: party_name_r1
supporting_fields:
  - debtor.address.country
  - debtor.identification.birth_date
  - debtor.identification.organization_id
```

Screening-plan configuration is validated and compiled before use. Unknown semantic roles, incompatible routes, and unsupported entity types are configuration errors.

## 7. Default field policy

### Party names

Party names may trigger person, organization, government-entity, vessel-owner/operator, or other explicitly configured entity routes. A name score alone does not establish identity.

### Financial institution identifiers

BIC and LEI values use exact or tightly controlled normalized identifier matching. Substring matching inside identifiers is not a default escalation route.

### Accounts and other identifiers

IBAN, account, clearing, reference, and proprietary identifiers are screened only through typed routes. A value that resembles a vessel IMO, securities identifier, or name token must not be treated as that type unless the plan permits it.

### Countries and jurisdictions

Country fields provide policy and geographic context. The platform must not implement a simplistic universal "OFAC country list." Jurisdiction treatment depends on the applicable program, transaction context, institution policy, and effective date.

### Addresses

Address lines, towns, subdivisions, postal codes, and countries are retained as separate evidence. They can support or contradict a party match but should not be collapsed into a party name.

### Remittance and narrative

Unstructured narrative uses phrase/window and context-aware routes. The system must distinguish a transacting party from quoted text, a denial statement, an invoice description, a compliance instruction, or a historical reference.

### Payment references

Message IDs, end-to-end IDs, transaction IDs, and references are retain-only unless an explicit typed screening rule exists.

## 8. False-positive controls enabled by structure

Native path and semantic role allow deterministic controls for cases such as:

- a country token embedded in an unrelated product or company name;
- a vessel identifier collision inside an account field;
- a sanctioned acronym inside a payment reference;
- a BIC suffix or routing code matching a short watchlist token;
- a legal entity name compared to a vessel candidate;
- a narrative that says the customer has **no** relationship with a named party; and
- a technical migration or treasury identifier that resembles a list identifier.

The control result is evidence for the policy engine, not an unconditional release.

## 9. Evidence bundles

### 9.1 Plan-execution evidence — implemented in Phase 1B

Before list retrieval, the platform emits a deterministic message-level bundle containing:

```text
message and transaction identifiers
message definition and namespace
native field path and occurrence
original and normalized values
semantic role, party role, and value type
trigger policy and effective execution action
match routes and target entity types
normalization and threshold profiles
screening-plan ID, version, checksum, and entry
presence state and parser warnings
source payload and parser lineage
```

The executor independently re-resolves every path and rejects stale or altered parser attachments. Empty and invalid matching values are preserved but marked ineligible for matching.

### 9.2 Candidate-comparison evidence — future matcher phase

For every retrieved and compared candidate, later phases will add:

```text
candidate and catalog identifiers
source assertions and source version
candidate entity type
comparison features and scores
field/entity compatibility findings
false-positive patterns
contradictions and missing evidence
policy decision reference
```

## 10. Batch and real-time parity

The same parser, canonical model, screening plans, matcher, and policy engine must be used by:

- synchronous API requests;
- asynchronous batch workers;
- historical replay;
- fixture evaluation; and
- promotion gates.

Only transport, scheduling, and output packaging may differ.

## 11. Versioning and compatibility

Every result records:

- parser version;
- supported message-definition version;
- canonical schema version;
- screening-plan version;
- normalization version; and
- policy version.

Adding support for a newer ISO 20022 message version requires fixtures that demonstrate both intended new behavior and no unintended changes to pinned older versions.

## 12. Phase 1B acceptance criteria

- representative `pacs.008` documents parse into deterministic canonical elements;
- all extracted values retain message version, transaction index, and native path;
- name, BIC, LEI, account, country, reference, and narrative fields resolve to distinct semantic roles;
- every element is independently re-resolved against the pinned plan;
- route, trigger policy, semantic role, target entity types, and plan lineage are attached to element evidence;
- amount, date, IDs, and references remain ineligible for generic name matching;
- empty and invalid matching values are preserved but skipped;
- canonical and evidence golden JSON snapshots are regression-gated;
- all CLI output modes are machine-readable JSON; and
- unsafe XML constructs are rejected.

Structural `pacs.009`, `pacs.009 COV`, and `pacs.004` handling plus API/batch parser-registry parity remain in the next Phase 1 slice.

## 13. References

- [Swift: Guiding principles for screening ISO 20022 payments](https://www.swift.com/swift-resource/251416/download)
- [Swift: ISO 20022 standards and CBPR+ usage guidelines](https://www.swift.com/standards/iso-20022/iso-20022-standards)
- [Swift: About ISO 20022](https://www.swift.com/standards/iso-20022)

## Phase 1C matcher handoff

The Phase 1B evidence bundle is the sole ISO 20022 input to matcher projection. Only present elements resolved as `candidate_alert` or `supporting_evidence` become candidate-search requests. Retain-only references, amounts, dates, empty values, and invalid values remain auditable evidence but cannot reach the matcher.

The request preserves the native ISO path, transaction index, semantic and party roles, normalized query, route and target constraints, screening-plan checksum, evidence ID, element ID, parser version, executor version, and immutable source reference. This prevents matcher implementations from flattening or reinterpreting the payment message.
