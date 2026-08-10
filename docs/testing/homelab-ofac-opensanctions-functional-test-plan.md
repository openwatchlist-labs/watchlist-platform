# Homelab OFAC and OpenSanctions Functional Test Plan

**Plan ID:** `openwatchlist-homelab-functional-test-plan-r1`

**Release under qualification:** `v0.1.0-rc.2`

**VCS reference:** `fb88a11846b8940f69d2c5b4325e22812686a0b8`

**Immutable image:** `ghcr.io/openwatchlist-labs/watchlist-platform@sha256:02c1538f3525b16499062f72ae230f62279d021fe922ac9c5828dc9076562bf3`

**Status:** Test design and unbound real-source corpus

## 1. Purpose

This plan defines the tracked post-release functional qualification for native
OFAC, OpenSanctions `us_ofac_sdn`, and dual-provider screening. It converts all
35 supplied Fircosoft-style false-positive examples into durable industry
archetypes while replacing every illustrative watchlist ID, biography, alias,
identifier, and program with data resolved from a frozen real OFAC snapshot.

The supplied examples are pattern evidence, not source-of-truth watchlist data.
They remain valuable because the failure modes recur in production transaction
screening: common names, transliteration, field-type errors, substrings,
acronyms, missing qualifying words, narrative context, and asset/person/company
confusion.

## 2. Governing principles

1. **Real watchlist truth only.** OFAC names, aliases, UIDs, entity types,
   programs, dates, countries, addresses, and identifiers come from the frozen
   official snapshot.
2. **Synthetic innocent side.** Payment parties, payment messages, KYC
   conflicts, and controlled mutations are synthetic and must not represent a
   real innocent person or company.
3. **No invented provider lineage.** OpenSanctions entities must be cross-walked
   to the same OFAC source record and retain their own provider identifiers.
4. **No regulatory disposition.** Tests may assert candidate tiers, mismatch
   evidence, reason codes, or review recommendations. They must never expect
   auto-release, regulatory clearance, or a confirmed false-positive decision.
5. **Paired controls.** Every false-positive archetype has a true-positive and a
   near-negative control using the same real watchlist record.
6. **Frozen qualification, separate freshness.** Qualification uses immutable
   snapshots. Live provider refresh checks are a separate canary.

## 3. Repository layout

```text
docs/testing/homelab-ofac-opensanctions-functional-test-plan.md
testdata/homelab/
├── README.md
├── false-positive-archetypes.v1.json
├── bindings/
│   ├── frozen-source-lock.v1.template.json
│   └── real-ofac-bindings.v1.template.json
└── schemas/
    ├── false-positive-archetypes.v1.schema.json
    ├── frozen-source-lock.v1.schema.json
    └── real-ofac-bindings.v1.schema.json
cmd/homelab-testdata-validate/main.go
```

The archetype registry is immediately versioned. Binding files become
qualification evidence after snapshot selection and manual review.

## 4. Test data lifecycle

### 4.1 Freeze provider sources

Create a source lock containing release digest, OFAC file checksums, OpenSanctions
file checksums, parser/model versions, record counts, and projection package
checksums. Source bytes remain file-backed and are not placed in PostgreSQL.

### 4.2 Bind each archetype

For each `fp-NNN` entry:

1. Query the frozen OFAC data using the tracked selection strategy.
2. Select a record that naturally supports the archetype.
3. Record the real OFAC UID, primary name, aliases, attributes, and record hash.
4. Resolve the corresponding OpenSanctions FollowTheMoney entity.
5. Record the crosswalk rationale and evidence path.
6. Obtain manual review before the binding lock is merged.

When no real record satisfies a selector, mark the archetype blocked and choose
another real record preserving the same failure mode. Never invent a record.

### 4.3 Generate three controls

Each binding produces:

- **False-positive case:** controlled name, field, identifier, or narrative
  collision with contradictory evidence.
- **True-positive control:** real primary name or alias plus compatible real
  secondary evidence.
- **Near-negative control:** sufficiently unrelated data expected not to reach
  candidate threshold.

The minimum corpus is 105 scenarios. Running each through native OFAC,
OpenSanctions, and dual-provider modes produces at least 315 provider-mode
executions.

### 4.4 Execute and preserve evidence

Each execution records release digest, source locks, package activation lineage,
request bytes, candidate/evidence projection, reason codes, timing, and result
hashes. PostgreSQL may retain operational metadata and audit evidence but not the
full provider catalogs or full payment XML.

## 5. Scenario contract

A generated executable scenario must identify:

```json
{
  "scenario_id": "fp-001-false-positive-native-ofac",
  "archetype_id": "fp-001",
  "control": "false_positive",
  "provider_mode": "native_ofac",
  "source_lock_sha256": "sha256:...",
  "binding_lock_sha256": "sha256:...",
  "release_image_digest": "sha256:02c153...",
  "synthetic_transaction": true,
  "expected": {
    "provider_lineage_required": true,
    "catalog_activation_lineage_required": true,
    "regulatory_disposition": "not_provided"
  }
}
```

Expected results should assert evidence, not a fabricated score. Scores may be
bounded or tiered when the policy contract requires it, but provider parity does
not require identical numeric scores.

## 6. Required archetype matrix

| ID | Industry archetype | Family | Implementation track |
|---|---|---|---|
| fp-001 | Common Name Hit (Fuzzy Name Matching) | `common_name_biographical` | `identity_evidence` |
| fp-002 | Geographic Substring Hit (Text Containment) | `substring_collision` | `field_semantics` |
| fp-003 | Vessel / Corporate Name Conflict | `entity_type_conflict` | `asset_identity` |
| fp-004 | BIC Code / Location Sequence Hit | `routing_code_collision` | `field_semantics` |
| fp-005 | Corporate Initials / Acronym Hit | `acronym_collision` | `identity_evidence` |
| fp-006 | Phonetic / Transliteration Over-Match | `transliteration` | `identity_evidence` |
| fp-007 | Port or Locality Name Containment Hit | `substring_collision` | `narrative_context` |
| fp-008 | Generic Commercial Term Hit | `lexical_collision` | `narrative_context` |
| fp-009 | Multi-Word Overlap Hit (Shared Legal Form) | `multiword_overlap` | `identity_evidence` |
| fp-010 | OFAC Keyword Match with Missing Qualifying Words | `missing_qualifying_terms` | `identity_evidence` |
| fp-011 | Slavic / Eastern European Phonetic Over-Match | `transliteration` | `identity_evidence` |
| fp-012 | Latin American Name Permutation Over-Match | `name_permutation` | `identity_evidence` |
| fp-013 | East Asian Monosyllabic Exact-Name Over-Match | `common_name_biographical` | `identity_evidence` |
| fp-014 | Intermediary Bank Acronym Overlap | `routing_code_collision` | `field_semantics` |
| fp-015 | Sovereign Debt Free-Text Clause Match | `narrative_context` | `narrative_context` |
| fp-016 | Energy Commodity Trade Narrative Overlap | `substring_collision` | `narrative_context` |
| fp-017 | SWIFT Tag 20 Transaction Reference Match | `wrong_field_context` | `field_semantics` |
| fp-018 | Account Number Collision with Vessel IMO | `typed_identifier_collision` | `typed_identifier` |
| fp-019 | Regulatory Reporting Denial-Context Match | `denial_context` | `narrative_context` |
| fp-020 | Asset Management Fund Registry Overlap | `corporate_similarity` | `identity_evidence` |
| fp-021 | Securities Identifier Sequence Collision | `typed_identifier_collision` | `typed_identifier` |
| fp-022 | Syndicated Loan Facility Reference Collision | `narrative_context` | `narrative_context` |
| fp-023 | Bulk Vendor Name versus Individual | `entity_type_conflict` | `identity_evidence` |
| fp-024 | Corporate Liquidity Sweep Internal Code Collision | `wrong_field_context` | `field_semantics` |
| fp-025 | Trade Invoice Product-Code Substring | `substring_collision` | `narrative_context` |
| fp-026 | Middle Eastern Name Transliteration and Age Conflict | `transliteration` | `identity_evidence` |
| fp-027 | Latin American Compound Surname and Gender Conflict | `name_permutation` | `identity_evidence` |
| fp-028 | Family Remittance Substring Phrase Collision | `substring_collision` | `narrative_context` |
| fp-029 | Dual-Use Goods or Trade Serial Collision | `typed_identifier_collision` | `typed_identifier` |
| fp-030 | Bankruptcy Trustee and Sanctioned Estate Name | `legal_control_context` | `narrative_context` |
| fp-031 | Short Exact Name versus Corporate Entity | `entity_type_conflict` | `identity_evidence` |
| fp-032 | System Migration Padding or Technical Artifact | `technical_artifact` | `field_semantics` |
| fp-033 | Dictionary Word versus Individual Surname | `lexical_collision` | `narrative_context` |
| fp-034 | Missing Qualifying Industry Word: Company versus Vessel | `missing_qualifying_terms` | `identity_evidence` |
| fp-035 | Distinctive Token with Multiple Missing Context Words | `missing_qualifying_terms` | `identity_evidence` |

## 7. Provider suites

### Native OFAC

Validate official-source acquisition, strict parsing, stable source IDs,
provider projection, runtime package creation, registration, activation,
readiness, single and batch screening, idempotency, lineage, refresh, and
rollback.

### OpenSanctions

Validate `us_ofac_sdn` dataset locking, FollowTheMoney parsing, names and aliases,
typed identifiers, memberships, source links, multi-valued properties, entity
merges, provider projection, activation, screening, refresh, and rollback.

### Cross-provider differential

Run the same synthetic case against native OFAC, OpenSanctions, and dual-provider
modes. Require correct provider-specific lineage, prevent evidence leakage
between providers, and retain both sources when subject-level deduplication is
performed.

## 8. Acceptance gates

A corpus revision is mergeable when:

- exactly 35 numbered archetypes exist;
- every archetype declares false-positive, true-positive, and near-negative
  controls;
- every archetype declares all three provider modes;
- every binding is tied to a frozen real OFAC record;
- every OpenSanctions binding points to the same OFAC source record;
- binding evidence is manually reviewed;
- no illustrative or guessed OFAC data is used as source truth;
- no expected result provides regulatory disposition;
- the test-data validator passes;
- all generated scenario and evidence files have deterministic hashes.

Homelab qualification additionally requires deployment smoke, all functional
suites, benchmark gates, and upgrade/rollback qualification against the exact
published image digest.

## 9. Pull-request governance

Changes to archetypes, binding locks, source locks, or expected invariants should
be isolated in reviewable pull requests. A binding PR should show:

- source snapshot checksums;
- before/after corpus hashes;
- real record selection evidence;
- OpenSanctions crosswalk evidence;
- generated scenario count;
- validator output;
- reviewer approval.

Changing a real record binding is a test-data change and must not be hidden in a
code-only pull request.

## 10. Non-goals

This plan does not treat the attached illustrative XML as official OFAC data, does
not authorize storing full catalogs in PostgreSQL, does not allow an LLM to own a
screening disposition, and does not treat live provider updates as deterministic
release qualification.
