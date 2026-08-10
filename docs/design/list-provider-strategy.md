# List Provider Strategy

**Status:** Phase 0 design contract
**Initial source:** OFAC official list data
**Architectural requirement:** provider-ready without provider lock-in

## 1. Objective

The first implementation will ingest OFAC official list data, but the canonical model and matching APIs must support the evidence shapes used by consolidated open and commercial providers.

The platform separates:

- a **source assertion** — what a specific authority or provider published;
- a **catalog candidate** — the runtime object used for retrieval and comparison; and
- an **entity profile** — an optional consolidated view linking multiple assertions.

This prevents an OFAC-specific schema from becoming the permanent platform boundary.

## 2. Supported product modes

A deployment selects one runtime mode.

### `OFFICIAL_LIST`

One candidate projection per official-list record. For OFAC, the sole supported production source is `SDN_ADVANCED.XML` Version 3. The candidate retains direct source lineage and does not imply cross-source entity consolidation.

### `PROVIDER`

One candidate per provider-consolidated entity. The provider may link multiple source memberships, aliases, identifiers, relationships, and enrichments. OpenSanctions is the first adapter, not a platform list taxonomy. Provider dataset names are discovered metadata and are never hardcoded as internal list identities.

### Historical hybrid experiment

Phase 7A implemented `HYBRID_OVERLAY` for architectural research and provider qualification. It remains regression code but is not a supported product runtime mode. Organizations use either official-list mode or provider mode.

## 3. Canonical source assertion

```text
assertion_id
source_system
source_authority
source_list
source_record_id
source_record_version
published_at
acquired_at
effective_from/effective_to
content_checksum
raw_record_reference
entity_type_as_published
names and aliases as published
identifiers as published
addresses as published
programs/measures as published
relationships as published
provider rights/entitlement classification
```

Corrections and withdrawals create new versioned state; they do not silently rewrite historical lineage required for replay.

## 4. Canonical catalog candidate

```text
candidate_id
catalog_mode
catalog_version
canonical_entity_type
primary_name
aliases
identifiers
addresses
countries/nationalities
birth/incorporation facts
program memberships
relationships
source_assertion_refs
provider_entity_ref when applicable
normalization/runtime package versions
```

The candidate is a comparison projection, not a claim that all attached assertions are legally or factually identical beyond the catalog's documented consolidation rules.

## 5. Entity types

The normalized taxonomy should support at least:

```text
individual
organization
government_entity
financial_institution
vessel
aircraft
jurisdiction
securities_instrument
unknown
```

Provider-specific types map to the normalized taxonomy while retaining the original published value.

## 6. OFAC Advanced XML ingestion

The OFAC production adapter must:

- acquire only `SDN_ADVANCED.XML` through the official Sanctions List Service endpoint;
- capture acquisition time, publication/version metadata where available, checksums, and source URLs;
- enforce Advanced XML namespace, Version 3, schema location, and SDN list membership;
- parse and preserve structured names, Unicode/script metadata, aliases, addresses, identifiers, programs, entity type, features, legal authorities, and relationships;
- retain unsupported fields in raw/source form rather than discarding them;
- produce a deterministic catalog snapshot and runtime package; and
- support replay against a pinned snapshot.

The adapter must not treat the OFAC search tool's score as the platform's decision score.

## 7. Provider adapter contract

A provider adapter supplies:

```text
capabilities
catalog mode
source and entity version identifiers
incremental/full update behavior
record and relationship mappings
rights and retention constraints
quality warnings
raw-record access policy
```

The platform validates provider output against the canonical schema before publishing a catalog snapshot.

## 8. OpenSanctions prototype role

An OpenSanctions adapter can demonstrate provider-style consolidated entities and multi-source membership using an open-data ecosystem. It is an architectural prototype, not proof that all commercial providers expose identical semantics or licensing terms.

The adapter must preserve:

- OpenSanctions entity and dataset identifiers;
- contributing source memberships;
- source and dataset versions;
- schema mappings and unsupported properties; and
- applicable licensing/usage metadata.

## 9. Commercial provider readiness

Commercial adapters may require:

- deployment-local connectors;
- customer-provided credentials;
- entitlement checks;
- field-level usage and retention policy;
- encrypted storage and restricted logs;
- prohibition on public fixtures or redistributed snapshots;
- provider-specific update SLAs; and
- audit evidence showing which provider version informed a decision.

No commercial provider data should enter the public repository.

## 10. Matching independence

The matcher consumes provider-neutral candidates. It must not branch on vendor names to implement core comparison semantics.

Provider differences are expressed through:

- source assertions;
- entity type and confidence metadata;
- available identifiers and relationships;
- quality flags;
- consolidation lineage; and
- screening-plan or policy configuration.

A deployment can qualify provider behavior against official evidence in a laboratory workflow, but production screening runs one selected mode.

## 11. Identity consolidation

Consolidation is separate from matching a transaction party to a candidate.

```text
source record linkage
  determines whether multiple list/provider records refer to one catalog entity

screening comparison
  determines whether the input party/field may refer to a catalog candidate
```

Do not reuse a transaction match score to consolidate provider records. Consolidation requires its own rules, provenance, confidence, and review process.

## 12. Update and snapshot model

```text
acquire source version
validate completeness and schema
map to source assertions
build candidate projections
build indexes/runtime package
run catalog and matcher regression
publish immutable catalog version
activate through controlled configuration
retain rollback pointer
```

A partial or failed update must not replace the active catalog.

## 13. List quality and conflict handling

The catalog records, rather than hides:

- conflicting dates or identifiers;
- inconsistent entity types;
- alias-language or transliteration differences;
- source withdrawals and provider lag;
- duplicate or suspected duplicate records;
- missing qualifiers; and
- unsupported or malformed values.

Policy can require manual review when source conflicts are material.

## 14. Evidence returned to review

At minimum:

```text
catalog candidate and version
catalog mode
candidate entity type
matched name/identifier/address feature
all material source assertion references
source list and record identifiers
program/measure context
provider entity identifier when applicable
conflicts and quality warnings
runtime package and normalization versions
```

An analyst must be able to distinguish an official assertion from provider enrichment.

## 15. Rights and licensing

The platform license governs platform code, not third-party data. Each adapter and deployment must respect source-specific terms governing acquisition, redistribution, storage, derivatives, retention, and model use.

The repository should contain:

- adapter code where redistribution is permitted;
- synthetic or expressly redistributable fixtures;
- checksums and metadata examples; and
- instructions for users to acquire restricted data themselves.

It should not contain unlicensed commercial datasets or customer exports.

## 16. Phase 2 acceptance criteria

- ingest a complete supported OFAC snapshot from an official source;
- preserve source list, source record ID, acquisition metadata, and checksum;
- represent aliases, identifiers, addresses, programs, and normalized entity type;
- publish an immutable direct-list catalog version;
- retrieve a candidate with full source lineage;
- rebuild the runtime package deterministically; and
- replay fixtures against a pinned catalog snapshot.

## 17. Phase 7 acceptance criteria

- load a provider-style consolidated catalog through the same public contracts;
- expose provider source membership without losing direct-list lineage;
- run direct-list and provider-entity modes through the same matcher API;
- enforce rights/entitlement metadata; and
- compare behavior through catalog-specific regression reports.

## 18. References

- [OFAC Sanctions List Service](https://ofac.treasury.gov/sanctions-list-service)
- [OFAC Sanctions List Search Tool](https://ofac.treasury.gov/sanctions-list-search-tool)
- [OpenSanctions](https://www.opensanctions.org/)

## Phase 2A OFAC direct-list generation

The supported official-list adapter uses OFAC `SDN_ADVANCED.XML` Version 3. Legacy `SDN.XML` remains test-only migration evidence. Raw bytes, manifests, UID-based records, and catalog checksums are immutable. Updates always produce a staged generation; active memory is never patched in place. Future delta support must reconstruct a complete generation off-path and preserve the same activation and audit contracts.

## Runtime-package boundary

Provider adapters may expose different source models, but screening workers consume a compiled package with a stable provider descriptor, catalog reference, source-manifest lineage, and route-specific index. Phase 2B implements this boundary for the OFAC `direct_list` mode. Future provider compilers must emit the same package, readiness, activation, rollback, and generation-stamping contracts while preserving their source-specific entity semantics.

## Fleet distribution

Provider catalog artifacts are distributed as immutable compiled packages. The update manager never sends raw OFAC XML to the active screening path. Workers acknowledge package readiness and activation using provider, catalog, package, and source-manifest lineage. A fleet epoch identifies the coordinated rollout, while each worker retains its own content-addressed generation identity.

## Normalized delta boundary

List providers may expose different delta formats, sequence conventions, and record semantics. Provider adapters must translate those inputs into the Phase 2D immutable catalog-delta contract. Screening workers and matcher providers do not consume provider-native deltas. They consume only a fully reconstructed, validated, compiled catalog generation after promotion policy succeeds.

## Deterministic matcher profiles

Catalog identity and matcher-profile identity are governed separately. Phase 3A records the profile-set ID and checksum inside candidate evidence while preserving catalog and runtime-generation lineage.

## Context and jurisdiction policy overlays

A direct sanctions list is not automatically a complete embargo-geography policy. Phase 3B therefore treats jurisdiction policy as an explicit, versioned, checksum-protected overlay. Provider adapters may supply equivalent governed geography data, but must preserve source identity and must not silently infer policy from ordinary address-country values. Contextual narrative matching uses whole-token phrase windows and records the underlying direct-list or policy source assertion.


## 19. Alert-list mapping

Incoming alert list names are organization-controlled data, not provider constants. Resolution uses exact `(source_system, raw_list_name)` mappings to stable platform catalog-component IDs. A provider component reference such as an OpenSanctions dataset name is stored as mutable provider metadata behind that stable ID. Provider refresh cannot promote a component removal or rename while active alert mappings would break. Unmapped alerts are retained with `ALERT_LIST_MAPPING_REQUIRED`; they never become clean results.

## Stable provider-neutral component registry

Provider dataset identifiers are not platform list identities. An organization creates a stable component key and maps each provider release to that component through version metadata. A provider rename therefore creates a reviewed version/source-reference change without changing the component ID that future alert mappings use. Official-list components follow the same registry and activation contract, with OFAC restricted to Advanced XML Version 3.

## Exact organization alert mappings

List names emitted by upstream alert systems are organization configuration. The platform resolves only exact `(source_system_id, raw_list_name)` keys to stable catalog component IDs. It does not hardcode provider dataset names and does not fuzzy-match list labels. A future provider rename or a planned official-to-provider cutover changes catalog-version metadata or creates an effective-dated mapping version; it does not require changing the alert source or stable mapping identity. Resolution also requires an active catalog pointer. Any unresolved or unavailable state is retained with a review blocker.


## Provider refresh and mapping compatibility

A provider release is represented as a normalized inventory of opaque provider component references. The platform reports exact additions, removals, unchanged references, and administrator/provider-declared renames. It never infers a rename by fuzzy title or dataset-name similarity. Every active provider-mode stable component is checked against the candidate inventory, and effective Phase 7C-C mappings are counted. Removal of a component with active mappings blocks promotion. New provider components require explicit stable-component registration and alert mapping before use. An approved refresh registers a new immutable catalog version and activates it with a compare-and-set precondition; rollback is a new append-only activation and governance event.
