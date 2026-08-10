# Phase 7C-A — OFAC Advanced XML production source

Phase 7C-A makes OFAC Advanced XML the sole supported production format for the platform's official-list mode. It does not add PostgreSQL as a catalog dependency and does not add a memory-mapped runtime implementation.

## Product modes

The supported deployment choices are:

1. **Official-list mode** — acquire OFAC SDN Advanced XML directly from OFAC.
2. **Provider mode** — acquire a provider catalog through a provider-neutral adapter and organization-managed alert-list mappings.

The earlier hybrid-overlay implementation remains historical research and regression code. It is not a supported product runtime mode.

## Supported OFAC source

Production acquisition is restricted to:

```text
SDN_ADVANCED.XML
namespace: https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/ADVANCED_XML
Version: 3
schema: https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/ADVANCED_XML.xsd
```

Legacy `SDN.XML` is retained only for historical migration fixtures and parity evidence. It is not accepted by the public `live-catalog-sync ofac` production command.

## XSD-driven document model

The Advanced XML file is not treated as a flat sequence in which every `DistinctParty` is automatically an SDN record. The XSD defines separate, cross-referenced collections:

```text
DistinctParty
  -> one or more Profile
       -> one or more Identity

SanctionsEntry
  -> required ProfileID
  -> optional ListID

ListID
  -> ReferenceValueSets/ListValues

ProfileRelationship
  -> required SanctionsEntryID
```

A single Advanced XML publication can therefore contain profiles and sanctions entries associated with list references other than the SDN list. The parser resolves each `SanctionsEntry.ListID` through `ListValues` and selects only the exact canonical reference value `SDN List`. Entries for `Non-SDN Palestinian Legislative Council List`, SSI, or any other list are counted and filtered; they do not invalidate the document and do not enter the SDN catalog.

List selection is exact after case and whitespace normalization. It does not use substring or fuzzy matching, so `Non-SDN ... List` cannot be mistaken for `SDN List`.

The parser also follows the XSD cardinalities instead of assuming one record per profile:

- one `DistinctParty` may contain multiple profiles;
- one profile may contain multiple identities;
- one profile may be referenced by multiple sanctions entries;
- multiple selected SDN profiles belonging to one `DistinctParty` are merged into one UID-scoped canonical party;
- programs and legal-authority events from all selected SDN entries are aggregated;
- relationships are retained only when their required `SanctionsEntryID` belongs to a selected SDN entry; and
- location and identity-document attributes use their XSD names, including `LocPartTypeID`, `LocationPartValue`, `IDRegDocTypeID`, `IdentityID`, and `IDRegDocDateTypeID`.

The canonical snapshot publishes source-shape statistics so a live run can be audited:

```text
distinct_party_count
profile_count
sanctions_entry_count
selected_sdn_entry_count
filtered_non_sdn_entry_count
```

These counts distinguish the full Advanced XML source structure from the final UID-scoped SDN catalog record count.

## Data flow

```text
allowlisted OFAC HTTPS endpoint
  -> bounded acquisition and signed-redirect redaction
  -> strict Advanced XML namespace/version validation
  -> XSD-scoped list and relationship resolution
  -> canonical Advanced snapshot containing SDN entries only
  -> compatibility direct-list catalog
  -> immutable checksums and provenance
```

The canonical snapshot preserves source Unicode and script metadata. It does not transliterate, flatten to ASCII, or discard non-Latin values. Future multilingual normalization and matching must derive additional indexes from these preserved values.

## Outputs

```text
var/live-catalogs/ofac-sdn-advanced/
  source/SDN_ADVANCED.XML
  source-manifest.json
  ofac-advanced-canonical.json
  ofac-sdn-catalog.json
  advanced-legacy-parity.json   # only when --legacy-catalog is supplied
```

The source manifest records the Advanced XML namespace, schema version, schema location, source filename, acquisition method, source checksum, publication date, parser version, and selected catalog record count. The canonical snapshot separately records the full source-shape statistics listed above.

## Live synchronization

```bash
go run ./cmd/live-catalog-sync ofac \
  --output-dir var/live-catalogs/ofac-sdn-advanced
```

Verify the downloaded bytes independently:

```bash
go run ./cmd/live-catalog-sync verify \
  --manifest var/live-catalogs/ofac-sdn-advanced/source-manifest.json \
  --data var/live-catalogs/ofac-sdn-advanced/source/SDN_ADVANCED.XML
```

## Migration parity

During the cutover, an existing legacy fixture or previously generated legacy catalog can be supplied only for comparison:

```bash
go run ./cmd/live-catalog-sync ofac \
  --input test/fixtures/ofac/advanced/sdn-advanced-fixture.xml \
  --acquired-at 2026-07-14T15:00:00Z \
  --output-dir /tmp/ofac-advanced \
  --legacy-catalog test/golden/ofac/ofac-sdn-fixture.catalog.json
```

The parity report compares UID coverage, primary names, entity types, programs, and alias/address/identifier counts. Differences are migration evidence; they are never silently reconciled.

## Catalog storage boundary

Phase 7C-A stores source bytes, canonical snapshots, and catalogs as immutable versioned artifacts. It does not load every list record into PostgreSQL.

Later phases store control-plane metadata in PostgreSQL:

```text
catalog source and version
catalog component registry
active-version pointer
alert-list mappings
promotion and rollback history
```

The screening data plane will consume a compiled immutable runtime package rather than query PostgreSQL for every candidate.

## Acceptance gates

Phase 7C-A requires:

- strict Advanced XML namespace, Version 3, and schema-location recognition;
- XSD-scoped `ListID` resolution through `ListValues`;
- exact selection of `SDN List` and safe filtering of non-SDN entries;
- support for multiple profiles, identities, and sanctions entries under their XSD cardinalities;
- rejection of legacy XML, DOCTYPE, unknown top-level sections, duplicate IDs, unresolved list references, and malformed relationships;
- deterministic source manifest, canonical snapshot, catalog, and parity report;
- preservation of Unicode names and script metadata;
- UID, primary-name, entity-type, program, alias, address, and identifier parity evidence;
- unchanged provider-mode and Phase 7B OpenSanctions behavior;
- no network dependency in automated regression; and
- no live or third-party bytes committed to Git.
