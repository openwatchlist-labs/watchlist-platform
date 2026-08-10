# Phase 2A: OFAC ingestion and direct-list catalogs

Phase 2A adds official SDN source acquisition, immutable source manifests and archives, strict legacy `SDN.XML` parsing, deterministic direct-list projection, an exact-only provider adapter, and generation swap/drain contracts.

## Contracts

```text
ofac-source-manifest/v1alpha1
ofac-source-package/v1alpha1
ofac-direct-list-catalog/v1alpha1
catalog-runtime-generation/v1alpha1
```

## Acquisition

`cmd/ofac-ingest` supports the official SLS HTTPS export or a local controlled copy. HTTP mode requires HTTPS, approved OFAC/Treasury hosts, bounded same-trust redirects, an explicit User-Agent, a 60-second timeout, a 128 MiB limit, and SHA-256 over received bytes.

With `--archive-dir`, immutable artifacts are stored at:

```text
<archive>/ofac-sdn/<content-sha256>/source.xml
<archive>/ofac-sdn/<content-sha256>/<manifest-id>.manifest.json
```

Existing content is never overwritten.

## Strict parsing

The parser requires the current SLS legacy XML namespace and rejects DOCTYPE/directives, unexpected processing instructions, unsupported namespaces, unknown schema elements, duplicate UIDs, malformed linked records, and declared record-count mismatches.

The legacy XML contains the complete SDN list. Advanced XML is a later adapter for richer multilingual and metadata structures.

## Direct-list projection

Each OFAC primary UID becomes `ofac:sdn:<UID>`. Alias, address, identifier, program, date, nationality, citizenship, vessel, and source-assertion lineage is retained. Records are sorted by numeric UID. The catalog checksum uses stable source-content and projected-record material, excluding acquisition timestamps, so identical bytes compile identically.

## Matching boundary

The Phase 2A provider performs exact comparisons only: normalized primary name, alias/transliteration value, supported identifier, date, address component, country, or full remarks equality. It performs no edit-distance, phonetic, partial-token, or probabilistic matching.

## Commands

```bash
go run ./cmd/ofac-ingest \
  --input test/fixtures/ofac/sdn/sdn-fixture.xml \
  --source-url https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML \
  --acquired-at 2026-07-13T16:30:00Z \
  --output catalog
```

```bash
go run ./cmd/matcher-run \
  --provider ofac-direct \
  --catalog test/golden/ofac/ofac-sdn-fixture.catalog.json \
  --input requests --output results \
  test/golden/iso20022/pacs008/pacs008-basic.matcher-requests.json
```

Fixtures are synthetic and are not actual OFAC designations. Phase 2A does not automatically activate downloads, consume deltas, parse advanced XML, ingest non-SDN lists, implement production fuzzy matching, or make sanctions decisions.
