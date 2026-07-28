# Synthetic OFAC Advanced XML golden artifacts

These artifacts are generated only from `test/fixtures/ofac/advanced/sdn-advanced-fixture.xml`.
The fixture contains invented names and records and is not an OFAC sanctions publication.

Regenerate deterministically with:

```bash
go run ./cmd/live-catalog-sync ofac \
  --input test/fixtures/ofac/advanced/sdn-advanced-fixture.xml \
  --acquired-at 2026-07-14T15:00:00Z \
  --output-dir /tmp/ofac-advanced-golden \
  --legacy-catalog test/golden/ofac/ofac-sdn-fixture.catalog.json
```

The committed golden files prove Advanced XML version/namespace enforcement, XSD-scoped list selection, UID-scoped canonical projection, Unicode/script preservation, compatibility catalog production, deterministic source statistics, and migration parity reporting without requiring network access or redistributing live list data.
