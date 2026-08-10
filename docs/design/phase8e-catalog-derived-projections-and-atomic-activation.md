# Phase 8E — catalog-derived projection packages and atomic scoring activation

Phase 8E removes the independently maintained projection registry introduced in
Phase 8D. Candidate projections are now compiled from the same canonical record
feed and catalog descriptor that produce the active mmap catalog package.

## Projection package

`cmd/projection-package compile` consumes:

1. a strict `openwatchlist.catalog-package-descriptor.v1` document;
2. a strict `openwatchlist.canonical-projection-input.v1` record stream; and
3. an output object directory.

The descriptor binds provider, catalog, component, version, exact catalog file
path and SHA-256, normalization profile, record count, retrievable projection
count, and a checksum of all retrievable candidate IDs. The compiler verifies
the catalog bytes before it emits anything.

Output is a checksum-addressed directory containing:

- `manifest.json` — catalog binding, counts, coverage checksum and payload SHA;
- `projections.json` — the bounded Phase 8D-compatible scoring registry;
- `FILES.sha256` — exact file checksums; and
- `PACKAGE.sha256` — SHA-256 of `FILES.sha256`, also used as the directory name.

Identical canonical input produces byte-identical package content. Candidate
IDs and all projected attributes are normalized, deduplicated and sorted. A
record that is not retrievable is never projected. No full catalog row, source
document, address narrative or sanctions-program narrative is included.

## Atomic activation tuple

`cmd/scoring-activation activate` validates and atomically publishes one tuple:

- exact catalog package path and SHA-256;
- catalog component ID and version;
- exact projection package SHA-256 and payload SHA-256;
- projection count and candidate coverage checksum;
- exact scoring policy ID, version and canonical SHA-256; and
- one shared normalization profile.

The transaction writes an immutable activation document, a pending journal and
then `active.json` using fsync plus atomic rename. The pending journal is removed
only after the active pointer is durable. `recover` completes a durable target
or restores the previous activation. `rollback` validates the prior immutable
tuple before moving the pointer.

Activation IDs cannot be reused with different bytes.

## Phase 8E screening front door

`cmd/screening-api-v8e` loads only the active tuple. It derives the Phase 8D
policy and projection paths from that tuple and refuses startup if catalog,
projection or policy bytes are absent, tampered, stale or incompatible.

Every readiness and screening response includes `activation_tuple` with catalog,
projection and policy checksums. The front door validates the active tuple on
every screening request. A pointer change requires restart, preventing one
process from mixing candidates or idempotent responses across activation
versions.

Phase 8B responses must carry lineage matching the active provider, catalog,
component, component version, activation ID and normalization profile. Candidate
retrieval from an inactive catalog version is blocked before projection lookup.

## Operation

Compile a package:

```bash
go run ./cmd/projection-package compile \
  --catalog-descriptor var/catalogs/ofac/sdn/catalog-descriptor.json \
  --input var/catalogs/ofac/sdn/canonical-projection-input.json \
  --output-root var/projection-packages
```

Activate a tuple:

```bash
go run ./cmd/scoring-activation activate \
  --state-dir var/scoring-activation \
  --activation-id ofac-sdn-20260714-r1 \
  --catalog-descriptor var/catalogs/ofac/sdn/catalog-descriptor.json \
  --projection-package var/projection-packages/<projection-package-sha256> \
  --policy configs/scoring/candidate-scoring-r1.json
```

Inspect or recover:

```bash
go run ./cmd/scoring-activation status --state-dir var/scoring-activation
go run ./cmd/scoring-activation recover --state-dir var/scoring-activation
go run ./cmd/scoring-activation rollback --state-dir var/scoring-activation
```

Run the public front door after the private Phase 8B retrieval backend:

```bash
go run ./cmd/screening-api-v8e serve \
  --config configs/scoring-activation/phase8e-example.json
```

The checked-in example uses fixture activation state only. Production must use a
writable state directory and production catalog/projection packages.

## Explicit non-goals

Phase 8E does not make a regulatory clearance, alert disposition, analyst
recommendation, case decision or sanctions determination. It does not place full
catalog records in PostgreSQL or in API responses.
