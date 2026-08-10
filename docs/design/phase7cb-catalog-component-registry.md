# Phase 7C-B — Stable catalog component registry and activation metadata

Phase 7C-B introduces the control-plane identity that later alert-list mappings will target. It does not put watchlist entities, aliases, addresses, or identifiers into PostgreSQL. Full catalogs remain immutable artifacts and Phase 8A will compile them into the Rust memory-mapped runtime package.

## Stable component identity

A component ID is derived only from:

- registry namespace;
- organization-controlled `component_key`.

Provider names, provider dataset references, catalog versions, and artifact paths are deliberately excluded. A provider may rename a dataset without changing the platform component that alert mappings reference. The changed provider reference is recorded in a new catalog-version record and must pass later promotion governance.

Supported component modes are:

- `official_list` — currently OFAC Advanced XML Version 3 only;
- `provider` — any provider implementing the provider-neutral catalog contract.

Hybrid overlay is not a product runtime mode.

## Version registration

Each immutable catalog artifact is represented by `catalog-component-version/v1alpha1`. Metadata includes:

- stable component ID;
- source catalog ID and version;
- catalog and artifact SHA-256 values;
- artifact URI;
- source-manifest identity;
- record count and producer version;
- official or provider source descriptor;
- registration actor and time.

For official OFAC versions, validation permits only `source_format=ofac_advanced_xml`. For provider versions, `provider_component_ref` is version metadata and is never part of stable component identity.

## Activation metadata

Activations are append-only, hash chained, and globally sequenced within a registry namespace. Each component has an independent monotonically increasing epoch and one atomic active pointer.

Activation supports an optional expected-current-version precondition. This prevents stale administrators or workers from overwriting a newer activation. Rollback is represented as a new activation and may target only a version that was previously active.

## Persistence boundary

The reference file store is deterministic and supports local validation without infrastructure:

```text
var/catalog-registry/<namespace>/
  registry.json
  components/<component-id>.json
  versions/<version-id>.json
  activations/<sequence>-<activation-id>.json
  active/<component-id>.json
```

The embedded PostgreSQL migration creates only control-plane tables:

- `catalog_registry_namespaces`;
- `catalog_components`;
- `catalog_component_versions`;
- `catalog_component_activations`;
- `active_catalog_component_versions`.

It intentionally creates no entity, alias, address, identifier, or relationship tables.

## CLI

```bash
STORE=var/catalog-registry/demo-bank

go run ./cmd/catalog-registry init \
  --store "$STORE" \
  --namespace demo-bank

go run ./cmd/catalog-registry register-component \
  --store "$STORE" \
  --input test/fixtures/catalog-registry/official-ofac-sdn.component.json

go run ./cmd/catalog-registry register-version \
  --store "$STORE" \
  --input test/fixtures/catalog-registry/official-ofac-sdn-v1.version.json

go run ./cmd/catalog-registry activate \
  --store "$STORE" \
  --component-id catalog_component_ed835720fdb2b3a505927488 \
  --version-id catalog_version_10c16906983641525bcc85a4 \
  --actor catalog-admin \
  --reason "approved initial activation"

go run ./cmd/catalog-registry verify --store "$STORE"
```

`catalog-registry postgres-schema` prints the embedded PostgreSQL migration for deployment tooling.

## Phase boundary

Phase 7C-B provides stable component identity, immutable version registration, activation pointers, rollback metadata, and PostgreSQL-compatible control-plane persistence. Phase 7C-C will add exact alert-list mappings from `source_system + raw_list_name` to these stable component IDs.
