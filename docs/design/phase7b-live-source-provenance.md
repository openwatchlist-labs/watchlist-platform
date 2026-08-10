# Phase 7B — Live-source acquisition and provenance

Phase 7B closes the gap between deterministic fixtures and locally acquired current list data. It does not commit or redistribute live OFAC or OpenSanctions data.

## Provenance of earlier tests

All OFAC and provider data committed before Phase 7B is synthetic:

- `test/fixtures/ofac/sdn/sdn-fixture*.xml` is a small OFAC-shaped XML fixture containing invented records.
- `test/fixtures/provider-entity/opensanctions-like-snapshot.json` is a hand-authored provider-shaped fixture containing invented entities.
- Phase 7A did not download an OpenSanctions export and did not invoke the OpenSanctions API.
- Phase 7B initially exercised legacy-shaped OFAC fixtures. Phase 7C-A retains those only through a hidden regression command; the public OFAC synchronization path supports Advanced XML only.

## Live-source boundary

`cmd/live-catalog-sync` exposes four supported subcommands:

```text
ofac
opensanctions
reproject-opensanctions
verify
```

Both live paths acquire from allowlisted HTTPS hosts, reject embedded credentials and unsafe redirects, enforce size limits, record source metadata and SHA-256, preserve advertised upstream checksums, write with atomic renames and mode `0600`, and store all source bytes under ignored local paths.

## Official OFAC synchronization

```bash
go run ./cmd/live-catalog-sync ofac \
  --output-dir var/live-catalogs/ofac-sdn
```

Outputs:

```text
var/live-catalogs/ofac-sdn/
  source/SDN_ADVANCED.XML
  source-manifest.json
  ofac-advanced-canonical.json
  ofac-sdn-catalog.json
```

The `ofac` subcommand accepts only OFAC Advanced XML Version 3. It preserves Unicode/script metadata in `ofac-advanced-canonical.json`; the live request path consumes the resulting deterministic catalog, never raw XML. Legacy `SDN.XML` parsing is test-only migration support.

## OpenSanctions synchronization

Non-commercial research mode must be selected explicitly:

```bash
go run ./cmd/live-catalog-sync opensanctions \
  --dataset us_ofac_sdn \
  --license-mode noncommercial \
  --output-dir var/live-catalogs/opensanctions-us-ofac-sdn
```

Commercial mode requires a delivery token:

```bash
export OPENSANCTIONS_DELIVERY_TOKEN='...'

go run ./cmd/live-catalog-sync opensanctions \
  --dataset us_ofac_sdn \
  --license-mode commercial \
  --output-dir var/live-catalogs/opensanctions-us-ofac-sdn
```

Outputs:

```text
var/live-catalogs/opensanctions-us-ofac-sdn/
  source/index.json
  source/entities.ftm.json
  source-manifest.json
  provider-snapshot.json
  provider-catalog.json
```

## FollowTheMoney adapter

`opensanctions-ftm-adapter/v0.1.2` consumes line-oriented FtM JSON with `id`, `schema`, `caption`, `datasets`, `referents`, and `properties`. It supports Person, Company, Organization, LegalEntity, PublicBody, Vessel, Airplane, and Aircraft targets. It resolves separate Address and Sanction entities, including source-scoped relation targets that point to a referent such as `ofac-54742` instead of the consolidated `NK-...` target ID. Source-scoped exports can also retain the authoritative OFAC UID only as a numeric `ofac-<UID>` target referent; the adapter projects those referents into OFAC memberships, ignores non-numeric OFAC relation identifiers, and merges duplicate lineage without losing sanction programs.

The adapter deliberately separates OFAC's source program codes from OpenSanctions' provider taxonomy. `Sanction.program` values such as `GLOMAG` or `RUSSIA-EO14024` populate the authoritative OFAC membership used for direct-list comparison. `Sanction.programId` values such as `US-GLOMAG` or `US-RUSHAR` are retained in the entity attribute `ofac_program_ids` and do not create false direct-list program differences.

For `us_ofac_sdn`, each projected target retains both:

```text
OFAC authoritative membership:
  source_id: ofac-sls
  list_id: SDN
  source_record_id: upstream recordId

Provider membership:
  source_id: opensanctions
  list_id: us_ofac_sdn
  source_record_id: OpenSanctions entity ID
```


### Re-project an existing verified OpenSanctions download

Adapter upgrades must not overwrite the original live acquisition manifest or re-label downloaded bytes as a local fixture. Re-project the already verified FtM file in place:

```bash
go run ./cmd/live-catalog-sync reproject-opensanctions \
  --manifest var/live-catalogs/opensanctions-us-ofac-sdn/source-manifest.json \
  --data var/live-catalogs/opensanctions-us-ofac-sdn/source/entities.ftm.json \
  --output-dir var/live-catalogs/opensanctions-us-ofac-sdn
```

This rewrites only `provider-snapshot.json` and `provider-catalog.json`. It does not download data and does not modify `source-manifest.json`, `source/index.json`, or `source/entities.ftm.json`.

## Verification and comparison

`verify` detects and strictly validates both `ofac-source-manifest/v1alpha1` and
`catalog-source-manifest/v1alpha1` before hashing the referenced bytes.

```bash
go run ./cmd/live-catalog-sync verify \
  --manifest var/live-catalogs/ofac-sdn/source-manifest.json \
  --data var/live-catalogs/ofac-sdn/source/SDN_ADVANCED.XML

go run ./cmd/live-catalog-sync verify \
  --manifest var/live-catalogs/opensanctions-us-ofac-sdn/source-manifest.json \
  --data var/live-catalogs/opensanctions-us-ofac-sdn/source/entities.ftm.json

go run ./cmd/provider-catalog compare \
  --provider var/live-catalogs/opensanctions-us-ofac-sdn/provider-catalog.json \
  --direct var/live-catalogs/ofac-sdn/ofac-sdn-catalog.json
```

A zero-link live comparison is a validation failure, not evidence that the catalogs are unrelated. A comparison in which every linked record has a program difference is also a validation warning because it usually indicates source-code/provider-taxonomy conflation. Re-project the provider catalog with adapter v0.1.2 before comparing catalogs created by earlier adapter versions. Catalog differences are provider-qualification evidence, not automatic merge instructions. Production deployments select official-list mode or provider mode; they do not require a runtime overlay.

## Regression policy

Automated validation remains offline and deterministic. It uses invented OFAC Advanced XML, historical legacy migration fixtures, and invented FtM JSON-lines that follow the public source shapes. Network access is opt-in and is not required for `go test ./...` or phase validation.
