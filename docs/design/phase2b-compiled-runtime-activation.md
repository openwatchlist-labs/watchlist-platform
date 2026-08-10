# Phase 2B: compiled OFAC runtime packages and activation records

Phase 2B moves the validated Phase 2A direct-list catalog into a portable, deterministic runtime artifact and connects that artifact to audited activation, rollback, generation leasing, and candidate-result stamping.

## Contracts

```text
ofac-compiled-runtime/v1alpha1
compiled-catalog-package-manifest/v1alpha1
compiled-catalog-package-info/v1alpha1
catalog-readiness-report/v1alpha1
catalog-generation-stamp/v1alpha1
catalog-active-pointer/v1alpha1
catalog-activation-record/v1alpha1
catalog-rollback-record/v1alpha1
```

## Portable package format

The `.owpcat` artifact is architecture-neutral and contains:

```text
8-byte magic: OWPCAT01
uint64 big-endian manifest length
strict JSON package manifest
uint64 big-endian payload length
strict JSON compiled runtime payload
```

The payload is not the raw OFAC XML and is not a copy of the Phase 2A catalog. It is a canonical exact-match index compiled from the direct-list catalog. Entries are keyed by route and normalized query value and retain the provider record, entity type, matched value, attributes, and OFAC source assertion needed to reproduce Phase 2A exact-only results.

The package contains no build timestamp. Compiling the same validated catalog with the same compiler version produces byte-identical artifacts, package IDs, and package checksums. Operational compilation and activation timestamps live in readiness and activation records rather than contaminating package identity.

## Package integrity

The loader validates:

- package magic and bounded framing;
- strict manifest JSON with unknown-field rejection;
- content-addressed package ID;
- whole-artifact SHA-256;
- payload size and SHA-256;
- strict payload JSON;
- canonical index ordering and duplicate rejection;
- record and index-entry counts;
- provider descriptor and catalog lineage; and
- source-manifest identity.

Any trailing bytes, framing error, payload mutation, manifest mutation, or lineage mismatch rejects the entire artifact.

## Readiness

A package cannot activate until a readiness report is `ready=true`. Phase 2B checks:

```text
artifact_integrity
manifest_contract
payload_integrity
runtime_index
provider_descriptor
source_lineage
record_count
```

Readiness reports are immutable, content-addressed records. They identify the package, whole-artifact checksum, catalog version/checksum, source manifest, check time, and individual check results.

Production phases can add resource-budget checks, canary probes, signature verification, worker compatibility, and distributed quorum without changing the package or generation contracts.

## Activation state

The file-backed control-plane state is:

```text
<state>/
  packages/<package-id>.owpcat
  readiness/<readiness-id>.json
  activations/<activation-id>.json
  rollbacks/<rollback-id>.json
  active.json
```

Packages and readiness records use immutable create semantics. `active.json` is replaced by write, sync, and atomic rename while an exclusive activation lock is held.

The active pointer is a control-plane record. Screening workers still perform an in-process atomic pointer swap through `catalogruntime.Registry`. Each request acquires a lease and remains pinned to the generation it started with until release.

## Activation record

An activation record contains:

```text
action
readiness report ID
activation timestamp
previous generation, when present
new active generation
```

The generation stamp contains:

```text
generation ID
activation epoch
package ID and artifact checksum
catalog ID, version, and checksum
source-manifest ID
compilation timestamp
activation timestamp
```

Activation epochs are monotonic. A first activation receives epoch 1. Every later activation, including rollback, increments the epoch.

## Rollback record

Rollback does not mutate an older generation. The retained package is re-read, revalidated, and activated as a new generation. Its package, catalog, and source identities remain unchanged, while its generation ID and activation epoch are new.

The rollback record links:

```text
from generation
reason
activation record
retained target package
new rollback generation
```

## Candidate-result stamping

`matcherprovider.Runner` supports both legacy unstamped execution and generation-stamped execution. Stamped batches and every result include the same `runtime_generation` object.

Generation identity participates in candidate-result and result-batch IDs. The same request and candidates screened against two activation epochs therefore produce distinct auditable result IDs even if the catalog content is identical. Candidate IDs remain catalog/request-derived and do not change solely because of activation epoch.

The CLI accepts either a generation stamp or `catalog-active-pointer/v1alpha1`:

```bash
go run ./cmd/matcher-run \
  --provider ofac-runtime \
  --catalog var/runtime/ofac-sdn.owpcat \
  --generation-stamp var/runtime-state/active.json \
  --input requests \
  --output results \
  test/golden/iso20022/pacs008/pacs008-basic.matcher-requests.json
```

The CLI rejects a generation stamp whose package ID, package checksum, source manifest, or catalog lineage differs from the loaded runtime package.

## Commands

Compile a validated Phase 2A catalog:

```bash
go run ./cmd/ofac-runtime \
  --command compile \
  --catalog test/golden/ofac/ofac-sdn-fixture.catalog.json \
  --package /tmp/ofac-sdn.owpcat
```

Check readiness:

```bash
go run ./cmd/ofac-runtime \
  --command readiness \
  --package /tmp/ofac-sdn.owpcat \
  --compiled-at 2026-07-13T17:00:00Z \
  --checked-at 2026-07-13T17:01:00Z
```

Activate into a local control-plane state directory:

```bash
go run ./cmd/ofac-runtime \
  --command activate \
  --package /tmp/ofac-sdn.owpcat \
  --state-dir /tmp/openwatchlist-runtime \
  --compiled-at 2026-07-13T17:00:00Z \
  --checked-at 2026-07-13T17:01:00Z \
  --activated-at 2026-07-13T17:02:00Z
```

Rollback to a retained package:

```bash
go run ./cmd/ofac-runtime \
  --command rollback \
  --package /tmp/previous-ofac-sdn.owpcat \
  --state-dir /tmp/openwatchlist-runtime \
  --compiled-at 2026-07-13T17:00:00Z \
  --checked-at 2026-07-14T17:02:30Z \
  --activated-at 2026-07-14T17:03:00Z \
  --reason "rollback after canary regression"
```

## Explicit non-goals

Phase 2B does not add production fuzzy matching, cryptographic signing, distributed activation quorum, memory-mapped indexes, automatic OFAC polling, delta application, resource-aware canary policy, or a long-running screening service. It establishes the portable artifact and audit contracts those later capabilities will use.
