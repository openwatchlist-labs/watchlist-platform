# Phase 7C-C: exact alert-list mapping

## Purpose

Phase 7C-C resolves the list name carried by an external alert to a stable Phase 7C-B catalog component. It does not infer provider datasets, fuzzy-match list names, or alter the raw alert value.

```text
(source_system_id, raw_list_name)
                ↓ exact lookup
stable catalog component ID
                ↓ active pointer
active immutable catalog version
```

The same mapping contract applies to both supported runtime modes:

- `official_list`, including OFAC Advanced XML Version 3; and
- `provider`, including any organization-selected provider adapter.

A mapping never stores an OpenSanctions, World-Check, Dow Jones, or other provider dataset identifier. Provider component references remain catalog-version metadata behind the stable component ID.

## Exact-match contract

`source_system_id` is a controlled lowercase identifier matching:

```text
^[a-z0-9][a-z0-9._-]{0,127}$
```

`raw_list_name` is the original UTF-8 alert value. Matching is:

- case-sensitive;
- whitespace-sensitive;
- Unicode-code-point preserving;
- free of trimming, alias expansion, fuzzy matching, phonetics, or transliteration.

For example, these are three independent keys:

```text
fircosoft-prod / WLS_OFAC_001
fircosoft-prod / wls_ofac_001
actimize-prod  / WLS_OFAC_001
```

The PostgreSQL schema uses `COLLATE "C"` for the source-system and raw-list-name columns so the relational control plane follows the same exact equality contract.

## Stable identity and versioning

A stable mapping ID is content-addressed from:

```text
organization namespace
source_system_id
raw_list_name
```

It does not include a catalog component or provider reference. A later organization-approved cutover from an official component to a provider component therefore creates a new immutable mapping version under the same mapping ID.

Each mapping version records:

```text
action: bind or retire
stable component ID for bind
UTC effective_from
optional UTC effective_to
superseded mapping version
reason
actor and creation time
global sequence
previous event hash and event hash
version checksum
```

New versions for one exact key must advance `effective_from`. A later version takes precedence from its effective time. A `retire` version ends the mapping without mutating prior evidence.

## Resolution outcomes

A successful result includes the mapping identity and the active catalog artifact metadata:

```text
status: resolved
component ID and component key
catalog mode
active catalog version ID
catalog checksum
artifact URI
```

A non-resolved result is retained with an explicit blocker:

| Status | Review blocker |
|---|---|
| `unmapped` | `ALERT_LIST_MAPPING_REQUIRED` |
| `not_effective` | `ALERT_LIST_MAPPING_NOT_EFFECTIVE` |
| `expired` | `ALERT_LIST_MAPPING_EXPIRED` |
| `retired` | `ALERT_LIST_MAPPING_RETIRED` |
| `component_missing` | `CATALOG_COMPONENT_NOT_FOUND` |
| `component_retired` | `CATALOG_COMPONENT_RETIRED` |
| `catalog_not_active` | `CATALOG_COMPONENT_NOT_ACTIVE` |

An unresolved list reference never becomes a clean screening result.

## Active catalog availability

Exact mapping alone is insufficient. Resolution also verifies that:

1. the stable component exists in the Phase 7C-B registry;
2. the component is active;
3. an active catalog-version pointer exists; and
4. the pointer resolves to immutable version metadata.

The mapping result references the active catalog package. It does not load or duplicate names, aliases, identifiers, addresses, or provider entities.

## Local reference store

The deterministic local store is suitable for fixtures, offline administration, and migration rehearsal:

```text
var/alert-list-mappings/<namespace>/
  registry.json
  mappings/<mapping-id>.json
  versions/<sequence>-<mapping-version-id>.json
```

All mapping keys and versions are immutable. The registry snapshot is atomically replaced and validated against the immutable files.

## PostgreSQL control plane

The embedded migration adds only:

```text
alert_list_mapping_namespaces
alert_list_mapping_keys
alert_list_mapping_versions
```

`component_id` references the Phase 7C-B `catalog_components` table. Full watchlist data remains outside PostgreSQL as immutable artifacts for the Phase 8A Rust memory-mapped runtime.

## CLI

Initialize a mapping registry:

```bash
go run ./cmd/alert-list-mapping init \
  --store var/alert-list-mappings/demo-bank \
  --namespace demo-bank
```

Register an exact mapping version:

```bash
go run ./cmd/alert-list-mapping register \
  --store var/alert-list-mappings/demo-bank \
  --catalog-registry-store var/catalog-registry/demo-bank \
  --input mapping.json
```

Resolve one alert list reference:

```bash
go run ./cmd/alert-list-mapping resolve \
  --store var/alert-list-mappings/demo-bank \
  --catalog-registry-store var/catalog-registry/demo-bank \
  --source-system-id fircosoft-prod \
  --raw-list-name WLS_OFAC_001 \
  --at 2026-07-21T12:00:00Z
```

Preflight a batch before importing alerts:

```bash
go run ./cmd/alert-list-mapping resolve-batch \
  --store var/alert-list-mappings/demo-bank \
  --catalog-registry-store var/catalog-registry/demo-bank \
  --input alerts.json
```

The batch output preserves input order and reports counts for every resolution status.

## Phase boundary

Phase 7C-C provides mapping metadata and deterministic resolution. It does not yet provide:

- HTTP mapping administration;
- tenant authentication or authorization;
- case persistence;
- a UI;
- provider refresh impact approval; or
- full screening catalog database storage.

Provider component-change impact gates, promotion, activation, and rollback governance remain Phase 7C-D.
