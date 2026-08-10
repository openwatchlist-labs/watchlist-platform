# Phase 8A — Rust compiled memory-mapped catalog package and runtime

Phase 8A establishes the first production-oriented catalog data plane. Go remains responsible for acquisition, provider adapters, canonical catalog validation, stable component registration, alert-list mapping, promotion, activation, and rollback. A dependency-free Rust compiler converts a deterministic Go-exported compiler input into an immutable sectioned package and a Rust reader opens the package through a read-only memory map on Unix platforms.

Phase 8A performs candidate retrieval only. It does not move similarity scoring, context evaluation, false-positive classification, policy decisions, review orchestration, RAG, or analyst-note generation into Rust.

## Boundary

```text
validated official or provider catalog JSON
  -> Go runtime-catalog-input exporter
  -> runtime-catalog-input/v1alpha1 (.owcin)
  -> Rust catalog-mmap compiler
  -> memory-mapped-catalog/v1alpha1 (.owmmap)
  -> Rust zero-copy package validation and candidate retrieval
```

The `.owcin` intermediary is deterministic, line-oriented, UTF-8, and hex-encodes all catalog values. It contains stable Phase 7C-B component identity, immutable catalog lineage, records, primary names, aliases, and exact identifiers. It rejects hybrid catalogs. Official catalogs must originate from OFAC Advanced XML Version 3.

## Binary package

The package begins with a fixed 64-byte header:

```text
8 bytes   magic OWMMAP01
u32 LE    format version 1
u32 LE    section count
u64 LE    whole file length
u64 LE    section-directory offset
32 bytes  SHA-256 of directory plus all sections
```

The checked section directory describes:

```text
metadata
UTF-8 string pool
fixed-width record table
normalized primary/alias name index
normalized exact-identifier index
```

Every section has a checked offset, length, entry size, and count. Sections must be canonical, contiguous, ordered, non-overlapping, and completely consume the file. The loader rejects unknown format versions, integer overflow, out-of-bounds references, invalid UTF-8, malformed fixed-width sections, unsorted indexes, unknown entity types, checksum mismatch, and trailing data before exposing records.

The metadata binds the package to:

```text
stable catalog component ID
catalog ID, version, checksum, and mode
source manifest or provider snapshot ID
source catalog schema
normalization profile
compiler-input SHA-256
compiler and package schema versions
```

The entire package also has an externally reportable SHA-256 used by Phase 7C-B catalog-version metadata and later activation readiness.

## Normalization profile

Phase 8A uses `openwatchlist-runtime-normalization/ascii-v1`.

Name keys:

- lowercase ASCII letters;
- preserve ASCII digits;
- collapse ASCII punctuation and whitespace to one space;
- preserve non-ASCII UTF-8 bytes exactly and case-sensitively.

Identifier keys:

- uppercase ASCII letters;
- preserve ASCII digits;
- remove ASCII punctuation and whitespace;
- preserve non-ASCII UTF-8 bytes exactly.

This conservative profile is intentionally not multilingual matching. Original Unicode source values remain in the package. A later profile may add script-aware normalization and transliteration as derived indexes without replacing those values.

## Candidate retrieval

The library supports:

```text
record ID lookup
exact normalized primary/alias name lookup
normalized name-prefix lookup
exact typed identifier lookup
```

Name and identifier indexes are sorted and searched with binary search. Result allocation is bounded by the caller-provided limit. A long-running worker opens and validates the memory map once and reuses the package view concurrently.

## Cross-language conformance

`internal/mmapcatalogcontract` is a Go reference encoder used only to freeze the binary contract. The committed fixture includes:

```text
test/fixtures/runtime-mmap/ofac-fixture.owcin
test/golden/runtime-mmap/ofac-fixture.owmmap
```

Rust compilation must produce a byte-identical package. The golden package checksum is:

```text
8c5e581ad36807c15a2ae00c5cb4e8b7f9154e208b369ff3227617294a473367
```

The Rust crate uses no third-party crates. This removes dependency resolution from package compilation and keeps the binary layout reviewable.

## Commands

Export an official catalog:

```bash
go run ./cmd/runtime-catalog-input \
  --catalog var/live-catalogs/ofac-sdn-advanced/ofac-sdn-catalog.json \
  --component-id catalog_component_<stable-id> \
  --output var/runtime-mmap/ofac-sdn.owcin
```

Compile and verify:

```bash
cargo run --release -p openwatchlist-catalog-mmap --bin catalog-mmap -- \
  compile \
  --input var/runtime-mmap/ofac-sdn.owcin \
  --output var/runtime-mmap/ofac-sdn.owmmap

cargo run --release -p openwatchlist-catalog-mmap --bin catalog-mmap -- \
  verify --package var/runtime-mmap/ofac-sdn.owmmap
```

Candidate retrieval:

```bash
cargo run --release -p openwatchlist-catalog-mmap --bin catalog-mmap -- \
  lookup-name --package var/runtime-mmap/ofac-sdn.owmmap --query 'ACME IMPORTS'

cargo run --release -p openwatchlist-catalog-mmap --bin catalog-mmap -- \
  lookup-name --package var/runtime-mmap/ofac-sdn.owmmap --query 'ACME' --prefix

cargo run --release -p openwatchlist-catalog-mmap --bin catalog-mmap -- \
  lookup-identifier \
  --package var/runtime-mmap/ofac-sdn.owmmap \
  --type 'Legal Entity Identifier' \
  --value '5493001KJTIIGC8Y1R12'
```

Microbenchmark a repeated mapped lookup:

```bash
cargo run --release -p openwatchlist-catalog-mmap --bin catalog-mmap -- \
  benchmark-name \
  --package var/runtime-mmap/ofac-sdn.owmmap \
  --query 'ACME' \
  --prefix \
  --iterations 100000
```

## Integration and activation

Phase 8A does not introduce `cgo` or change the Go matcher. The crate is a library plus CLI reference runtime. The next service phase can expose the same package through a versioned local protocol and stamp results with the existing `catalogruntime.GenerationStamp`.

Phase 7C-B remains authoritative for stable component identity, catalog-version registration, and active pointers. A compiled package is registered as the immutable artifact for a version only after compile, verify, deterministic conformance, and performance readiness gates pass. Rollback continues to move the active catalog-version pointer to a retained artifact; the package itself is immutable.

## Non-goals

Phase 8A does not provide:

- multilingual case folding or transliteration;
- fuzzy similarity scoring;
- context or geography scoring;
- final screening decisions;
- an HTTP or gRPC service;
- distributed worker activation;
- package signatures;
- Windows memory mapping as the primary validated runtime; or
- full catalog row storage in PostgreSQL.
