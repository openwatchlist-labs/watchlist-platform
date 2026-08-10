# Phase 8A boundary — Rust memory-mapped catalog runtime

Phase 8A implements the Go-to-Rust data-plane boundary. Go owns source acquisition, parsing, canonical catalogs, provenance, stable component identity, exact alert-list mapping, provider refresh, promotion, and rollback. Rust owns deterministic binary index construction, package validation, read-only memory mapping, and bounded candidate retrieval.

```text
Go control plane
  validated official/provider catalog
  stable Phase 7C-B component identity
        |
        | runtime-catalog-input/v1alpha1
        v
Rust catalog compiler
  dependency-free deterministic compiler
  sectioned memory-mapped-catalog/v1alpha1
        |
        | immutable .owmmap artifact
        v
Rust runtime library
  validate once
  read-only memory map
  binary-search name and identifier indexes
```

The initial integration remains a separate process/library boundary rather than `cgo`. Phase 8A does not replace the existing Go matcher or decision pipeline. A later worker/service phase will attach a versioned process protocol and generation-stamped screening execution.

The package contains checked metadata, a UTF-8 source-value pool, fixed-width records, primary/alias name indexes, and typed exact-identifier indexes. Readers reject unknown versions, integer overflow, non-canonical or overlapping sections, invalid UTF-8, checksum mismatch, bad record references, unsorted indexes, and trailing bytes.

The r1 normalization profile intentionally normalizes ASCII only and preserves non-ASCII UTF-8 exactly. This prevents premature transliteration or source-value loss. Future multilingual indexes are derived additions under a new normalization-profile checksum.

The full contract and commands are documented in [Phase 8A](phase8a-rust-memory-mapped-runtime.md).

## Phase 8B process protocol

Phase 8B realizes the planned process boundary with a persistent `catalog-mmap worker`. Each worker validates and maps one immutable package, emits package lineage at startup, and accepts bounded record, name/prefix, and typed-identifier requests over a hexadecimal UTF-8 line protocol. The Go HTTP service verifies the worker lineage against the exact active Phase 7C-B component/version before routing requests. No `cgo` boundary is introduced.
