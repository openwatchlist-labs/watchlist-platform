// Package ofacruntime compiles a validated internal/ofaccatalog document
// into the portable, pure-Go .owpcat binary runtime package that
// internal/matcherbaseline reads (Compile), and loads one back (Load).
// No Rust dependency anywhere in this path - contrast with the separate
// Rust-compiled .owmmap format at runtime/catalog-mmap, which production
// cmd/screening-api uses via internal/runtimemmapclient. See
// docs/ARCHITECTURE.md's "Go/Rust boundary" section for the full
// three-format picture (.owpcat / .owmmap / .owcin), and issue #13 /
// internal/projectionpackage/rust_compat_test.go for what's independently
// verified about how the two compiled formats relate.
package ofacruntime
