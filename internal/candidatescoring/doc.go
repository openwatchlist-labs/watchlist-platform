// Package candidatescoring scores a bounded, already-retrieved candidate
// set for a screening item using corroborating evidence (date of birth,
// identifiers, jurisdiction) - it does not search a catalog itself. In
// the live production path, the candidates it scores come from
// internal/runtimemmapclient's exact/prefix/identifier lookup against the
// Rust-compiled catalog-mmap runtime (see docs/ARCHITECTURE.md); this
// package is what turns a raw retrieval hit into a confidence-scored
// result for downstream false-positive classification and policy
// evaluation.
//
// Imported by internal/screeningapi, internal/scoringactivation, and
// internal/projectionpackage; exposed directly via cmd/candidate-score.
package candidatescoring
