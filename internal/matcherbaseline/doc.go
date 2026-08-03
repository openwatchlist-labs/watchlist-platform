// Package matcherbaseline implements the real fuzzy/token-alignment/
// phonetic name-matching engine used for retrospective analysis of
// matches the live system has already produced (see docs/ARCHITECTURE.md
// - this is intentionally NOT the retrieval path production
// cmd/screening-api uses; that goes through internal/runtimemmapclient
// for exact/prefix/identifier lookup only).
//
// Provider reads a compiled runtime package (built via
// cmd/ofac-runtime -command compile from an internal/ofaccatalog
// document) and scores candidate names against a query using a weighted
// combination of edit-distance, token-alignment, ordered-token, phonetic,
// and length-similarity features (see similarity.go), after normalizing
// and folding both strings (see normalize.go) - including nickname/
// diminutive canonicalization and legal-entity-suffix dropping, both
// added as targeted fixes verified against internal/adversarialtest's
// scenario bank.
//
// Exercised directly by cmd/matcher-run.
package matcherbaseline
