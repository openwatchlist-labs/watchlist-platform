// Package normalization does deliberately minimal field-level string
// normalization (whitespace collapsing, case-folding) per a named
// profile (party name, IBAN, country code, etc.) - no diacritic
// stripping, no Unicode-confusable folding, no phonetic logic. That
// deeper, name-specific normalization (fold, nickname canonicalization,
// legal-entity-suffix handling) lives one layer up, in
// internal/matcherbaseline - this package is intentionally the shallow,
// general-purpose layer underneath it, shared by non-name fields too.
package normalization
