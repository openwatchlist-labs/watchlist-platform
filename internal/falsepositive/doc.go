// Package falsepositive classifies alert/match observations against known
// false-positive patterns - substring collisions (e.g. "SCUBA" containing
// "CUBA"), common-name ambiguity, and similar recurring, low-signal
// patterns - producing a ClassificationBatch. This runs downstream of
// candidate retrieval and scoring, and its output feeds
// internal/policyengine's disposition decisions directly (policyengine
// imports this package).
//
// See test/fixtures/false-positive/pattern-observations.json and
// test/golden/false-positive/ for the canonical worked examples, and
// cmd/false-positive-classify for the CLI entrypoint.
package falsepositive
