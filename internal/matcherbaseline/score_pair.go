package matcherbaseline

import "github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"

// ScorePair scores one caller-supplied (query, candidate) pair against a
// threshold profile. It is the same fold+scoreName call shape
// SearchWithDiagnostics already makes per candidate
// (provider.go:84,94,100), addressed at one caller-supplied pair instead of
// a whole scanned ofacruntime.RuntimePayload.
//
// This is the mechanism ADR-0008's addendum, AD1, decided on: a narrow
// exported surface over the existing unexported fold/scoreName, rather than
// synthesizing a per-request RuntimePayload to satisfy ofacruntime's
// compiled-catalog provenance validator (Exact/SourceAssertions) for live
// retrieval candidates that were never compiled from a source list.
func ScorePair(query, candidate string, profile ThresholdProfile) (score int, evidence []matcherprovider.FeatureEvidence, penalty int) {
	q := fold(query)
	c := fold(candidate)
	s, features, p := scoreName(q, c, profile)
	for _, f := range features {
		evidence = append(evidence, matcherprovider.FeatureEvidence{
			Name:                    f.name,
			ScoreBasisPoints:        f.score,
			WeightBasisPoints:       f.weight,
			ContributionBasisPoints: f.contribution,
		})
	}
	return s, evidence, p
}
