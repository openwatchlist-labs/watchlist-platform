package matcherbaseline

import "testing"

// TestScorePairMatchesInternalScoreName proves ScorePair (ADR-0008
// addendum AD1) is a faithful, narrow wrapper over the package's existing
// fold+scoreName call shape -- the same one SearchWithDiagnostics already
// uses per candidate -- rather than a parallel, drifting implementation.
func TestScorePairMatchesInternalScoreName(t *testing.T) {
	profile := ThresholdProfile{
		ProfileID: "test", ThresholdBasisPoints: 7800, DiagnosticFloorBasisPoints: 6800,
		TokenAlignmentWeightBasisPoints: 3000, EditSimilarityWeightBasisPoints: 3000,
		OrderedTokenWeightBasisPoints: 1500, PhoneticWeightBasisPoints: 1500,
		LengthWeightBasisPoints: 1000, SingleTokenPenaltyBasisPoints: 700,
	}

	cases := []struct{ query, candidate string }{
		{"ACME IMPORTS", "ACME IMPROTS"},
		{"ACME IMPORTS", "ACME IMPORTS"},
		{"", "ACME"},
		{"Джордан Экзампл", "DZHORDAN EKZAMPL"},
	}

	for _, c := range cases {
		gotScore, gotEvidence, gotPenalty := ScorePair(c.query, c.candidate, profile)

		wantScore, wantFeatures, wantPenalty := scoreName(fold(c.query), fold(c.candidate), profile)
		if gotScore != wantScore || gotPenalty != wantPenalty {
			t.Fatalf("ScorePair(%q, %q) = (%d, _, %d), want (%d, _, %d)", c.query, c.candidate, gotScore, gotPenalty, wantScore, wantPenalty)
		}
		if len(gotEvidence) != len(wantFeatures) {
			t.Fatalf("ScorePair(%q, %q) returned %d evidence entries, want %d", c.query, c.candidate, len(gotEvidence), len(wantFeatures))
		}
		for i, f := range wantFeatures {
			e := gotEvidence[i]
			if e.Name != f.name || e.ScoreBasisPoints != f.score || e.WeightBasisPoints != f.weight || e.ContributionBasisPoints != f.contribution {
				t.Fatalf("ScorePair(%q, %q) evidence[%d] = %+v, want feature %+v", c.query, c.candidate, i, e, f)
			}
		}
	}

	// Sanity floor: an exact match, once folded, must score at the ceiling.
	if score, _, _ := ScorePair("ACME IMPORTS", "ACME IMPORTS", profile); score != 10000 {
		t.Fatalf("ScorePair on an identical pair = %d, want 10000", score)
	}
}
