package matcherbaseline

import "testing"

// FuzzFold and FuzzScoreName throw arbitrary/malformed input at this
// package's core name-normalization and name-scoring functions. Written
// as same-package tests (package matcherbaseline, not
// matcherbaseline_test) deliberately - fold() and scoreName() are
// unexported, and they're the actual functions doing the
// "normalization/matching" work issue #17 is concerned about, not the
// exported Provider.Search() wrapper (which would need a compiled
// runtime catalog loaded per fuzz iteration - far too slow for the
// thousands of iterations/second a fuzzer runs, and it's the string
// processing underneath, not the catalog lookup, that's the actual
// crash/panic risk surface for arbitrary third-party name data).
//
// Seeded with real adversarial-scenario queries (homoglyphs, zero-width
// spaces, RTL overrides - see
// test/fixtures/adversarial/adversarial-scenarios-v*.json) plus
// hand-picked pathological cases. Only invariant checked is "does not
// panic" for FuzzFold; FuzzScoreName additionally checks the returned
// score always stays within the documented [0, 10000] basis-point range,
// since a score escaping that range would silently corrupt every
// downstream threshold comparison without ever panicking - a
// correctness bug fuzzing can catch that a pure crash-hunt would miss.
//
// Run locally with a longer budget than CI's default single pass:
//
//	go test ./internal/matcherbaseline/ -fuzz=FuzzFold -fuzztime=30s
//	go test ./internal/matcherbaseline/ -fuzz=FuzzScoreName -fuzztime=30s
func seedQueries() []string {
	return []string{
		"ACME IMPORTS LLC",
		"0RION TRADING GMBH",
		"ACME IM\u0420ORTS LLC",
		"ACME \u0406MPORTS LLC",
		"AC\u200bME IMPORTS LLC",
		"ACME \u202eSTROPMI\u202c LLC",
		"JOSÉ MARIA EXAMPLON",
		"NGUYEN VAN V\u0129 D\u0169NG",
		"CHEN, WEI EXAMPLE",
		"MR BILL J EXAMPLETON ESQ",
		"MOHAMED EL-EXAMP",
		"A.C.M.E. IMPORTS, LLC.",
	}
}

func FuzzFold(f *testing.F) {
	for _, q := range seedQueries() {
		f.Add(q)
	}
	f.Add("")
	f.Add("   ")
	f.Add(string([]byte{0xff, 0xfe, 0x00, 0x01})) // invalid UTF-8
	f.Add("\x00\x01\x02\x03")                     // raw control characters
	f.Add(string(make([]byte, 100000)))           // pathologically long

	f.Fuzz(func(t *testing.T, value string) {
		// No recover() wrapper on purpose - Go's fuzzing engine already
		// catches a panic natively and auto-saves a minimized reproducer
		// under testdata/fuzz/, which our own recover() would intercept
		// and lose.
		_ = fold(value)
	})
}

func FuzzScoreName(f *testing.F) {
	queries := seedQueries()
	for i, q := range queries {
		// Pair each seed with the next one (wrapping around) so the seed
		// corpus includes genuinely different query/candidate pairs, not
		// just a string against itself.
		f.Add(q, queries[(i+1)%len(queries)])
	}
	f.Add("", "")
	f.Add("A", "")
	f.Add("", "A")
	f.Add(string([]byte{0xff, 0xfe}), "ACME IMPORTS")
	f.Add(string(make([]byte, 50000)), string(make([]byte, 50000)))

	profile := ThresholdProfile{
		ProfileID: "fuzz", ThresholdBasisPoints: 7800, DiagnosticFloorBasisPoints: 6800,
		TokenAlignmentWeightBasisPoints: 3000, EditSimilarityWeightBasisPoints: 3000,
		OrderedTokenWeightBasisPoints: 1500, PhoneticWeightBasisPoints: 1500,
		LengthWeightBasisPoints: 1000, SingleTokenPenaltyBasisPoints: 700,
	}

	f.Fuzz(func(t *testing.T, query, candidate string) {
		score, _, _ := scoreName(fold(query), fold(candidate), profile)
		if score < 0 || score > 10000 {
			t.Fatalf("scoreName returned %d, outside the documented [0, 10000] basis-point range, for query=%q candidate=%q", score, query, candidate)
		}
	})
}
