package normalization

import "testing"

// FuzzNormalize throws arbitrary/malformed input at Normalize, seeded
// with real adversarial-scenario queries (homoglyphs, zero-width
// spaces, RTL overrides, mixed scripts - see
// test/fixtures/adversarial/adversarial-scenarios-v*.json) plus a few
// hand-picked pathological cases (very long strings, raw control
// characters, invalid UTF-8 byte sequences). Go's fuzzing engine then
// mutates these to explore inputs nobody thought to try by hand -
// exactly the class of bug issue #17 is concerned about: this package
// processes arbitrary third-party name/address data, so a
// crash/panic on malformed input is a real production risk, not just a
// theoretical one.
//
// The only invariant checked is "does not panic" - Normalize's own
// contract already allows returning an error for any input (including
// an unrecognized profile), so a returned error is expected, correct
// behavior for plenty of fuzzed inputs, not a finding. What would be a
// finding is Normalize panicking instead of returning an error, or
// hanging (a fuzz run timing out on a single input, which the Go
// fuzzing engine also detects and reports as a failure).
//
// Run locally with a longer budget than CI's default single pass:
//
//	go test ./internal/normalization/ -fuzz=FuzzNormalize -fuzztime=30s
func FuzzNormalize(f *testing.F) {
	profiles := []string{
		ProfileNone, ProfilePartyName, ProfileBIC, ProfileLEI, ProfileIBAN,
		ProfileCountryCode, ProfileAddress, ProfileContextText, ProfileReference,
		ProfileIdentifier, ProfileAmount, ProfileDate, ProfileDateTime,
	}
	queries := []string{
		"ACME IMPORTS LLC",
		"0RION TRADING GMBH",           // digit-zero substituted for letter-O
		"ACME IM\u0420ORTS LLC",        // Cyrillic Er, visually near "P"
		"ACME \u0406MPORTS LLC",        // Cyrillic I
		"AC\u200bME IMPORTS LLC",       // zero-width space (U+200B)
		"ACME \u202eSTROPMI\u202c LLC", // RTL override (U+202E) + PDF (U+202C)
		"JOSÉ MARIA EXAMPLON",
		"NGUYEN VAN V\u0129 D\u0169NG", // Vietnamese tone diacritics
		"CHEN, WEI EXAMPLE",
		"MR BILL J EXAMPLETON ESQ",
	}
	for _, p := range profiles {
		for _, q := range queries {
			f.Add(p, q)
		}
	}
	// Hand-picked pathological cases beyond the adversarial bank's own
	// scenarios, specifically targeting the "nobody thought to try this"
	// gap fuzzing is meant to close.
	f.Add(ProfilePartyName, "")
	f.Add(ProfilePartyName, "   ")
	f.Add(ProfilePartyName, string([]byte{0xff, 0xfe, 0x00, 0x01})) // invalid UTF-8
	f.Add(ProfilePartyName, "\x00\x01\x02\x03")                     // raw control characters
	f.Add(ProfilePartyName, "A")
	f.Add("bogus-profile-name", "ACME IMPORTS")
	f.Add("", "")
	f.Add(ProfilePartyName, string(make([]byte, 100000))) // pathologically long (100KB of NUL bytes)

	f.Fuzz(func(t *testing.T, profile, value string) {
		// No recover() wrapper here on purpose: Go's fuzzing engine
		// already catches a panic in the fuzz function natively and
		// auto-saves a minimized reproducer under testdata/fuzz/ -
		// wrapping this in our own recover() would intercept the panic
		// first and lose that built-in reproduction mechanism.
		_, _ = Normalize(profile, value)
	})
}
