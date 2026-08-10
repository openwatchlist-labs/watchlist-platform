package matcherbaseline

// transliterationVariantToCanonical canonicalizes common
// transliteration-only prefix variants to a single form, the same
// drop-vs-canonicalize distinction documented in nicknames.go: unlike a
// corporate-suffix (where no form is more "correct" than another and all
// are dropped), these ARE the same underlying element just romanized
// differently, so canonicalizing to one form (rather than dropping) is
// the right move - the same way BILL canonicalizes to WILLIAM rather
// than being dropped.
//
// Real motivating case (issue #32, combined-01-transliteration-plus-
// truncation): "MOHAMED EL-EXAMP" against catalog entry
// "Muhammad Al-Exampli". The individual, non-stacked scenarios this case
// combines already pass without this map -
// translit-05-stress-prefix-variant ("MOHAMED EL-EXAMPLI", full word) and
// incomplete-05-truncated-name ("MUHAMMAD AL-EXAMP", exact AL- prefix)
// both succeed today. The combined case only fails because THREE
// independent differences (MOHAMED/MUHAMMAD spelling, EL/AL prefix,
// EXAMP/EXAMPLI truncation) stack at once, and el/al specifically scores
// only 5000 basis points of edit similarity as a bare 2-character token
// pair - low enough, on top of the other two differences, to pull the
// heaviest-weighted feature (token_alignment_similarity, per-token
// best-match average) below threshold. Canonicalizing el<->al directly
// addresses that specific weak link rather than loosening any
// system-wide scoring threshold, which would have a much larger and
// harder-to-evaluate blast radius across every other scoring call in
// this matcher.
//
// Scope, deliberately narrow: only "EL", evidenced by this one real
// scenario. NOT a general-purpose transliteration-equivalence table -
// other variants (e.g. IL-, AR-, or non-Arabic-name prefix conventions)
// would need their own concrete evidence and their own review, not a
// speculative expansion alongside this one.
var transliterationVariantToCanonical = map[string]string{
	"EL": "AL",
}

// canonicalizeTransliterationVariant returns the canonical form of a
// transliteration-variant token, or the token unchanged if it isn't one.
func canonicalizeTransliterationVariant(t string) string {
	if canonical, ok := transliterationVariantToCanonical[t]; ok {
		return canonical
	}
	return t
}
