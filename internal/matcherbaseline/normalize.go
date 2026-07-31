package matcherbaseline

import (
	"strings"
	"unicode"
)

var foldMap = map[rune]string{
	'À': "A", 'Á': "A", 'Â': "A", 'Ã': "A", 'Ä': "A", 'Å': "A", 'Æ': "AE",
	'Ç': "C", 'È': "E", 'É': "E", 'Ê': "E", 'Ë': "E", 'Ì': "I", 'Í': "I",
	'Î': "I", 'Ï': "I", 'Ð': "D", 'Ñ': "N", 'Ò': "O", 'Ó': "O", 'Ô': "O",
	'Õ': "O", 'Ö': "O", 'Ø': "O", 'Œ': "OE", 'Ù': "U", 'Ú': "U", 'Û': "U",
	'Ü': "U", 'Ý': "Y", 'Þ': "TH", 'ß': "SS", 'Š': "S", 'Ž': "Z", 'Ł': "L",
	'Đ': "D", 'Ğ': "G", 'İ': "I", 'Ş': "S", 'Č': "C", 'Ć': "C", 'Ř': "R",
	'А': "A", 'Б': "B", 'В': "V", 'Г': "G", 'Д': "D", 'Е': "E", 'Ё': "E",
	'Ж': "ZH", 'З': "Z", 'И': "I", 'Й': "I", 'К': "K", 'Л': "L", 'М': "M",
	'Н': "N", 'О': "O", 'П': "P", 'Р': "R", 'С': "S", 'Т': "T", 'У': "U",
	'Ф': "F", 'Х': "KH", 'Ц': "TS", 'Ч': "CH", 'Ш': "SH", 'Щ': "SHCH",
	'Ы': "Y", 'Э': "E", 'Ю': "YU", 'Я': "YA", 'Ь': "", 'Ъ': "",
}

func fold(value string) string {
	value = resolveBidiOverrides(value)
	value = strings.ToUpper(value)
	var builder strings.Builder
	lastSpace := true
	for _, r := range value {
		if replacement, ok := foldMap[r]; ok {
			if replacement != "" {
				builder.WriteString(replacement)
				lastSpace = false
			}
			continue
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			builder.WriteRune(r)
			lastSpace = false
			continue
		}
		if isIgnorableForFold(r) {
			// Deleted outright, not treated as a token separator.
			//
			// Two distinct cases land here:
			//   - Unicode format characters (category Cf): zero-width
			//     space/joiner/non-joiner, byte-order mark, and any
			//     bidirectional override/isolate markers that
			//     resolveBidiOverrides (above) didn't already consume.
			//     These have no visual width at all, so inserting a token
			//     break for them would split a single visible word into
			//     two - which is exactly what was happening before this
			//     fix, and is a bigger error than just ignoring an
			//     invisible character.
			//   - Decorative "connector" punctuation within a name: period
			//     and apostrophe. "A.C.M.E." should fold to "ACME" (one
			//     token), not "A C M E" (four); "O'Brien" should fold to
			//     "OBRIEN", not "O BRIEN". Other punctuation (hyphen,
			//     comma, slash, ampersand, underscore, colon, semicolon)
			//     deliberately keeps the old space-separator behavior below
			//     - those more often do separate genuinely distinct words
			//     (e.g. "Smith-Jones"), and changing that is a different,
			//     riskier decision than this one.
			continue
		}
		if !lastSpace && builder.Len() > 0 {
			builder.WriteByte(' ')
			lastSpace = true
		}
	}
	return strings.Join(strings.Fields(builder.String()), " ")
}

// resolveBidiOverrides undoes the classic "Trojan Source"-style spoofing
// technique before anything else touches the string: an attacker wraps a
// substring in a Right-to-Left Override (U+202E) or Left-to-Right Override
// (U+202D), pre-reversing the substring's actual character order so that
// once a bidi-aware renderer applies the override, the DISPLAYED text reads
// correctly (or as intended to deceive) - e.g. the literal bytes "STROPMI"
// wrapped in RLO/PDF display on screen as "IMPORTS".
//
// Merely deleting the RLO/PDF control characters (which is all the general
// Cf-stripping in fold's main loop does) is not enough: it leaves the
// enclosed text in its already-reversed byte order, so "ACME \u202eSTROPMI
// \u202cLLC" would fold to "ACME STROPMI LLC" - genuinely different text,
// not a fixed version of "ACME IMPORTS LLC". This function reverses the
// rune sequence between an override start and its matching Pop Directional
// Formatting (U+202C) - or the end of the string, if unterminated - before
// the override markers themselves are discarded, so the two representations
// of the same visible name compare equal after folding.
//
// Scope: handles the two override characters (RLO, LRO), which are what
// this specific spoofing technique relies on. Bidi *isolate* characters
// (U+2066-U+2069) don't reverse rendering order the same way and are left
// to the general Cf-stripping path; they're a narrower concern and not
// known to be used for this particular attack.
func resolveBidiOverrides(value string) string {
	const (
		rlo = '\u202e'
		lro = '\u202d'
		pdf = '\u202c'
	)
	runes := []rune(value)
	hasOverride := false
	for _, r := range runes {
		if r == rlo || r == lro {
			hasOverride = true
			break
		}
	}
	if !hasOverride {
		return value // fast path: no bidi override present, nothing to do
	}
	out := make([]rune, 0, len(runes))
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r != rlo && r != lro {
			out = append(out, r)
			continue
		}
		j := i + 1
		for j < len(runes) && runes[j] != pdf {
			j++
		}
		span := append([]rune(nil), runes[i+1:j]...)
		for l, rgt := 0, len(span)-1; l < rgt; l, rgt = l+1, rgt-1 {
			span[l], span[rgt] = span[rgt], span[l]
		}
		out = append(out, span...)
		if j < len(runes) {
			i = j // the loop's i++ will skip past the PDF itself
		} else {
			i = j - 1 // reached end of string without a closing PDF
		}
	}
	return string(out)
}

// isIgnorableForFold reports whether r should be deleted entirely during
// folding rather than treated as a token separator. See the call site in
// fold for the reasoning behind each case.
func isIgnorableForFold(r rune) bool {
	if unicode.Is(unicode.Cf, r) {
		return true
	}
	switch r {
	case '.', '\'', '\u2019': // full stop, apostrophe, right single quotation mark (common apostrophe substitute)
		return true
	}
	return false
}

func tokens(value string) []string {
	if value == "" {
		return nil
	}
	fields := strings.Fields(value)
	for i, f := range fields {
		fields[i] = canonicalizeToken(f)
	}
	return fields
}
