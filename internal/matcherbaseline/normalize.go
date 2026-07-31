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
			//     space/joiner/non-joiner, byte-order mark, bidirectional
			//     overrides (used e.g. to visually reverse text). These have
			//     no visual width at all, so inserting a token break for
			//     them would split a single visible word into two - which
			//     is exactly what was happening before this fix, and is a
			//     bigger error than just ignoring an invisible character.
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
	return strings.Fields(value)
}
