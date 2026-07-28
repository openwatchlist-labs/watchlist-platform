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
		if !lastSpace && builder.Len() > 0 {
			builder.WriteByte(' ')
			lastSpace = true
		}
	}
	return strings.Join(strings.Fields(builder.String()), " ")
}

func tokens(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Fields(value)
}
