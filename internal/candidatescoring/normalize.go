package candidatescoring

import (
	"sort"
	"strings"
	"unicode"
)

func normalizeText(value string) string {
	var b strings.Builder
	lastSpace := true
	for _, r := range strings.ToUpper(strings.TrimSpace(value)) {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
			b.WriteRune(r)
			lastSpace = false
		default:
			if !lastSpace {
				b.WriteByte(' ')
				lastSpace = true
			}
		}
	}
	return strings.TrimSpace(b.String())
}

func normalizeIdentifierType(value string) string {
	return strings.ReplaceAll(normalizeText(value), " ", "_")
}

func normalizeIdentifierValue(value string) string {
	return strings.ReplaceAll(normalizeText(value), " ", "")
}

func normalizeCountry(value string) string {
	return strings.ReplaceAll(normalizeText(value), " ", "")
}

func normalizeEntityType(value string) string {
	switch normalizeText(value) {
	case "PERSON", "INDIVIDUAL", "NATURAL PERSON":
		return "PERSON"
	case "ORGANIZATION", "ORGANISATION", "ENTITY", "COMPANY", "BUSINESS":
		return "ORGANIZATION"
	case "VESSEL", "SHIP":
		return "VESSEL"
	case "AIRCRAFT", "PLANE":
		return "AIRCRAFT"
	default:
		return normalizeText(value)
	}
}

func tokenSet(value string) []string {
	seen := map[string]struct{}{}
	for _, token := range strings.Fields(normalizeText(value)) {
		seen[token] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for token := range seen {
		out = append(out, token)
	}
	sort.Strings(out)
	return out
}

func equalTokenSet(a, b string) bool {
	ta := tokenSet(a)
	tb := tokenSet(b)
	if len(ta) == 0 || len(ta) != len(tb) {
		return false
	}
	for i := range ta {
		if ta[i] != tb[i] {
			return false
		}
	}
	return true
}

func uniqueSorted(values []string, normalizer func(string) string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		n := normalizer(value)
		if n != "" {
			seen[n] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
