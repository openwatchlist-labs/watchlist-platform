package projectionpackage

import (
	"sort"
	"strings"
	"unicode"

	"github.com/openwatchlist-labs/watchlist-platform/internal/candidatescoring"
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

func uniqueSorted(values []string, normalizer func(string) string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if normalized := normalizer(value); normalized != "" {
			seen[normalized] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func normalizeIdentifiers(values []candidatescoring.Identifier) []candidatescoring.Identifier {
	seen := map[string]candidatescoring.Identifier{}
	for _, value := range values {
		typeValue := normalizeIdentifierType(value.Type)
		identifierValue := normalizeIdentifierValue(value.Value)
		if typeValue == "" || identifierValue == "" {
			continue
		}
		key := typeValue + "\x00" + identifierValue
		seen[key] = candidatescoring.Identifier{Type: typeValue, Value: identifierValue}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]candidatescoring.Identifier, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out
}
