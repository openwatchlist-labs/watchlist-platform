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

// equalSpacesStripped is ADR-0008 addendum 2's AD2 extension: a and b
// (already run through normalizeText) compare equal once internal spaces
// are removed entirely from both sides, so "ACMEIMPORTS" and "ACME
// IMPORTS" agree regardless of which side is concatenated. Symmetric by
// construction -- it does not care which side supplied the space.
func equalSpacesStripped(a, b string) bool {
	return strings.ReplaceAll(a, " ", "") == strings.ReplaceAll(b, " ", "")
}

// particleTokens is candidatescoring's own copy of the starter particle
// list ADR-0008 addendum AD2 names, matching Table 1's own examples (AL,
// BIN, VAN DER). Deliberately not imported from internal/matcherbaseline:
// AD2 keeps this an independently-consumed leaf-package list, the same
// posture candidatescoring/doc.go and docs/ARCHITECTURE.md already take
// toward this package, rather than adding a live dependency on
// matcherbaseline merely to detect a shape. Two independently-maintained
// particle lists can drift apart over time -- an accepted, named risk
// (AD2), not resolved here.
var particleTokens = map[string]struct{}{
	"AL": {}, "BIN": {}, "VAN": {}, "DER": {}, "DE": {}, "DA": {}, "DEL": {},
	"DOS": {}, "DAS": {}, "LA": {}, "LE": {}, "VON": {}, "IBN": {},
}

// equalParticleStrippedTokenSet reports whether a and b's token sets agree
// once particleTokens are dropped from each side independently -- applied
// at the token level so a multi-word particle like "VAN DER" drops as two
// independently-droppable tokens (AD2): "KLAAS VAN DER BERG" drops to
// {BERG, KLAAS}, matching "KLAAS BERG" exactly.
func equalParticleStrippedTokenSet(a, b string) bool {
	ta := stripParticleTokens(tokenSet(a))
	tb := stripParticleTokens(tokenSet(b))
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

func stripParticleTokens(tokens []string) []string {
	out := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if _, isParticle := particleTokens[token]; isParticle {
			continue
		}
		out = append(out, token)
	}
	return out
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
