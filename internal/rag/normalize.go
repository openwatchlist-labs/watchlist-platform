package rag

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
)

var tokenPattern = regexp.MustCompile(`[A-Z0-9]+`)

func normalizeText(value string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(value) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte(' ')
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

func tokenize(value string) []string {
	items := tokenPattern.FindAllString(normalizeText(value), -1)
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if len(item) == 1 && item < "0" || len(item) == 1 && item > "9" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func instructionIndicators(value string) []string {
	normalized := normalizeText(value)
	checks := []string{
		"IGNORE PREVIOUS INSTRUCTIONS",
		"REVEAL SYSTEM PROMPT",
		"SYSTEM MESSAGE",
		"CALL A TOOL",
		"EXFILTRATE",
		"DISREGARD POLICY",
	}
	out := []string{}
	for _, check := range checks {
		if strings.Contains(normalized, check) {
			out = append(out, strings.ToLower(strings.ReplaceAll(check, " ", "_")))
		}
	}
	return out
}
