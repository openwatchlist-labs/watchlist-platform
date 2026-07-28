package falsepositive

import (
	"sort"
	"strings"
	"unicode"
)

func normalizeText(value string) string {
	var b strings.Builder
	space := true
	for _, r := range strings.ToUpper(strings.TrimSpace(value)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			space = false
			continue
		}
		if !space && b.Len() > 0 {
			b.WriteByte(' ')
			space = true
		}
	}
	return strings.TrimSpace(b.String())
}

func tokens(value string) []string {
	value = normalizeText(value)
	if value == "" {
		return nil
	}
	return strings.Fields(value)
}

func compact(value string) string {
	return strings.Join(tokens(value), "")
}

func containsWholeTokenSequence(input, needle string) bool {
	in := tokens(input)
	want := tokens(needle)
	if len(want) == 0 || len(want) > len(in) {
		return false
	}
	for start := 0; start+len(want) <= len(in); start++ {
		match := true
		for index := range want {
			if in[start+index] != want[index] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func containsString(values []string, value string) bool {
	for _, current := range values {
		if current == value {
			return true
		}
	}
	return false
}

func canonicalStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}
