package matcherbaseline

import (
	"sort"
	"strings"
)

type featureScore struct {
	name                        string
	score, weight, contribution int
}

func scoreName(query, candidate string, profile ThresholdProfile) (int, []featureScore, int) {
	qt, ct := tokens(query), tokens(candidate)
	features := []featureScore{
		{name: "edit_similarity", score: bestEditSimilarity(query, candidate, qt, ct), weight: profile.EditSimilarityWeightBasisPoints},
		{name: "length_similarity", score: lengthSimilarity(query, candidate), weight: profile.LengthWeightBasisPoints},
		{name: "ordered_token_similarity", score: orderedTokenSimilarity(qt, ct), weight: profile.OrderedTokenWeightBasisPoints},
		{name: "phonetic_similarity", score: phoneticSimilarity(qt, ct), weight: profile.PhoneticWeightBasisPoints},
		{name: "token_alignment_similarity", score: tokenAlignmentSimilarity(qt, ct), weight: profile.TokenAlignmentWeightBasisPoints},
	}
	sort.Slice(features, func(i, j int) bool { return features[i].name < features[j].name })
	total := 0
	for i := range features {
		features[i].contribution = features[i].score * features[i].weight / 10000
		total += features[i].contribution
	}
	penalty := 0
	if query != candidate && (len(qt) == 1 || len(ct) == 1) {
		penalty += profile.SingleTokenPenaltyBasisPoints
	}
	total -= penalty
	if total < 0 {
		total = 0
	}
	return total, features, penalty
}

// bestEditSimilarity returns the higher of the raw whole-string edit
// similarity and the edit similarity computed on token-sorted renderings of
// the same two strings.
//
// Why: token_alignment_similarity already scores pure token reordering as a
// perfect match (each token has an exact best match somewhere in the other
// list, regardless of position) - that's deliberate, existing behavior, not
// something introduced here. But raw whole-string edit_similarity is
// order-sensitive, so it was fighting against that decision instead of
// agreeing with it: a full reordering of otherwise-identical tokens (e.g.
// "Acme Imports LLC" vs "Imports LLC Acme") scored a very low raw edit
// similarity purely because the characters shifted position, even though
// nothing about the actual words differs. Comparing sorted-token renderings
// as well, and taking the max, means edit_similarity stops re-penalizing a
// property (token order) the system has already decided elsewhere isn't
// meaningful for a name match.
//
// This intentionally cannot raise a score above what perfect token identity
// already earns via token_alignment_similarity - it only removes a
// redundant, conflicting penalty for the same case. The accepted trade-off,
// consistent with token_alignment_similarity's existing weight, is that two
// entities whose names are literally the same words in a different order
// (e.g. "Alpha Beta Corp" vs "Beta Alpha Corp") are not distinguishable by
// word order alone under this matcher - genuine spelling differences within
// a token are unaffected, since sorting tokens doesn't fix a misspelled word.
func bestEditSimilarity(query, candidate string, qt, ct []string) int {
	raw := editSimilarity(query, candidate)
	if len(qt) < 2 && len(ct) < 2 {
		return raw // nothing to reorder
	}
	sortedRaw := editSimilarity(sortedJoin(qt), sortedJoin(ct))
	if sortedRaw > raw {
		return sortedRaw
	}
	return raw
}

func sortedJoin(tokens []string) string {
	sorted := append([]string(nil), tokens...)
	sort.Strings(sorted)
	return strings.Join(sorted, " ")
}

func editSimilarity(left, right string) int {
	lr, rr := []rune(left), []rune(right)
	m := len(lr)
	if len(rr) > m {
		m = len(rr)
	}
	if m == 0 {
		return 10000
	}
	d := levenshtein(lr, rr)
	return (m - d) * 10000 / m
}
func levenshtein(left, right []rune) int {
	prev := make([]int, len(right)+1)
	for i := range prev {
		prev[i] = i
	}
	for i, lr := range left {
		cur := make([]int, len(right)+1)
		cur[0] = i + 1
		for j, rr := range right {
			cost := 0
			if lr != rr {
				cost = 1
			}
			cur[j+1] = min3(cur[j]+1, prev[j+1]+1, prev[j]+cost)
		}
		prev = cur
	}
	return prev[len(right)]
}
func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
func lengthSimilarity(left, right string) int {
	a, b := len([]rune(left)), len([]rune(right))
	m := a
	if b > m {
		m = b
	}
	if m == 0 {
		return 10000
	}
	d := a - b
	if d < 0 {
		d = -d
	}
	return (m - d) * 10000 / m
}
func tokenAlignmentSimilarity(left, right []string) int {
	if len(left) == 0 && len(right) == 0 {
		return 10000
	}
	if len(left) == 0 || len(right) == 0 {
		return 0
	}
	return (directedTokenScore(left, right) + directedTokenScore(right, left)) / 2
}
func directedTokenScore(source, target []string) int {
	total := 0
	for _, s := range source {
		best := 0
		for _, t := range target {
			v := editSimilarity(s, t)
			if v > best {
				best = v
			}
		}
		total += best
	}
	return total / len(source)
}
func orderedTokenSimilarity(left, right []string) int {
	m := len(left)
	if len(right) > m {
		m = len(right)
	}
	if m == 0 {
		return 10000
	}
	matrix := make([][]int, len(left)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(right)+1)
	}
	for i := 1; i <= len(left); i++ {
		for j := 1; j <= len(right); j++ {
			if editSimilarity(left[i-1], right[j-1]) >= 8000 {
				matrix[i][j] = matrix[i-1][j-1] + 1
			} else if matrix[i-1][j] > matrix[i][j-1] {
				matrix[i][j] = matrix[i-1][j]
			} else {
				matrix[i][j] = matrix[i][j-1]
			}
		}
	}
	return matrix[len(left)][len(right)] * 10000 / m
}
func phoneticSimilarity(left, right []string) int {
	if len(left) == 0 && len(right) == 0 {
		return 10000
	}
	if len(left) == 0 || len(right) == 0 {
		return 0
	}
	lc := make([]string, len(left))
	rc := make([]string, len(right))
	for i, t := range left {
		lc[i] = soundex(t)
	}
	for i, t := range right {
		rc[i] = soundex(t)
	}
	used := make([]bool, len(rc))
	matches := 0
	for _, c := range lc {
		for i, o := range rc {
			if !used[i] && c != "" && c == o {
				used[i] = true
				matches++
				break
			}
		}
	}
	m := len(lc)
	if len(rc) > m {
		m = len(rc)
	}
	return matches * 10000 / m
}
func soundex(value string) string {
	value = strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r
		}
		return -1
	}, strings.ToUpper(value))
	if value == "" {
		return ""
	}
	var out strings.Builder
	out.WriteByte(value[0])
	prev := soundexDigit(value[0])
	for i := 1; i < len(value) && out.Len() < 4; i++ {
		d := soundexDigit(value[i])
		if d != '0' && d != prev {
			out.WriteByte(d)
		}
		prev = d
	}
	for out.Len() < 4 {
		out.WriteByte('0')
	}
	return out.String()
}
func soundexDigit(v byte) byte {
	switch v {
	case 'B', 'F', 'P', 'V':
		return '1'
	case 'C', 'G', 'J', 'K', 'Q', 'S', 'X', 'Z':
		return '2'
	case 'D', 'T':
		return '3'
	case 'L':
		return '4'
	case 'M', 'N':
		return '5'
	case 'R':
		return '6'
	default:
		return '0'
	}
}
