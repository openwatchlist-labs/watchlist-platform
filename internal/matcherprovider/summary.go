package matcherprovider

import "sort"

func summarizeResults(results []CandidateSearchResult) ResultSummary {
	summary := ResultSummary{TotalRequests: len(results)}
	types := map[string]int{}
	routes := map[string]int{}
	diagnostics := map[string]int{}
	for _, result := range results {
		switch result.Status {
		case ResultMatched:
			summary.MatchedRequests++
		case ResultNoCandidates:
			summary.NoCandidateRequests++
		}
		summary.TotalCandidates += len(result.Candidates)
		for _, candidate := range result.Candidates {
			types[string(candidate.EntityType)]++
			routes[string(candidate.MatchRoute)]++
		}
		for _, diagnostic := range result.Diagnostics {
			diagnostics[diagnostic.Code]++
		}
	}
	summary.CandidateTypeCounts = sortedCounts(types)
	summary.MatchRouteCounts = sortedCounts(routes)
	summary.DiagnosticCounts = sortedCounts(diagnostics)
	return summary
}

func sortedCounts(values map[string]int) []NamedCount {
	if len(values) == 0 {
		return nil
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]NamedCount, 0, len(names))
	for _, name := range names {
		result = append(result, NamedCount{Name: name, Count: values[name]})
	}
	return result
}
