package matcherrequest

import "sort"

func summarize(requests []CandidateSearchRequest) RequestSummary {
	summary := RequestSummary{TotalRequests: len(requests)}
	transactions := map[int]struct{}{}
	routes := map[string]int{}
	targets := map[string]int{}
	for _, request := range requests {
		if request.TransactionIndex != nil {
			transactions[*request.TransactionIndex] = struct{}{}
		}
		switch request.RequestKind {
		case RequestCandidateAlert:
			summary.CandidateAlertRequests++
		case RequestSupportingEvidence:
			summary.SupportingEvidenceRequests++
		}
		for _, route := range request.MatchRoutes {
			routes[string(route)]++
		}
		for _, target := range request.TargetEntityTypes {
			targets[string(target)]++
		}
	}
	summary.TransactionCount = len(transactions)
	summary.RouteCounts = sortedCounts(routes)
	summary.TargetEntityTypeCounts = sortedCounts(targets)
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
