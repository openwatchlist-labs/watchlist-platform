package rag

import (
	"fmt"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/policyengine"
)

func QueryFromDecision(decision policyengine.Decision, tenantID, effectiveAt string) (RetrievalQuery, error) {
	if err := policyengine.ValidateDecision(decision); err != nil {
		return RetrievalQuery{}, err
	}
	observation := decision.Classification.Observation
	query := RetrievalQuery{
		SchemaVersion:    RetrievalQuerySchema,
		Task:             "explain_policy_route",
		TenantID:         tenantID,
		Scope:            "transaction_screening", // policyengine.Decision is always transaction-screening-scoped
		DecisionID:       decision.DecisionID,
		Disposition:      string(decision.Disposition),
		ReviewRoute:      string(decision.ReviewRoute),
		ReasonCodes:      append([]string(nil), decision.ReasonCodes...),
		Blockers:         append([]string(nil), decision.EscalationBlockers...),
		RequiredEvidence: append([]string(nil), decision.RequiredEvidence...),
		MessageType:      observation.MessageType,
		SemanticRole:     string(observation.SemanticRole),
		PolicyID:         decision.Policy.PolicyID,
		EffectiveAt:      effectiveAt,
		QueryText:        fmt.Sprintf("Explain why %s was routed to %s for %s. Candidate entity type %s. Input %s. Watchlist value %s.", decision.Disposition, decision.ReviewRoute, observation.SemanticRole, observation.WatchlistEntityType, observation.InputValue, observation.WatchlistValue),
	}
	query.ReasonCodes = sortedUnique(query.ReasonCodes)
	query.Blockers = sortedUnique(query.Blockers)
	query.RequiredEvidence = sortedUnique(query.RequiredEvidence)
	query.QueryText = strings.TrimSpace(query.QueryText)
	query.QueryID = stableQueryID(query)
	if err := ValidateQuery(query); err != nil {
		return RetrievalQuery{}, err
	}
	return query, nil
}
