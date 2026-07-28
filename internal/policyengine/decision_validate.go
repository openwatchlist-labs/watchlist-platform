package policyengine

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/openwatchlist-labs/watchlist-platform/internal/falsepositive"
)

func ValidateDecisionBatch(batch DecisionBatch) error {
	if batch.SchemaVersion != DecisionBatchSchema {
		return fmt.Errorf("decision batch schema must be %q", DecisionBatchSchema)
	}
	if batch.DecisionBatchID == "" || batch.InputClassificationBatchID == "" {
		return fmt.Errorf("decision batch identifiers are required")
	}
	if batch.EngineVersion != PolicyEngineVersion {
		return fmt.Errorf("engine version must be %q", PolicyEngineVersion)
	}
	if len(batch.Decisions) == 0 {
		return fmt.Errorf("decisions are required")
	}
	for index, decision := range batch.Decisions {
		if err := ValidateDecision(decision); err != nil {
			return fmt.Errorf("decisions[%d]: %w", index, err)
		}
		if decision.Policy != batch.Policy || !reflect.DeepEqual(decision.Overlay, batch.Overlay) {
			return fmt.Errorf("decisions[%d]: policy lineage differs from batch", index)
		}
	}
	if expected := summarize(batch.Decisions); !reflect.DeepEqual(batch.Summary, expected) {
		return fmt.Errorf("decision batch summary mismatch")
	}
	if expected := stableBatchID(batch); batch.DecisionBatchID != expected {
		return fmt.Errorf("decision_batch_id=%q expected %q", batch.DecisionBatchID, expected)
	}
	return nil
}

func ValidateDecision(decision Decision) error {
	if decision.SchemaVersion != DecisionSchemaVersion {
		return fmt.Errorf("schema_version must be %q", DecisionSchemaVersion)
	}
	if decision.DecisionID == "" {
		return fmt.Errorf("decision_id is required")
	}
	if decision.EngineVersion != PolicyEngineVersion {
		return fmt.Errorf("engine_version must be %q", PolicyEngineVersion)
	}
	if err := falsepositive.ValidateClassification(decision.Classification); err != nil {
		return err
	}
	if decision.PolicyScore < 0 || decision.PolicyScore > 10000 {
		return fmt.Errorf("policy score outside 0..10000")
	}
	if err := validateDisposition(decision.Disposition, "disposition", fmt.Errorf("invalid decision")); err != nil {
		return err
	}
	if err := validateReviewRoute(decision.ReviewRoute, "review_route", fmt.Errorf("invalid decision")); err != nil {
		return err
	}
	if len(decision.ScoreComponents) < 3 || len(decision.RuleTrace) == 0 || len(decision.ReasonCodes) == 0 {
		return fmt.Errorf("score components, rule trace, and reason codes are required")
	}
	if !sort.StringsAreSorted(decision.ReasonCodes) || !sort.StringsAreSorted(decision.EscalationBlockers) || !sort.StringsAreSorted(decision.RequiredEvidence) {
		return fmt.Errorf("reason codes, blockers, and required evidence must be sorted")
	}
	if expected := stableDecisionID(decision); decision.DecisionID != expected {
		return fmt.Errorf("decision_id=%q expected %q", decision.DecisionID, expected)
	}
	return nil
}
