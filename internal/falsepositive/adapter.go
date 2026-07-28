package falsepositive

import (
	"fmt"

	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
)

func ObservationsFromMatcherResults(batch matcherprovider.ResultBatch, sourceReference string) (ObservationBatch, error) {
	if err := matcherprovider.ValidateResultBatch(batch); err != nil {
		return ObservationBatch{}, fmt.Errorf("invalid matcher result batch: %w", err)
	}
	out := ObservationBatch{
		SchemaVersion:   ObservationBatchSchema,
		SourceReference: sourceReference,
		Observations:    make([]Observation, 0),
	}
	for _, result := range batch.Results {
		for _, candidate := range result.Candidates {
			reasonCodes := []string(nil)
			contextMarkers := []string(nil)
			if candidate.Evidence != nil {
				reasonCodes = append(reasonCodes, candidate.Evidence.ReasonCodes...)
				if candidate.Evidence.Context != nil {
					contextMarkers = append(contextMarkers, candidate.Evidence.Context.NegationMarkers...)
				}
			}
			observation := Observation{
				SchemaVersion:             ObservationSchemaVersion,
				CaseID:                    result.ResultID + ":" + candidate.CandidateID,
				MessageID:                 result.Request.MessageID,
				MessageType:               string(result.Request.SourceLineage.MessageDefinition),
				SourceSystem:              "openwatchlist-matcher",
				MatchedField:              string(result.Request.SemanticRole),
				NativePath:                result.Request.NativePath,
				SemanticRole:              result.Request.SemanticRole,
				ValueType:                 result.Request.ValueType,
				TriggerPolicy:             result.Request.TriggerPolicy,
				InputValue:                result.Request.Query.OriginalValue,
				NormalizedInputValue:      result.Request.Query.NormalizedValue,
				WatchlistValue:            candidate.MatchedValue,
				NormalizedWatchlistValue:  candidate.NormalizedMatchedValue,
				WatchlistEntityType:       candidate.EntityType,
				MatchRoute:                candidate.MatchRoute,
				ScreeningScoreBasisPoints: candidate.ScoreBasisPoints,
				Exact:                     candidate.Exact,
				MatcherReasonCodes:        reasonCodes,
				SourceAssertions:          append([]matcherprovider.SourceAssertion(nil), candidate.SourceAssertions...),
			}
			observation.TargetEntityTypes = append(observation.TargetEntityTypes, result.Request.TargetEntityTypes...)
			observation.ContextMarkers = contextMarkers
			out.Observations = append(out.Observations, observation)
		}
		for _, diagnostic := range result.Diagnostics {
			reasonCodes := []string(nil)
			contextMarkers := []string(nil)
			if diagnostic.Evidence != nil {
				reasonCodes = append(reasonCodes, diagnostic.Evidence.ReasonCodes...)
				if diagnostic.Evidence.Context != nil {
					contextMarkers = append(contextMarkers, diagnostic.Evidence.Context.NegationMarkers...)
				}
			}
			observation := Observation{
				SchemaVersion:             ObservationSchemaVersion,
				CaseID:                    result.ResultID + ":diagnostic:" + diagnostic.Code + ":" + diagnostic.ProviderRecordID,
				MessageID:                 result.Request.MessageID,
				MessageType:               string(result.Request.SourceLineage.MessageDefinition),
				SourceSystem:              "openwatchlist-matcher",
				MatchedField:              string(result.Request.SemanticRole),
				NativePath:                result.Request.NativePath,
				SemanticRole:              result.Request.SemanticRole,
				ValueType:                 result.Request.ValueType,
				TriggerPolicy:             result.Request.TriggerPolicy,
				InputValue:                result.Request.Query.OriginalValue,
				NormalizedInputValue:      result.Request.Query.NormalizedValue,
				WatchlistValue:            diagnostic.MatchedValue,
				NormalizedWatchlistValue:  normalizeText(diagnostic.MatchedValue),
				WatchlistEntityType:       diagnostic.EntityType,
				MatchRoute:                diagnostic.MatchRoute,
				ScreeningScoreBasisPoints: diagnostic.ScoreBasisPoints,
				Exact:                     false,
				MatcherReasonCodes:        reasonCodes,
				MatcherDiagnosticCodes:    []string{diagnostic.Code},
				SourceAssertions:          append([]matcherprovider.SourceAssertion(nil), diagnostic.SourceAssertions...),
				ContextMarkers:            contextMarkers,
			}
			observation.TargetEntityTypes = append(observation.TargetEntityTypes, result.Request.TargetEntityTypes...)
			out.Observations = append(out.Observations, observation)
		}
	}
	out = CanonicalizeObservationBatch(out)
	return out, ValidateObservationBatch(out)
}
