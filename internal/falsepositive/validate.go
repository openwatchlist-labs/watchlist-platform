package falsepositive

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
)

var (
	ErrInvalidObservationBatch    = errors.New("invalid false-positive observation batch")
	ErrInvalidClassificationBatch = errors.New("invalid false-positive classification batch")
)

func CanonicalizeObservationBatch(batch ObservationBatch) ObservationBatch {
	batch.SchemaVersion = ObservationBatchSchema
	batch.SourceReference = strings.TrimSpace(batch.SourceReference)
	for index := range batch.Observations {
		observation := &batch.Observations[index]
		observation.SchemaVersion = ObservationSchemaVersion
		observation.NormalizedInputValue = normalizeText(observation.InputValue)
		observation.NormalizedWatchlistValue = normalizeText(observation.WatchlistValue)
		observation.MatcherReasonCodes = canonicalStrings(observation.MatcherReasonCodes)
		observation.MatcherDiagnosticCodes = canonicalStrings(observation.MatcherDiagnosticCodes)
		observation.SecondaryIdentifierMatches = canonicalStrings(observation.SecondaryIdentifierMatches)
		observation.RequiredQualifiers = canonicalStrings(observation.RequiredQualifiers)
		observation.PresentQualifiers = canonicalStrings(observation.PresentQualifiers)
		observation.TechnicalMarkers = canonicalStrings(observation.TechnicalMarkers)
		observation.ContextMarkers = canonicalStrings(observation.ContextMarkers)
		sort.Slice(observation.TargetEntityTypes, func(i, j int) bool { return observation.TargetEntityTypes[i] < observation.TargetEntityTypes[j] })
		observation.TargetEntityTypes = dedupeCandidateTypes(observation.TargetEntityTypes)
		for assertionIndex := range observation.SourceAssertions {
			observation.SourceAssertions[assertionIndex].Programs = canonicalStrings(observation.SourceAssertions[assertionIndex].Programs)
		}
		sort.Slice(observation.SourceAssertions, func(i, j int) bool {
			left, right := observation.SourceAssertions[i], observation.SourceAssertions[j]
			if left.SourceID != right.SourceID {
				return left.SourceID < right.SourceID
			}
			if left.ListID != right.ListID {
				return left.ListID < right.ListID
			}
			return left.SourceRecordID < right.SourceRecordID
		})
		observation.ObservationID = stableObservationID(*observation)
	}
	sort.Slice(batch.Observations, func(i, j int) bool {
		if batch.Observations[i].CaseID != batch.Observations[j].CaseID {
			return batch.Observations[i].CaseID < batch.Observations[j].CaseID
		}
		return batch.Observations[i].ObservationID < batch.Observations[j].ObservationID
	})
	batch.BatchID = stableObservationBatchID(batch)
	return batch
}

func dedupeCandidateTypes(values []canonical.CandidateType) []canonical.CandidateType {
	if len(values) == 0 {
		return nil
	}
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}

func ValidateObservationBatch(batch ObservationBatch) error {
	if batch.SchemaVersion != ObservationBatchSchema {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidObservationBatch, ObservationBatchSchema)
	}
	if strings.TrimSpace(batch.BatchID) == "" || strings.TrimSpace(batch.SourceReference) == "" {
		return fmt.Errorf("%w: batch_id and source_reference are required", ErrInvalidObservationBatch)
	}
	if len(batch.Observations) == 0 {
		return fmt.Errorf("%w: observations are required", ErrInvalidObservationBatch)
	}
	seen := map[string]struct{}{}
	for index, observation := range batch.Observations {
		if err := ValidateObservation(observation); err != nil {
			return fmt.Errorf("%w: observations[%d]: %v", ErrInvalidObservationBatch, index, err)
		}
		if _, exists := seen[observation.ObservationID]; exists {
			return fmt.Errorf("%w: duplicate observation_id %q", ErrInvalidObservationBatch, observation.ObservationID)
		}
		seen[observation.ObservationID] = struct{}{}
	}
	if !sort.SliceIsSorted(batch.Observations, func(i, j int) bool {
		if batch.Observations[i].CaseID != batch.Observations[j].CaseID {
			return batch.Observations[i].CaseID < batch.Observations[j].CaseID
		}
		return batch.Observations[i].ObservationID < batch.Observations[j].ObservationID
	}) {
		return fmt.Errorf("%w: observations are not in canonical order", ErrInvalidObservationBatch)
	}
	if expected := stableObservationBatchID(batch); batch.BatchID != expected {
		return fmt.Errorf("%w: batch_id=%q expected %q", ErrInvalidObservationBatch, batch.BatchID, expected)
	}
	return nil
}

func ValidateObservation(observation Observation) error {
	if observation.SchemaVersion != ObservationSchemaVersion {
		return fmt.Errorf("schema_version must be %q", ObservationSchemaVersion)
	}
	for field, value := range map[string]string{
		"observation_id":             observation.ObservationID,
		"case_id":                    observation.CaseID,
		"message_id":                 observation.MessageID,
		"message_type":               observation.MessageType,
		"source_system":              observation.SourceSystem,
		"matched_field":              observation.MatchedField,
		"semantic_role":              string(observation.SemanticRole),
		"value_type":                 string(observation.ValueType),
		"trigger_policy":             string(observation.TriggerPolicy),
		"input_value":                observation.InputValue,
		"normalized_input_value":     observation.NormalizedInputValue,
		"watchlist_value":            observation.WatchlistValue,
		"normalized_watchlist_value": observation.NormalizedWatchlistValue,
		"watchlist_entity_type":      string(observation.WatchlistEntityType),
		"match_route":                string(observation.MatchRoute),
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}
	if observation.ScreeningScoreBasisPoints < 0 || observation.ScreeningScoreBasisPoints > 10000 {
		return fmt.Errorf("screening_score_basis_points outside 0..10000")
	}
	if observation.NormalizedInputValue != normalizeText(observation.NormalizedInputValue) {
		return fmt.Errorf("normalized_input_value is not canonical")
	}
	if observation.NormalizedWatchlistValue != normalizeText(observation.NormalizedWatchlistValue) {
		return fmt.Errorf("normalized_watchlist_value is not canonical")
	}
	if expected := stableObservationID(observation); observation.ObservationID != expected {
		return fmt.Errorf("observation_id=%q expected %q", observation.ObservationID, expected)
	}
	for _, values := range [][]string{
		observation.MatcherReasonCodes,
		observation.MatcherDiagnosticCodes,
		observation.SecondaryIdentifierMatches,
		observation.RequiredQualifiers,
		observation.PresentQualifiers,
		observation.TechnicalMarkers,
		observation.ContextMarkers,
	} {
		if !reflect.DeepEqual(values, canonicalStrings(values)) {
			return fmt.Errorf("string collections must be sorted and unique")
		}
	}
	for _, assertion := range observation.SourceAssertions {
		if strings.TrimSpace(assertion.SourceID) == "" || strings.TrimSpace(assertion.Authority) == "" || strings.TrimSpace(assertion.ListID) == "" || strings.TrimSpace(assertion.SourceRecordID) == "" {
			return fmt.Errorf("source assertion is incomplete")
		}
		if !reflect.DeepEqual(assertion.Programs, canonicalStrings(assertion.Programs)) {
			return fmt.Errorf("source assertion programs must be sorted and unique")
		}
	}
	return nil
}

func ValidateClassificationBatch(batch ClassificationBatch) error {
	if batch.SchemaVersion != ClassificationBatchSchema {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidClassificationBatch, ClassificationBatchSchema)
	}
	for field, value := range map[string]string{
		"classification_batch_id":               batch.ClassificationBatchID,
		"input_observation_batch_id":            batch.InputObservationBatchID,
		"classifier_version":                    batch.ClassifierVersion,
		"pattern_library.library_id":            batch.PatternLibrary.LibraryID,
		"pattern_library.library_version":       batch.PatternLibrary.LibraryVersion,
		"pattern_library.library_checksum":      batch.PatternLibrary.LibraryChecksum,
		"countervailing_policy.policy_id":       batch.CountervailingPolicy.PolicyID,
		"countervailing_policy.policy_version":  batch.CountervailingPolicy.PolicyVersion,
		"countervailing_policy.policy_checksum": batch.CountervailingPolicy.PolicyChecksum,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidClassificationBatch, field)
		}
	}
	if batch.ClassifierVersion != ClassifierVersion {
		return fmt.Errorf("%w: classifier_version must be %q", ErrInvalidClassificationBatch, ClassifierVersion)
	}
	seen := map[string]struct{}{}
	for index, classification := range batch.Classifications {
		if err := ValidateClassification(classification); err != nil {
			return fmt.Errorf("%w: classifications[%d]: %v", ErrInvalidClassificationBatch, index, err)
		}
		if !reflect.DeepEqual(classification.PatternLibrary, batch.PatternLibrary) {
			return fmt.Errorf("%w: classifications[%d] pattern library differs from batch", ErrInvalidClassificationBatch, index)
		}
		if !reflect.DeepEqual(classification.CountervailingPolicy, batch.CountervailingPolicy) {
			return fmt.Errorf("%w: classifications[%d] countervailing policy differs from batch", ErrInvalidClassificationBatch, index)
		}
		if _, exists := seen[classification.ClassificationID]; exists {
			return fmt.Errorf("%w: duplicate classification_id %q", ErrInvalidClassificationBatch, classification.ClassificationID)
		}
		seen[classification.ClassificationID] = struct{}{}
	}
	if expected := summarizeClassifications(batch.Classifications); !reflect.DeepEqual(batch.Summary, expected) {
		return fmt.Errorf("%w: summary differs from classifications", ErrInvalidClassificationBatch)
	}
	if expected := stableClassificationBatchID(batch); batch.ClassificationBatchID != expected {
		return fmt.Errorf("%w: classification_batch_id=%q expected %q", ErrInvalidClassificationBatch, batch.ClassificationBatchID, expected)
	}
	return nil
}

func ValidateClassification(classification Classification) error {
	if classification.SchemaVersion != ClassificationSchemaVersion {
		return fmt.Errorf("schema_version must be %q", ClassificationSchemaVersion)
	}
	if strings.TrimSpace(classification.ClassificationID) == "" || classification.ClassifierVersion != ClassifierVersion || !validRouteHint(classification.RouteHint) {
		return fmt.Errorf("classification identity, version, or route is invalid")
	}
	if err := ValidateObservation(classification.Observation); err != nil {
		return fmt.Errorf("observation: %v", err)
	}
	for field, value := range map[string]string{
		"countervailing_policy.policy_id":       classification.CountervailingPolicy.PolicyID,
		"countervailing_policy.policy_version":  classification.CountervailingPolicy.PolicyVersion,
		"countervailing_policy.policy_checksum": classification.CountervailingPolicy.PolicyChecksum,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}
	if !sort.SliceIsSorted(classification.Patterns, func(i, j int) bool { return classification.Patterns[i].Code < classification.Patterns[j].Code }) {
		return fmt.Errorf("patterns are not in canonical order")
	}
	for _, pattern := range classification.Patterns {
		if pattern.SchemaVersion != PatternEvidenceSchema || strings.TrimSpace(pattern.Code) == "" || strings.TrimSpace(pattern.Detail) == "" || !validRouteHint(pattern.RouteHint) {
			return fmt.Errorf("pattern evidence is incomplete")
		}
		if pattern.StrengthBasisPoints < 0 || pattern.StrengthBasisPoints > 10000 {
			return fmt.Errorf("pattern strength outside 0..10000")
		}
		if !reflect.DeepEqual(pattern.EscalationBlockers, canonicalStrings(pattern.EscalationBlockers)) || !reflect.DeepEqual(pattern.ReasonCodes, canonicalStrings(pattern.ReasonCodes)) {
			return fmt.Errorf("pattern evidence collections must be sorted and unique")
		}
	}
	if !sort.SliceIsSorted(classification.CountervailingSignals, func(i, j int) bool {
		return classification.CountervailingSignals[i].Code < classification.CountervailingSignals[j].Code
	}) {
		return fmt.Errorf("countervailing signals are not in canonical order")
	}
	for _, signal := range classification.CountervailingSignals {
		if signal.SchemaVersion != CountervailingSignalSchemaVersion || strings.TrimSpace(signal.Code) == "" || strings.TrimSpace(signal.Detail) == "" || !validEvidenceClass(signal.EvidenceClass) {
			return fmt.Errorf("countervailing signal is incomplete")
		}
		if signal.StrengthBasisPoints < 0 || signal.StrengthBasisPoints > 10000 {
			return fmt.Errorf("countervailing signal strength outside 0..10000")
		}
		if signal.EscalationEligible && signal.EvidenceClass != EvidenceClassPrimaryIdentifier {
			return fmt.Errorf("only primary identifier signals may be escalation eligible")
		}
	}
	if classification.Observation.TriggerPolicy != canonical.TriggerCandidateAlert && classification.RouteHint == RouteEscalationCandidate {
		return fmt.Errorf("supporting evidence cannot independently produce escalation_candidate")
	}
	if classification.RouteHint == RouteEscalationCandidate && !hasEscalationEligibleSignal(classification.CountervailingSignals) {
		return fmt.Errorf("escalation_candidate requires an escalation-eligible primary identifier signal")
	}
	if !reflect.DeepEqual(classification.EscalationBlockers, canonicalStrings(classification.EscalationBlockers)) || !reflect.DeepEqual(classification.RequiresEvidence, canonicalStrings(classification.RequiresEvidence)) {
		return fmt.Errorf("classification collections must be sorted and unique")
	}
	if classification.Summary.PatternCount != len(classification.Patterns) {
		return fmt.Errorf("pattern_count differs from patterns")
	}
	if expected := stableClassificationID(classification); classification.ClassificationID != expected {
		return fmt.Errorf("classification_id=%q expected %q", classification.ClassificationID, expected)
	}
	return nil
}
