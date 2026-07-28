package matcherrequest

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/screening"
)

func ValidateBatch(batch RequestBatch) error {
	if batch.SchemaVersion != BatchSchemaVersion {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidRequestBatch, BatchSchemaVersion)
	}
	for field, value := range map[string]string{
		"batch_id":                     batch.BatchID,
		"input_evidence_bundle_id":     batch.InputEvidenceBundleID,
		"message_id":                   batch.MessageID,
		"message_definition":           string(batch.MessageDefinition),
		"message_namespace":            batch.MessageNamespace,
		"source_payload_reference":     batch.SourcePayloadReference,
		"parser_version":               batch.ParserVersion,
		"executor_version":             batch.ExecutorVersion,
		"projector_version":            batch.ProjectorVersion,
		"screening_plan.plan_id":       batch.ScreeningPlan.PlanID,
		"screening_plan.plan_version":  batch.ScreeningPlan.PlanVersion,
		"screening_plan.plan_checksum": batch.ScreeningPlan.PlanChecksum,
	} {
		if err := requireNonBlank(value, field, ErrInvalidRequestBatch); err != nil {
			return err
		}
	}
	if batch.ProjectorVersion != ProjectorVersion {
		return fmt.Errorf("%w: projector_version must be %q", ErrInvalidRequestBatch, ProjectorVersion)
	}
	seenRequests := map[string]struct{}{}
	seenEvidence := map[string]struct{}{}
	for index, request := range batch.Requests {
		if err := validateRequest(batch, index, request); err != nil {
			return err
		}
		if _, exists := seenRequests[request.RequestID]; exists {
			return fmt.Errorf("%w: duplicate request_id %q", ErrInvalidRequestBatch, request.RequestID)
		}
		seenRequests[request.RequestID] = struct{}{}
		if _, exists := seenEvidence[request.SourceLineage.EvidenceID]; exists {
			return fmt.Errorf("%w: duplicate source evidence_id %q", ErrInvalidRequestBatch, request.SourceLineage.EvidenceID)
		}
		seenEvidence[request.SourceLineage.EvidenceID] = struct{}{}
	}
	if expected := summarize(batch.Requests); !reflect.DeepEqual(batch.Summary, expected) {
		return fmt.Errorf("%w: summary does not match requests", ErrInvalidRequestBatch)
	}
	if expected := stableBatchID(batch); batch.BatchID != expected {
		return fmt.Errorf("%w: batch_id=%q expected %q", ErrInvalidRequestBatch, batch.BatchID, expected)
	}
	return nil
}

func validateRequest(batch RequestBatch, index int, request CandidateSearchRequest) error {
	if request.SchemaVersion != RequestSchemaVersion {
		return fmt.Errorf("%w: requests[%d].schema_version must be %q", ErrInvalidRequestBatch, index, RequestSchemaVersion)
	}
	for field, value := range map[string]string{
		"request_id":             request.RequestID,
		"request_kind":           string(request.RequestKind),
		"message_id":             request.MessageID,
		"native_path":            request.NativePath,
		"semantic_role":          string(request.SemanticRole),
		"value_type":             string(request.ValueType),
		"trigger_policy":         string(request.TriggerPolicy),
		"query.original_value":   request.Query.OriginalValue,
		"query.normalized_value": request.Query.NormalizedValue,
		"normalization_profile":  request.NormalizationProfile,
		"threshold_profile":      request.ThresholdProfile,
		"source_lineage.source_payload_reference":     request.SourceLineage.SourcePayloadReference,
		"source_lineage.parser_version":               request.SourceLineage.ParserVersion,
		"source_lineage.executor_version":             request.SourceLineage.ExecutorVersion,
		"source_lineage.evidence_bundle_id":           request.SourceLineage.EvidenceBundleID,
		"source_lineage.evidence_id":                  request.SourceLineage.EvidenceID,
		"source_lineage.element_id":                   request.SourceLineage.ElementID,
		"source_lineage.message_definition":           string(request.SourceLineage.MessageDefinition),
		"source_lineage.message_namespace":            request.SourceLineage.MessageNamespace,
		"source_lineage.screening_plan.plan_id":       request.SourceLineage.ScreeningPlan.PlanID,
		"source_lineage.screening_plan.plan_version":  request.SourceLineage.ScreeningPlan.PlanVersion,
		"source_lineage.screening_plan.plan_checksum": request.SourceLineage.ScreeningPlan.PlanChecksum,
	} {
		if err := requireNonBlank(value, fmt.Sprintf("requests[%d].%s", index, field), ErrInvalidRequestBatch); err != nil {
			return err
		}
	}
	if request.MessageID != batch.MessageID || request.SourceLineage.MessageDefinition != batch.MessageDefinition || request.SourceLineage.MessageNamespace != batch.MessageNamespace {
		return fmt.Errorf("%w: requests[%d] message identity differs from batch", ErrInvalidRequestBatch, index)
	}
	if request.SourceLineage.SourcePayloadReference != batch.SourcePayloadReference || request.SourceLineage.ParserVersion != batch.ParserVersion || request.SourceLineage.ExecutorVersion != batch.ExecutorVersion {
		return fmt.Errorf("%w: requests[%d] source lineage differs from batch", ErrInvalidRequestBatch, index)
	}
	if request.SourceLineage.EvidenceBundleID != batch.InputEvidenceBundleID || !reflect.DeepEqual(request.SourceLineage.ScreeningPlan, batch.ScreeningPlan) {
		return fmt.Errorf("%w: requests[%d] evidence or plan lineage differs from batch", ErrInvalidRequestBatch, index)
	}
	if len(request.MatchRoutes) == 0 {
		return fmt.Errorf("%w: requests[%d] must include match routes", ErrInvalidRequestBatch, index)
	}
	if len(request.TargetEntityTypes) == 0 {
		return fmt.Errorf("%w: requests[%d] must include target entity types", ErrInvalidRequestBatch, index)
	}
	switch request.RequestKind {
	case RequestCandidateAlert:
		if request.TriggerPolicy != canonical.TriggerCandidateAlert {
			return fmt.Errorf("%w: requests[%d] candidate request has trigger_policy %q", ErrInvalidRequestBatch, index, request.TriggerPolicy)
		}
	case RequestSupportingEvidence:
		if request.TriggerPolicy != canonical.TriggerSupportingEvidence {
			return fmt.Errorf("%w: requests[%d] supporting request has trigger_policy %q", ErrInvalidRequestBatch, index, request.TriggerPolicy)
		}
	default:
		return fmt.Errorf("%w: requests[%d] unsupported request_kind %q", ErrInvalidRequestBatch, index, request.RequestKind)
	}
	if expected := stableRequestID(request); request.RequestID != expected {
		return fmt.Errorf("%w: requests[%d].request_id=%q expected %q", ErrInvalidRequestBatch, index, request.RequestID, expected)
	}
	return nil
}

func ValidateReplay(envelope ReplayEnvelope) error {
	if envelope.SchemaVersion != ReplaySchemaVersion {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidReplayEnvelope, ReplaySchemaVersion)
	}
	for field, value := range map[string]string{
		"replay_id":                            envelope.ReplayID,
		"projector_version":                    envelope.ProjectorVersion,
		"projection_contract.selection_policy": envelope.ProjectionContract.SelectionPolicy,
		"projection_contract.ordering_policy":  envelope.ProjectionContract.OrderingPolicy,
		"projection_contract.identity_policy":  envelope.ProjectionContract.IdentityPolicy,
		"projection_contract.lineage_policy":   envelope.ProjectionContract.LineagePolicy,
		"input.evidence_schema_version":        envelope.Input.EvidenceSchemaVersion,
		"input.evidence_bundle_id":             envelope.Input.EvidenceBundleID,
		"input.source_payload_reference":       envelope.Input.SourcePayloadReference,
		"input.parser_version":                 envelope.Input.ParserVersion,
		"input.executor_version":               envelope.Input.ExecutorVersion,
		"input.screening_plan.plan_id":         envelope.Input.ScreeningPlan.PlanID,
		"input.screening_plan.plan_version":    envelope.Input.ScreeningPlan.PlanVersion,
		"input.screening_plan.plan_checksum":   envelope.Input.ScreeningPlan.PlanChecksum,
	} {
		if err := requireNonBlank(value, field, ErrInvalidReplayEnvelope); err != nil {
			return err
		}
	}
	if envelope.ProjectorVersion != ProjectorVersion {
		return fmt.Errorf("%w: projector_version must be %q", ErrInvalidReplayEnvelope, ProjectorVersion)
	}
	expectedContract := ProjectionContract{
		SelectionPolicy: SelectionPolicyEligibleOnly,
		OrderingPolicy:  OrderingPolicyEvidenceOrder,
		IdentityPolicy:  IdentityPolicyContentAddressed,
		LineagePolicy:   LineagePolicyFull,
	}
	if !reflect.DeepEqual(envelope.ProjectionContract, expectedContract) {
		return fmt.Errorf("%w: projection_contract differs from the supported contract", ErrInvalidReplayEnvelope)
	}
	if envelope.Input.EvidenceSchemaVersion != screening.EvidenceBundleSchemaVersion {
		return fmt.Errorf("%w: input.evidence_schema_version must be %q", ErrInvalidReplayEnvelope, screening.EvidenceBundleSchemaVersion)
	}
	if err := ValidateBatch(envelope.RequestBatch); err != nil {
		return fmt.Errorf("%w: request_batch: %v", ErrInvalidReplayEnvelope, err)
	}
	batch := envelope.RequestBatch
	if envelope.Input.EvidenceBundleID != batch.InputEvidenceBundleID || envelope.Input.SourcePayloadReference != batch.SourcePayloadReference || envelope.Input.ParserVersion != batch.ParserVersion || envelope.Input.ExecutorVersion != batch.ExecutorVersion || !reflect.DeepEqual(envelope.Input.ScreeningPlan, batch.ScreeningPlan) {
		return fmt.Errorf("%w: input lineage differs from request batch", ErrInvalidReplayEnvelope)
	}
	if expected := stableReplayID(envelope); envelope.ReplayID != expected {
		return fmt.Errorf("%w: replay_id=%q expected %q", ErrInvalidReplayEnvelope, envelope.ReplayID, expected)
	}
	return nil
}

func requireNonBlank(value, field string, sentinel error) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: %s is required", sentinel, field)
	}
	return nil
}
