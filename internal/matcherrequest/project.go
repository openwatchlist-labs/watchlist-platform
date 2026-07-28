package matcherrequest

import (
	"errors"
	"fmt"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/screening"
)

var (
	ErrProjection            = errors.New("matcher-request projection failed")
	ErrInvalidRequestBatch   = errors.New("invalid matcher request batch")
	ErrInvalidReplayEnvelope = errors.New("invalid matcher replay envelope")
)

type Projector struct{}

func NewProjector() *Projector {
	return &Projector{}
}

func (projector *Projector) Project(bundle screening.EvidenceBundle) (RequestBatch, error) {
	if err := screening.ValidateBundle(bundle); err != nil {
		return RequestBatch{}, fmt.Errorf("%w: validate evidence bundle: %v", ErrProjection, err)
	}
	batch := RequestBatch{
		SchemaVersion:          BatchSchemaVersion,
		InputEvidenceBundleID:  bundle.BundleID,
		MessageID:              bundle.MessageID,
		MessageDefinition:      bundle.MessageDefinition,
		MessageNamespace:       bundle.MessageNamespace,
		SourcePayloadReference: bundle.SourcePayloadReference,
		ParserVersion:          bundle.ParserVersion,
		ExecutorVersion:        bundle.ExecutorVersion,
		ProjectorVersion:       ProjectorVersion,
		ScreeningPlan:          bundle.ScreeningPlan,
		Requests:               make([]CandidateSearchRequest, 0, bundle.Summary.MatchEligibleElements),
	}
	for index, evidence := range bundle.Elements {
		if !evidence.Resolution.EligibleForMatching {
			continue
		}
		kind, err := requestKind(evidence.Resolution.TriggerPolicy)
		if err != nil {
			return RequestBatch{}, fmt.Errorf("%w: elements[%d] %s: %v", ErrProjection, index, evidence.NativePath, err)
		}
		request := CandidateSearchRequest{
			SchemaVersion:    RequestSchemaVersion,
			RequestKind:      kind,
			MessageID:        evidence.MessageID,
			TransactionID:    evidence.TransactionID,
			TransactionIndex: copyIndex(evidence.TransactionIndex),
			NativePath:       evidence.NativePath,
			Occurrence:       evidence.Occurrence,
			SemanticRole:     evidence.Resolution.SemanticRole,
			PartyRole:        evidence.Resolution.PartyRole,
			ValueType:        evidence.Resolution.ValueType,
			TriggerPolicy:    evidence.Resolution.TriggerPolicy,
			Query: QueryValue{
				OriginalValue:   evidence.OriginalValue,
				NormalizedValue: evidence.NormalizedValue,
				Attributes:      cloneMap(evidence.Attributes),
			},
			MatchRoutes:          append([]canonical.MatchRoute(nil), evidence.Resolution.MatchRoutes...),
			TargetEntityTypes:    append([]canonical.CandidateType(nil), evidence.Resolution.TargetEntityTypes...),
			NormalizationProfile: evidence.Resolution.NormalizationProfile,
			ThresholdProfile:     evidence.Resolution.ThresholdProfile,
			SupportingFields:     append([]canonical.SemanticRole(nil), evidence.Resolution.SupportingFields...),
			SourceLineage: SourceLineage{
				SourcePayloadReference: bundle.SourcePayloadReference,
				ParserVersion:          bundle.ParserVersion,
				ExecutorVersion:        bundle.ExecutorVersion,
				EvidenceBundleID:       bundle.BundleID,
				EvidenceID:             evidence.EvidenceID,
				ElementID:              evidence.ElementID,
				MessageDefinition:      evidence.MessageDefinition,
				MessageNamespace:       evidence.MessageNamespace,
				ScreeningPlan:          bundle.ScreeningPlan,
			},
		}
		request.RequestID = stableRequestID(request)
		batch.Requests = append(batch.Requests, request)
	}
	batch.Summary = summarize(batch.Requests)
	batch.BatchID = stableBatchID(batch)
	if err := ValidateBatch(batch); err != nil {
		return RequestBatch{}, err
	}
	return batch, nil
}

func (projector *Projector) Replay(bundle screening.EvidenceBundle) (ReplayEnvelope, error) {
	batch, err := projector.Project(bundle)
	if err != nil {
		return ReplayEnvelope{}, err
	}
	envelope := ReplayEnvelope{
		SchemaVersion:    ReplaySchemaVersion,
		ProjectorVersion: ProjectorVersion,
		ProjectionContract: ProjectionContract{
			SelectionPolicy: SelectionPolicyEligibleOnly,
			OrderingPolicy:  OrderingPolicyEvidenceOrder,
			IdentityPolicy:  IdentityPolicyContentAddressed,
			LineagePolicy:   LineagePolicyFull,
		},
		Input: ReplayInput{
			EvidenceSchemaVersion:  screening.EvidenceBundleSchemaVersion,
			EvidenceBundleID:       bundle.BundleID,
			SourcePayloadReference: bundle.SourcePayloadReference,
			ParserVersion:          bundle.ParserVersion,
			ExecutorVersion:        bundle.ExecutorVersion,
			ScreeningPlan:          bundle.ScreeningPlan,
		},
		RequestBatch: batch,
	}
	envelope.ReplayID = stableReplayID(envelope)
	if err := ValidateReplay(envelope); err != nil {
		return ReplayEnvelope{}, err
	}
	return envelope, nil
}

func requestKind(policy canonical.TriggerPolicy) (RequestKind, error) {
	switch policy {
	case canonical.TriggerCandidateAlert:
		return RequestCandidateAlert, nil
	case canonical.TriggerSupportingEvidence:
		return RequestSupportingEvidence, nil
	default:
		return "", fmt.Errorf("trigger policy %q is not match eligible", policy)
	}
}

func copyIndex(value *int) *int {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneMap(value map[string]string) map[string]string {
	if len(value) == 0 {
		return nil
	}
	copy := make(map[string]string, len(value))
	for key, item := range value {
		copy[key] = item
	}
	return copy
}
