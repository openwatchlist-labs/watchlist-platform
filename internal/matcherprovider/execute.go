package matcherprovider

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogruntime"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherrequest"
)

var (
	ErrProviderExecution     = errors.New("matcher provider execution failed")
	ErrInvalidDescriptor     = errors.New("invalid matcher provider descriptor")
	ErrInvalidCandidate      = errors.New("invalid provider candidate")
	ErrInvalidResultBatch    = errors.New("invalid candidate result batch")
	ErrInvalidProviderReplay = errors.New("invalid matcher provider replay envelope")
)

type Runner struct {
	provider   Provider
	descriptor ProviderDescriptor
}

func NewRunner(provider Provider) (*Runner, error) {
	if provider == nil {
		return nil, fmt.Errorf("%w: provider is required", ErrProviderExecution)
	}
	descriptor := provider.Descriptor()
	if err := ValidateDescriptor(descriptor); err != nil {
		return nil, err
	}
	return &Runner{provider: provider, descriptor: descriptor}, nil
}

func (runner *Runner) Execute(ctx context.Context, batch matcherrequest.RequestBatch) (ResultBatch, error) {
	return runner.execute(ctx, batch, nil)
}

func (runner *Runner) ExecuteStamped(ctx context.Context, batch matcherrequest.RequestBatch, stamp catalogruntime.GenerationStamp) (ResultBatch, error) {
	if err := catalogruntime.ValidateGenerationStamp(stamp); err != nil {
		return ResultBatch{}, fmt.Errorf("%w: runtime generation: %v", ErrProviderExecution, err)
	}
	if stamp.CatalogID != runner.descriptor.Catalog.CatalogID || stamp.CatalogVersion != runner.descriptor.Catalog.CatalogVersion || stamp.CatalogChecksum != runner.descriptor.Catalog.CatalogChecksum {
		return ResultBatch{}, fmt.Errorf("%w: runtime generation catalog differs from provider", ErrProviderExecution)
	}
	return runner.execute(ctx, batch, &stamp)
}

func (runner *Runner) execute(ctx context.Context, batch matcherrequest.RequestBatch, generation *catalogruntime.GenerationStamp) (ResultBatch, error) {
	if err := matcherrequest.ValidateBatch(batch); err != nil {
		return ResultBatch{}, fmt.Errorf("%w: validate request batch: %v", ErrProviderExecution, err)
	}
	output := ResultBatch{
		SchemaVersion:       ResultBatchSchemaVersion,
		InputRequestBatchID: batch.BatchID,
		MessageID:           batch.MessageID,
		RunnerVersion:       RunnerVersion,
		Provider:            runner.descriptor,
		RuntimeGeneration:   cloneGenerationStamp(generation),
		Results:             make([]CandidateSearchResult, 0, len(batch.Requests)),
	}
	for index, request := range batch.Requests {
		if err := validateRequestCompatibility(runner.descriptor, request); err != nil {
			return ResultBatch{}, fmt.Errorf("%w: requests[%d]: %v", ErrProviderExecution, index, err)
		}
		var providerCandidates []ProviderCandidate
		var diagnostics []CandidateDiagnostic
		var err error
		if diagnosticProvider, ok := runner.provider.(DiagnosticProvider); ok {
			providerCandidates, diagnostics, err = diagnosticProvider.SearchWithDiagnostics(ctx, request)
		} else {
			providerCandidates, err = runner.provider.Search(ctx, request)
		}
		if err != nil {
			return ResultBatch{}, fmt.Errorf("%w: requests[%d] %s: %v", ErrProviderExecution, index, request.RequestID, err)
		}
		sortDiagnostics(diagnostics)
		if len(providerCandidates) > runner.descriptor.Capabilities.MaxCandidatesPerRequest {
			return ResultBatch{}, fmt.Errorf("%w: requests[%d] returned %d candidates, maximum is %d", ErrProviderExecution, index, len(providerCandidates), runner.descriptor.Capabilities.MaxCandidatesPerRequest)
		}
		candidates := make([]CandidateMatch, 0, len(providerCandidates))
		seenRecords := map[string]struct{}{}
		for candidateIndex, providerCandidate := range providerCandidates {
			if err := validateProviderCandidate(runner.descriptor, request, providerCandidate); err != nil {
				return ResultBatch{}, fmt.Errorf("%w: requests[%d].candidates[%d]: %v", ErrProviderExecution, index, candidateIndex, err)
			}
			key := providerCandidate.ProviderRecordID + "\x1f" + string(providerCandidate.MatchRoute)
			if _, exists := seenRecords[key]; exists {
				return ResultBatch{}, fmt.Errorf("%w: requests[%d] duplicate provider candidate %q for route %q", ErrProviderExecution, index, providerCandidate.ProviderRecordID, providerCandidate.MatchRoute)
			}
			seenRecords[key] = struct{}{}
			candidate := canonicalizeCandidate(providerCandidate)
			candidate.CandidateID = stableCandidateID(request.RequestID, runner.descriptor, candidate)
			candidates = append(candidates, candidate)
		}
		sortCandidates(candidates)
		status := ResultNoCandidates
		if len(candidates) > 0 {
			status = ResultMatched
		}
		result := CandidateSearchResult{
			SchemaVersion:     CandidateResultSchemaVersion,
			Status:            status,
			Request:           requestLineage(request),
			Provider:          runner.descriptor,
			RuntimeGeneration: cloneGenerationStamp(generation),
			CandidateCount:    len(candidates),
			Candidates:        candidates,
			Diagnostics:       cloneDiagnostics(diagnostics),
		}
		result.ResultID = stableResultID(result)
		output.Results = append(output.Results, result)
	}
	output.Summary = summarizeResults(output.Results)
	output.ResultBatchID = stableResultBatchID(output)
	if err := ValidateResultBatch(output); err != nil {
		return ResultBatch{}, err
	}
	return output, nil
}

func (runner *Runner) Replay(ctx context.Context, input matcherrequest.ReplayEnvelope) (ProviderReplayEnvelope, error) {
	return runner.replay(ctx, input, nil)
}

func (runner *Runner) ReplayStamped(ctx context.Context, input matcherrequest.ReplayEnvelope, stamp catalogruntime.GenerationStamp) (ProviderReplayEnvelope, error) {
	if err := catalogruntime.ValidateGenerationStamp(stamp); err != nil {
		return ProviderReplayEnvelope{}, fmt.Errorf("%w: runtime generation: %v", ErrProviderExecution, err)
	}
	if stamp.CatalogID != runner.descriptor.Catalog.CatalogID || stamp.CatalogVersion != runner.descriptor.Catalog.CatalogVersion || stamp.CatalogChecksum != runner.descriptor.Catalog.CatalogChecksum {
		return ProviderReplayEnvelope{}, fmt.Errorf("%w: runtime generation catalog differs from provider", ErrProviderExecution)
	}
	return runner.replay(ctx, input, &stamp)
}

func (runner *Runner) replay(ctx context.Context, input matcherrequest.ReplayEnvelope, generation *catalogruntime.GenerationStamp) (ProviderReplayEnvelope, error) {
	if err := matcherrequest.ValidateReplay(input); err != nil {
		return ProviderReplayEnvelope{}, fmt.Errorf("%w: validate matcher replay: %v", ErrProviderExecution, err)
	}
	results, err := runner.execute(ctx, input.RequestBatch, generation)
	if err != nil {
		return ProviderReplayEnvelope{}, err
	}
	envelope := ProviderReplayEnvelope{
		SchemaVersion: ProviderReplaySchemaVersion,
		RunnerVersion: RunnerVersion,
		ExecutionContract: ExecutionContract{
			RequestOrdering:   RequestOrderingInputOrder,
			CandidateOrdering: CandidateOrderingCanonical,
			IdentityPolicy:    ResultIdentityContentAddressed,
			FailurePolicy:     FailurePolicyAtomic,
			LineagePolicy:     LineagePolicyRequestAndCatalog,
		},
		InputReplay: input,
		ResultBatch: results,
	}
	envelope.ReplayID = stableProviderReplayID(envelope)
	if err := ValidateProviderReplay(envelope); err != nil {
		return ProviderReplayEnvelope{}, err
	}
	return envelope, nil
}

func cloneGenerationStamp(stamp *catalogruntime.GenerationStamp) *catalogruntime.GenerationStamp {
	if stamp == nil {
		return nil
	}
	copy := *stamp
	return &copy
}

func requestLineage(request matcherrequest.CandidateSearchRequest) RequestLineage {
	return RequestLineage{
		RequestID:            request.RequestID,
		RequestKind:          request.RequestKind,
		MessageID:            request.MessageID,
		TransactionID:        request.TransactionID,
		TransactionIndex:     copyIndex(request.TransactionIndex),
		NativePath:           request.NativePath,
		Occurrence:           request.Occurrence,
		SemanticRole:         request.SemanticRole,
		PartyRole:            request.PartyRole,
		ValueType:            request.ValueType,
		TriggerPolicy:        request.TriggerPolicy,
		Query:                request.Query,
		MatchRoutes:          append([]canonical.MatchRoute(nil), request.MatchRoutes...),
		TargetEntityTypes:    append([]canonical.CandidateType(nil), request.TargetEntityTypes...),
		NormalizationProfile: request.NormalizationProfile,
		ThresholdProfile:     request.ThresholdProfile,
		SupportingFields:     append([]canonical.SemanticRole(nil), request.SupportingFields...),
		SourceLineage:        request.SourceLineage,
	}
}

func canonicalizeCandidate(candidate ProviderCandidate) CandidateMatch {
	assertions := append([]SourceAssertion(nil), candidate.SourceAssertions...)
	for index := range assertions {
		assertions[index].Programs = append([]string(nil), assertions[index].Programs...)
		sort.Strings(assertions[index].Programs)
	}
	sort.Slice(assertions, func(i, j int) bool {
		left, right := assertions[i], assertions[j]
		if left.SourceID != right.SourceID {
			return left.SourceID < right.SourceID
		}
		if left.ListID != right.ListID {
			return left.ListID < right.ListID
		}
		return left.SourceRecordID < right.SourceRecordID
	})
	attributes := make(map[string]string, len(candidate.Attributes))
	for key, value := range candidate.Attributes {
		attributes[key] = value
	}
	if len(attributes) == 0 {
		attributes = nil
	}
	return CandidateMatch{
		ProviderRecordID:       candidate.ProviderRecordID,
		ProviderEntityID:       candidate.ProviderEntityID,
		EntityType:             candidate.EntityType,
		PrimaryName:            candidate.PrimaryName,
		MatchedValue:           candidate.MatchedValue,
		NormalizedMatchedValue: candidate.NormalizedMatchedValue,
		MatchRoute:             candidate.MatchRoute,
		ScoreBasisPoints:       candidate.ScoreBasisPoints,
		Exact:                  candidate.Exact,
		Attributes:             attributes,
		Evidence:               cloneMatchEvidence(candidate.Evidence),
		SourceAssertions:       assertions,
	}
}

func cloneMatchEvidence(evidence *MatchEvidence) *MatchEvidence {
	if evidence == nil {
		return nil
	}
	copy := *evidence
	copy.ReasonCodes = append([]string(nil), evidence.ReasonCodes...)
	copy.Features = append([]FeatureEvidence(nil), evidence.Features...)
	return &copy
}

func cloneDiagnostics(values []CandidateDiagnostic) []CandidateDiagnostic {
	if len(values) == 0 {
		return nil
	}
	out := make([]CandidateDiagnostic, len(values))
	for index, value := range values {
		out[index] = value
		out[index].Evidence = cloneMatchEvidence(value.Evidence)
		out[index].SourceAssertions = append([]SourceAssertion(nil), value.SourceAssertions...)
		for assertionIndex := range out[index].SourceAssertions {
			out[index].SourceAssertions[assertionIndex].Programs = append([]string(nil), out[index].SourceAssertions[assertionIndex].Programs...)
		}
	}
	return out
}

func sortDiagnostics(values []CandidateDiagnostic) {
	sort.Slice(values, func(i, j int) bool {
		left, right := values[i], values[j]
		if left.ScoreBasisPoints != right.ScoreBasisPoints {
			return left.ScoreBasisPoints > right.ScoreBasisPoints
		}
		if left.Code != right.Code {
			return left.Code < right.Code
		}
		if left.ProviderRecordID != right.ProviderRecordID {
			return left.ProviderRecordID < right.ProviderRecordID
		}
		return left.MatchRoute < right.MatchRoute
	})
}

func sortCandidates(candidates []CandidateMatch) {
	sort.Slice(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		if left.ScoreBasisPoints != right.ScoreBasisPoints {
			return left.ScoreBasisPoints > right.ScoreBasisPoints
		}
		if left.Exact != right.Exact {
			return left.Exact
		}
		if left.ProviderRecordID != right.ProviderRecordID {
			return left.ProviderRecordID < right.ProviderRecordID
		}
		if left.MatchRoute != right.MatchRoute {
			return left.MatchRoute < right.MatchRoute
		}
		return left.NormalizedMatchedValue < right.NormalizedMatchedValue
	})
}

func copyIndex(value *int) *int {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}
