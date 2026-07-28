package matcherprovider

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogruntime"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherrequest"
)

func ValidateDescriptor(descriptor ProviderDescriptor) error {
	if descriptor.SchemaVersion != ProviderDescriptorSchemaVersion {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidDescriptor, ProviderDescriptorSchemaVersion)
	}
	for field, value := range map[string]string{
		"provider_id":              descriptor.ProviderID,
		"provider_version":         descriptor.ProviderVersion,
		"catalog.catalog_id":       descriptor.Catalog.CatalogID,
		"catalog.catalog_version":  descriptor.Catalog.CatalogVersion,
		"catalog.catalog_checksum": descriptor.Catalog.CatalogChecksum,
	} {
		if err := requireNonBlank(value, field, ErrInvalidDescriptor); err != nil {
			return err
		}
	}
	if len(descriptor.Catalog.CatalogChecksum) != 64 {
		return fmt.Errorf("%w: catalog.catalog_checksum must be a 64-character SHA-256 hex digest", ErrInvalidDescriptor)
	}
	if _, err := hex.DecodeString(descriptor.Catalog.CatalogChecksum); err != nil {
		return fmt.Errorf("%w: catalog.catalog_checksum is not hexadecimal", ErrInvalidDescriptor)
	}
	switch descriptor.Catalog.CatalogMode {
	case CatalogModeDirectList, CatalogModeProviderEntity, CatalogModeHybridOverlay:
	default:
		return fmt.Errorf("%w: unsupported catalog.catalog_mode %q", ErrInvalidDescriptor, descriptor.Catalog.CatalogMode)
	}
	capabilities := descriptor.Capabilities
	if capabilities.MaxCandidatesPerRequest <= 0 || capabilities.MaxCandidatesPerRequest > 1000 {
		return fmt.Errorf("%w: capabilities.max_candidates_per_request must be between 1 and 1000", ErrInvalidDescriptor)
	}
	if !capabilities.Deterministic {
		return fmt.Errorf("%w: capabilities.deterministic must be true", ErrInvalidDescriptor)
	}
	if !capabilities.SourceAssertionsIncluded {
		return fmt.Errorf("%w: capabilities.source_assertions_included must be true", ErrInvalidDescriptor)
	}
	if err := validateSortedUniqueRoutes(capabilities.SupportedRoutes, "capabilities.supported_routes", ErrInvalidDescriptor); err != nil {
		return err
	}
	if err := validateSortedUniqueTypes(capabilities.SupportedEntityTypes, "capabilities.supported_entity_types", ErrInvalidDescriptor); err != nil {
		return err
	}
	return nil
}

func validateRequestCompatibility(descriptor ProviderDescriptor, request matcherrequest.CandidateSearchRequest) error {
	if !hasRouteIntersection(request.MatchRoutes, descriptor.Capabilities.SupportedRoutes) {
		return fmt.Errorf("provider %q supports none of the request match routes", descriptor.ProviderID)
	}
	if !hasTypeIntersection(request.TargetEntityTypes, descriptor.Capabilities.SupportedEntityTypes) {
		return fmt.Errorf("provider %q supports none of the request target entity types", descriptor.ProviderID)
	}
	return nil
}

func validateProviderCandidate(descriptor ProviderDescriptor, request matcherrequest.CandidateSearchRequest, candidate ProviderCandidate) error {
	for field, value := range map[string]string{
		"provider_record_id":       candidate.ProviderRecordID,
		"primary_name":             candidate.PrimaryName,
		"matched_value":            candidate.MatchedValue,
		"normalized_matched_value": candidate.NormalizedMatchedValue,
	} {
		if err := requireNonBlank(value, field, ErrInvalidCandidate); err != nil {
			return err
		}
	}
	if descriptor.Catalog.CatalogMode == CatalogModeProviderEntity && strings.TrimSpace(candidate.ProviderEntityID) == "" {
		return fmt.Errorf("%w: provider_entity_id is required for provider_entity catalogs", ErrInvalidCandidate)
	}
	if !containsRoute(request.MatchRoutes, candidate.MatchRoute) {
		return fmt.Errorf("%w: match_route %q is not permitted by request %s", ErrInvalidCandidate, candidate.MatchRoute, request.RequestID)
	}
	if !containsRoute(descriptor.Capabilities.SupportedRoutes, candidate.MatchRoute) {
		return fmt.Errorf("%w: match_route %q is not supported by provider", ErrInvalidCandidate, candidate.MatchRoute)
	}
	if !containsType(request.TargetEntityTypes, candidate.EntityType) {
		return fmt.Errorf("%w: entity_type %q is not permitted by request %s", ErrInvalidCandidate, candidate.EntityType, request.RequestID)
	}
	if !containsType(descriptor.Capabilities.SupportedEntityTypes, candidate.EntityType) {
		return fmt.Errorf("%w: entity_type %q is not supported by provider", ErrInvalidCandidate, candidate.EntityType)
	}
	if candidate.ScoreBasisPoints < 0 || candidate.ScoreBasisPoints > 10000 {
		return fmt.Errorf("%w: score_basis_points must be between 0 and 10000", ErrInvalidCandidate)
	}
	if err := validateMatchEvidence(candidate.Evidence, candidate.ScoreBasisPoints); err != nil {
		return fmt.Errorf("%w: evidence: %v", ErrInvalidCandidate, err)
	}
	if len(candidate.SourceAssertions) == 0 {
		return fmt.Errorf("%w: at least one source_assertion is required", ErrInvalidCandidate)
	}
	seenAssertions := map[string]struct{}{}
	for index, assertion := range candidate.SourceAssertions {
		for field, value := range map[string]string{
			"source_id":        assertion.SourceID,
			"authority":        assertion.Authority,
			"list_id":          assertion.ListID,
			"source_record_id": assertion.SourceRecordID,
		} {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("%w: source_assertions[%d].%s is required", ErrInvalidCandidate, index, field)
			}
		}
		key := assertion.SourceID + "\x1f" + assertion.ListID + "\x1f" + assertion.SourceRecordID
		if _, exists := seenAssertions[key]; exists {
			return fmt.Errorf("%w: duplicate source assertion %q", ErrInvalidCandidate, key)
		}
		seenAssertions[key] = struct{}{}
	}
	return nil
}

func ValidateResultBatch(batch ResultBatch) error {
	if batch.SchemaVersion != ResultBatchSchemaVersion {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidResultBatch, ResultBatchSchemaVersion)
	}
	for field, value := range map[string]string{
		"result_batch_id":        batch.ResultBatchID,
		"input_request_batch_id": batch.InputRequestBatchID,
		"message_id":             batch.MessageID,
		"runner_version":         batch.RunnerVersion,
	} {
		if err := requireNonBlank(value, field, ErrInvalidResultBatch); err != nil {
			return err
		}
	}
	if batch.RunnerVersion != RunnerVersion {
		return fmt.Errorf("%w: runner_version must be %q", ErrInvalidResultBatch, RunnerVersion)
	}
	if err := ValidateDescriptor(batch.Provider); err != nil {
		return fmt.Errorf("%w: provider: %v", ErrInvalidResultBatch, err)
	}
	if batch.RuntimeGeneration != nil {
		if err := catalogruntime.ValidateGenerationStamp(*batch.RuntimeGeneration); err != nil {
			return fmt.Errorf("%w: runtime_generation: %v", ErrInvalidResultBatch, err)
		}
		if batch.RuntimeGeneration.CatalogID != batch.Provider.Catalog.CatalogID || batch.RuntimeGeneration.CatalogVersion != batch.Provider.Catalog.CatalogVersion || batch.RuntimeGeneration.CatalogChecksum != batch.Provider.Catalog.CatalogChecksum {
			return fmt.Errorf("%w: runtime_generation catalog differs from provider", ErrInvalidResultBatch)
		}
	}
	seenRequests := map[string]struct{}{}
	seenResults := map[string]struct{}{}
	for index, result := range batch.Results {
		if err := validateResult(batch, index, result); err != nil {
			return err
		}
		if _, exists := seenRequests[result.Request.RequestID]; exists {
			return fmt.Errorf("%w: duplicate request_id %q", ErrInvalidResultBatch, result.Request.RequestID)
		}
		seenRequests[result.Request.RequestID] = struct{}{}
		if _, exists := seenResults[result.ResultID]; exists {
			return fmt.Errorf("%w: duplicate result_id %q", ErrInvalidResultBatch, result.ResultID)
		}
		seenResults[result.ResultID] = struct{}{}
	}
	if expected := summarizeResults(batch.Results); !reflect.DeepEqual(batch.Summary, expected) {
		return fmt.Errorf("%w: summary differs from results", ErrInvalidResultBatch)
	}
	if expected := stableResultBatchID(batch); batch.ResultBatchID != expected {
		return fmt.Errorf("%w: result_batch_id=%q expected %q", ErrInvalidResultBatch, batch.ResultBatchID, expected)
	}
	return nil
}

func validateResult(batch ResultBatch, index int, result CandidateSearchResult) error {
	if result.SchemaVersion != CandidateResultSchemaVersion {
		return fmt.Errorf("%w: results[%d].schema_version must be %q", ErrInvalidResultBatch, index, CandidateResultSchemaVersion)
	}
	for field, value := range map[string]string{
		"result_id":                                           result.ResultID,
		"request.request_id":                                  result.Request.RequestID,
		"request.message_id":                                  result.Request.MessageID,
		"request.native_path":                                 result.Request.NativePath,
		"request.query.normalized_value":                      result.Request.Query.NormalizedValue,
		"request.normalization_profile":                       result.Request.NormalizationProfile,
		"request.threshold_profile":                           result.Request.ThresholdProfile,
		"request.source_lineage.evidence_id":                  result.Request.SourceLineage.EvidenceID,
		"request.source_lineage.element_id":                   result.Request.SourceLineage.ElementID,
		"request.source_lineage.screening_plan.plan_id":       result.Request.SourceLineage.ScreeningPlan.PlanID,
		"request.source_lineage.screening_plan.plan_version":  result.Request.SourceLineage.ScreeningPlan.PlanVersion,
		"request.source_lineage.screening_plan.plan_checksum": result.Request.SourceLineage.ScreeningPlan.PlanChecksum,
	} {
		if err := requireNonBlank(value, fmt.Sprintf("results[%d].%s", index, field), ErrInvalidResultBatch); err != nil {
			return err
		}
	}
	if result.Request.MessageID != batch.MessageID {
		return fmt.Errorf("%w: results[%d] message_id differs from batch", ErrInvalidResultBatch, index)
	}
	if !reflect.DeepEqual(result.Provider, batch.Provider) {
		return fmt.Errorf("%w: results[%d] provider differs from batch", ErrInvalidResultBatch, index)
	}
	if !reflect.DeepEqual(result.RuntimeGeneration, batch.RuntimeGeneration) {
		return fmt.Errorf("%w: results[%d] runtime_generation differs from batch", ErrInvalidResultBatch, index)
	}
	if result.CandidateCount != len(result.Candidates) {
		return fmt.Errorf("%w: results[%d].candidate_count=%d expected %d", ErrInvalidResultBatch, index, result.CandidateCount, len(result.Candidates))
	}
	switch result.Status {
	case ResultMatched:
		if len(result.Candidates) == 0 {
			return fmt.Errorf("%w: results[%d] matched status requires candidates", ErrInvalidResultBatch, index)
		}
	case ResultNoCandidates:
		if len(result.Candidates) != 0 {
			return fmt.Errorf("%w: results[%d] no_candidates status cannot include candidates", ErrInvalidResultBatch, index)
		}
	default:
		return fmt.Errorf("%w: results[%d] unsupported status %q", ErrInvalidResultBatch, index, result.Status)
	}
	if !candidatesCanonical(result.Candidates) {
		return fmt.Errorf("%w: results[%d] candidates are not in canonical order", ErrInvalidResultBatch, index)
	}
	seenCandidates := map[string]struct{}{}
	for candidateIndex, candidate := range result.Candidates {
		if err := validateCandidateMatch(batch.Provider, result.Request, candidate); err != nil {
			return fmt.Errorf("%w: results[%d].candidates[%d]: %v", ErrInvalidResultBatch, index, candidateIndex, err)
		}
		if _, exists := seenCandidates[candidate.CandidateID]; exists {
			return fmt.Errorf("%w: results[%d] duplicate candidate_id %q", ErrInvalidResultBatch, index, candidate.CandidateID)
		}
		seenCandidates[candidate.CandidateID] = struct{}{}
	}
	if !diagnosticsCanonical(result.Diagnostics) {
		return fmt.Errorf("%w: results[%d] diagnostics are not in canonical order", ErrInvalidResultBatch, index)
	}
	seenDiagnostics := map[string]struct{}{}
	for diagnosticIndex, diagnostic := range result.Diagnostics {
		if err := validateDiagnostic(result.Request, diagnostic); err != nil {
			return fmt.Errorf("%w: results[%d].diagnostics[%d]: %v", ErrInvalidResultBatch, index, diagnosticIndex, err)
		}
		key := diagnostic.Code + "\x1f" + diagnostic.ProviderRecordID + "\x1f" + string(diagnostic.MatchRoute)
		if _, exists := seenDiagnostics[key]; exists {
			return fmt.Errorf("%w: results[%d] duplicate diagnostic %q", ErrInvalidResultBatch, index, key)
		}
		seenDiagnostics[key] = struct{}{}
	}
	if expected := stableResultID(result); result.ResultID != expected {
		return fmt.Errorf("%w: results[%d].result_id=%q expected %q", ErrInvalidResultBatch, index, result.ResultID, expected)
	}
	return nil
}

func validateCandidateMatch(provider ProviderDescriptor, request RequestLineage, candidate CandidateMatch) error {
	providerCandidate := ProviderCandidate{
		ProviderRecordID:       candidate.ProviderRecordID,
		ProviderEntityID:       candidate.ProviderEntityID,
		EntityType:             candidate.EntityType,
		PrimaryName:            candidate.PrimaryName,
		MatchedValue:           candidate.MatchedValue,
		NormalizedMatchedValue: candidate.NormalizedMatchedValue,
		MatchRoute:             candidate.MatchRoute,
		ScoreBasisPoints:       candidate.ScoreBasisPoints,
		Exact:                  candidate.Exact,
		Attributes:             candidate.Attributes,
		Evidence:               candidate.Evidence,
		SourceAssertions:       candidate.SourceAssertions,
	}
	requestValue := matcherrequest.CandidateSearchRequest{
		RequestID:         request.RequestID,
		MatchRoutes:       request.MatchRoutes,
		TargetEntityTypes: request.TargetEntityTypes,
	}
	if err := validateProviderCandidate(provider, requestValue, providerCandidate); err != nil {
		return err
	}
	if !assertionsCanonical(candidate.SourceAssertions) {
		return fmt.Errorf("source_assertions are not in canonical order")
	}
	if expected := stableCandidateID(request.RequestID, provider, candidate); candidate.CandidateID != expected {
		return fmt.Errorf("candidate_id=%q expected %q", candidate.CandidateID, expected)
	}
	return nil
}

func ValidateProviderReplay(envelope ProviderReplayEnvelope) error {
	if envelope.SchemaVersion != ProviderReplaySchemaVersion {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidProviderReplay, ProviderReplaySchemaVersion)
	}
	if err := requireNonBlank(envelope.ReplayID, "replay_id", ErrInvalidProviderReplay); err != nil {
		return err
	}
	if envelope.RunnerVersion != RunnerVersion {
		return fmt.Errorf("%w: runner_version must be %q", ErrInvalidProviderReplay, RunnerVersion)
	}
	expectedContract := ExecutionContract{
		RequestOrdering:   RequestOrderingInputOrder,
		CandidateOrdering: CandidateOrderingCanonical,
		IdentityPolicy:    ResultIdentityContentAddressed,
		FailurePolicy:     FailurePolicyAtomic,
		LineagePolicy:     LineagePolicyRequestAndCatalog,
	}
	if !reflect.DeepEqual(envelope.ExecutionContract, expectedContract) {
		return fmt.Errorf("%w: execution_contract differs from the supported contract", ErrInvalidProviderReplay)
	}
	if err := matcherrequest.ValidateReplay(envelope.InputReplay); err != nil {
		return fmt.Errorf("%w: input_replay: %v", ErrInvalidProviderReplay, err)
	}
	if err := ValidateResultBatch(envelope.ResultBatch); err != nil {
		return fmt.Errorf("%w: result_batch: %v", ErrInvalidProviderReplay, err)
	}
	if envelope.ResultBatch.InputRequestBatchID != envelope.InputReplay.RequestBatch.BatchID {
		return fmt.Errorf("%w: result batch input does not match input replay request batch", ErrInvalidProviderReplay)
	}
	if len(envelope.ResultBatch.Results) != len(envelope.InputReplay.RequestBatch.Requests) {
		return fmt.Errorf("%w: result count differs from input request count", ErrInvalidProviderReplay)
	}
	for index, request := range envelope.InputReplay.RequestBatch.Requests {
		if !reflect.DeepEqual(envelope.ResultBatch.Results[index].Request, requestLineage(request)) {
			return fmt.Errorf("%w: results[%d] request lineage differs from input replay", ErrInvalidProviderReplay, index)
		}
	}
	if expected := stableProviderReplayID(envelope); envelope.ReplayID != expected {
		return fmt.Errorf("%w: replay_id=%q expected %q", ErrInvalidProviderReplay, envelope.ReplayID, expected)
	}
	return nil
}

func candidatesCanonical(candidates []CandidateMatch) bool {
	if len(candidates) < 2 {
		return true
	}
	copyCandidates := append([]CandidateMatch(nil), candidates...)
	sortCandidates(copyCandidates)
	return reflect.DeepEqual(candidates, copyCandidates)
}

func assertionsCanonical(assertions []SourceAssertion) bool {
	for _, assertion := range assertions {
		if !sort.StringsAreSorted(assertion.Programs) {
			return false
		}
	}
	copyAssertions := append([]SourceAssertion(nil), assertions...)
	sort.Slice(copyAssertions, func(i, j int) bool {
		left, right := copyAssertions[i], copyAssertions[j]
		if left.SourceID != right.SourceID {
			return left.SourceID < right.SourceID
		}
		if left.ListID != right.ListID {
			return left.ListID < right.ListID
		}
		return left.SourceRecordID < right.SourceRecordID
	})
	return reflect.DeepEqual(assertions, copyAssertions)
}

func validateSortedUniqueRoutes(values []canonical.MatchRoute, field string, sentinel error) error {
	if len(values) == 0 {
		return fmt.Errorf("%w: %s must not be empty", sentinel, field)
	}
	seen := map[canonical.MatchRoute]struct{}{}
	previous := ""
	for index, value := range values {
		if strings.TrimSpace(string(value)) == "" {
			return fmt.Errorf("%w: %s[%d] is blank", sentinel, field, index)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%w: %s contains duplicate %q", sentinel, field, value)
		}
		seen[value] = struct{}{}
		if index > 0 && previous > string(value) {
			return fmt.Errorf("%w: %s must be sorted", sentinel, field)
		}
		previous = string(value)
	}
	return nil
}

func validateSortedUniqueTypes(values []canonical.CandidateType, field string, sentinel error) error {
	if len(values) == 0 {
		return fmt.Errorf("%w: %s must not be empty", sentinel, field)
	}
	seen := map[canonical.CandidateType]struct{}{}
	previous := ""
	for index, value := range values {
		if strings.TrimSpace(string(value)) == "" {
			return fmt.Errorf("%w: %s[%d] is blank", sentinel, field, index)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%w: %s contains duplicate %q", sentinel, field, value)
		}
		seen[value] = struct{}{}
		if index > 0 && previous > string(value) {
			return fmt.Errorf("%w: %s must be sorted", sentinel, field)
		}
		previous = string(value)
	}
	return nil
}

func hasRouteIntersection(left, right []canonical.MatchRoute) bool {
	for _, value := range left {
		if containsRoute(right, value) {
			return true
		}
	}
	return false
}

func hasTypeIntersection(left, right []canonical.CandidateType) bool {
	for _, value := range left {
		if containsType(right, value) {
			return true
		}
	}
	return false
}

func containsRoute(values []canonical.MatchRoute, target canonical.MatchRoute) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsType(values []canonical.CandidateType, target canonical.CandidateType) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func requireNonBlank(value, field string, sentinel error) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: %s is required", sentinel, field)
	}
	return nil
}

func validateMatchEvidence(evidence *MatchEvidence, expectedScore int) error {
	if evidence == nil {
		return nil
	}
	if evidence.SchemaVersion != MatchEvidenceSchemaVersion {
		return fmt.Errorf("schema_version must be %q", MatchEvidenceSchemaVersion)
	}
	for field, value := range map[string]string{"matcher_version": evidence.MatcherVersion, "profile_set_id": evidence.ProfileSetID, "profile_set_checksum": evidence.ProfileSetChecksum, "threshold_profile": evidence.ThresholdProfile} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}
	if len(evidence.ProfileSetChecksum) != 64 {
		return fmt.Errorf("profile_set_checksum must be a 64-character SHA-256 hex digest")
	}
	if _, err := hex.DecodeString(evidence.ProfileSetChecksum); err != nil {
		return fmt.Errorf("profile_set_checksum is not hexadecimal")
	}
	if evidence.ThresholdBasisPoints < 0 || evidence.ThresholdBasisPoints > 10000 {
		return fmt.Errorf("threshold_basis_points must be between 0 and 10000")
	}
	if evidence.PenaltyBasisPoints < 0 || evidence.PenaltyBasisPoints > 10000 {
		return fmt.Errorf("penalty_basis_points must be between 0 and 10000")
	}
	if len(evidence.ReasonCodes) == 0 || !sort.StringsAreSorted(evidence.ReasonCodes) {
		return fmt.Errorf("reason_codes must be non-empty and sorted")
	}
	for i, code := range evidence.ReasonCodes {
		if strings.TrimSpace(code) == "" {
			return fmt.Errorf("reason_codes[%d] is blank", i)
		}
		if i > 0 && evidence.ReasonCodes[i-1] == code {
			return fmt.Errorf("reason_codes contains duplicate %q", code)
		}
	}
	if len(evidence.Features) == 0 {
		return fmt.Errorf("features must not be empty")
	}
	weightTotal, contributionTotal := 0, 0
	previous := ""
	for i, feature := range evidence.Features {
		if strings.TrimSpace(feature.Name) == "" {
			return fmt.Errorf("features[%d].name is required", i)
		}
		if i > 0 && previous >= feature.Name {
			return fmt.Errorf("features must be sorted by unique name")
		}
		previous = feature.Name
		if feature.ScoreBasisPoints < 0 || feature.ScoreBasisPoints > 10000 || feature.WeightBasisPoints < 0 || feature.WeightBasisPoints > 10000 {
			return fmt.Errorf("features[%d] score and weight must be between 0 and 10000", i)
		}
		expected := feature.ScoreBasisPoints * feature.WeightBasisPoints / 10000
		if feature.ContributionBasisPoints != expected {
			return fmt.Errorf("features[%d].contribution_basis_points=%d expected %d", i, feature.ContributionBasisPoints, expected)
		}
		weightTotal += feature.WeightBasisPoints
		contributionTotal += feature.ContributionBasisPoints
	}
	if weightTotal != 10000 {
		return fmt.Errorf("feature weights total %d, expected 10000", weightTotal)
	}
	computed := contributionTotal - evidence.PenaltyBasisPoints
	if computed < 0 {
		computed = 0
	}
	if computed != expectedScore {
		return fmt.Errorf("feature score %d differs from candidate score %d", computed, expectedScore)
	}
	if err := validateContextEvidence(evidence.Context); err != nil {
		return fmt.Errorf("context: %v", err)
	}
	return nil
}

func validateContextEvidence(context *ContextEvidence) error {
	if context == nil {
		return nil
	}
	if context.SchemaVersion != ContextEvidenceSchemaVersion {
		return fmt.Errorf("schema_version must be %q", ContextEvidenceSchemaVersion)
	}
	if len(context.QueryTokens) == 0 || len(context.MatchedTokens) == 0 {
		return fmt.Errorf("query_tokens and matched_tokens must not be empty")
	}
	for field, values := range map[string][]string{"query_tokens": context.QueryTokens, "matched_tokens": context.MatchedTokens} {
		for index, value := range values {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("%s[%d] is blank", field, index)
			}
		}
	}
	if context.Window != nil {
		if context.Window.Start < 0 || context.Window.End <= context.Window.Start || context.Window.End > len(context.QueryTokens) {
			return fmt.Errorf("window bounds are invalid")
		}
		if strings.TrimSpace(context.Window.Text) == "" {
			return fmt.Errorf("window.text is required")
		}
	}
	previous := ""
	for index, marker := range context.NegationMarkers {
		if strings.TrimSpace(marker) == "" {
			return fmt.Errorf("negation_markers[%d] is blank", index)
		}
		if index > 0 && previous >= marker {
			return fmt.Errorf("negation_markers must be sorted and unique")
		}
		previous = marker
	}
	if context.Policy != nil {
		for field, value := range map[string]string{
			"policy_set_id":       context.Policy.PolicySetID,
			"policy_set_checksum": context.Policy.PolicySetChecksum,
			"policy_entry_id":     context.Policy.PolicyEntryID,
			"country_code_alpha2": context.Policy.CountryCodeAlpha2,
			"country_name":        context.Policy.CountryName,
		} {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("policy.%s is required", field)
			}
		}
		if len(context.Policy.PolicySetChecksum) != 64 {
			return fmt.Errorf("policy.policy_set_checksum must be a 64-character SHA-256 hex digest")
		}
		if _, err := hex.DecodeString(context.Policy.PolicySetChecksum); err != nil {
			return fmt.Errorf("policy.policy_set_checksum is not hexadecimal")
		}
	}
	return nil
}

func validateDiagnostic(request RequestLineage, diagnostic CandidateDiagnostic) error {
	if diagnostic.SchemaVersion != CandidateDiagnosticSchemaVersion {
		return fmt.Errorf("schema_version must be %q", CandidateDiagnosticSchemaVersion)
	}
	for field, value := range map[string]string{"code": diagnostic.Code, "provider_record_id": diagnostic.ProviderRecordID, "primary_name": diagnostic.PrimaryName, "matched_value": diagnostic.MatchedValue, "detail": diagnostic.Detail} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}
	if diagnostic.ScoreBasisPoints < 0 || diagnostic.ScoreBasisPoints > 10000 || diagnostic.ThresholdBasisPoints < 0 || diagnostic.ThresholdBasisPoints > 10000 {
		return fmt.Errorf("score and threshold must be between 0 and 10000")
	}
	if !containsRoute(request.MatchRoutes, diagnostic.MatchRoute) {
		return fmt.Errorf("match_route %q is not permitted by request", diagnostic.MatchRoute)
	}
	switch diagnostic.Code {
	case "entity_type_mismatch":
		if containsType(request.TargetEntityTypes, diagnostic.EntityType) {
			return fmt.Errorf("entity_type_mismatch diagnostic entity_type %q is compatible with request", diagnostic.EntityType)
		}
	case "narrative_denial_context":
		if diagnostic.MatchRoute != canonical.RouteContextualPhrase {
			return fmt.Errorf("narrative_denial_context diagnostic requires contextual_phrase_window route")
		}
		if diagnostic.Evidence == nil || diagnostic.Evidence.Context == nil || len(diagnostic.Evidence.Context.NegationMarkers) == 0 {
			return fmt.Errorf("narrative_denial_context diagnostic requires negation context evidence")
		}
	default:
		return fmt.Errorf("unsupported diagnostic code %q", diagnostic.Code)
	}
	if err := validateMatchEvidence(diagnostic.Evidence, diagnostic.ScoreBasisPoints); err != nil {
		return fmt.Errorf("evidence: %v", err)
	}
	if diagnostic.Evidence != nil && diagnostic.Evidence.ThresholdBasisPoints != diagnostic.ThresholdBasisPoints {
		return fmt.Errorf("evidence threshold differs from diagnostic")
	}
	if len(diagnostic.SourceAssertions) == 0 || !assertionsCanonical(diagnostic.SourceAssertions) {
		return fmt.Errorf("source_assertions must be non-empty and canonical")
	}
	return nil
}

func diagnosticsCanonical(values []CandidateDiagnostic) bool {
	if len(values) < 2 {
		return true
	}
	copyValues := append([]CandidateDiagnostic(nil), values...)
	sort.Slice(copyValues, func(i, j int) bool {
		l, r := copyValues[i], copyValues[j]
		if l.ScoreBasisPoints != r.ScoreBasisPoints {
			return l.ScoreBasisPoints > r.ScoreBasisPoints
		}
		if l.Code != r.Code {
			return l.Code < r.Code
		}
		if l.ProviderRecordID != r.ProviderRecordID {
			return l.ProviderRecordID < r.ProviderRecordID
		}
		return l.MatchRoute < r.MatchRoute
	})
	return reflect.DeepEqual(values, copyValues)
}
