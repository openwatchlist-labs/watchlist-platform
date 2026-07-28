package matcherprovider

import (
	"context"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogruntime"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherrequest"
)

const (
	ProviderDescriptorSchemaVersion  = "matcher-provider-descriptor/v1alpha1"
	MatchEvidenceSchemaVersion       = "matcher-feature-evidence/v1alpha1"
	ContextEvidenceSchemaVersion     = "matcher-context-evidence/v1alpha1"
	CandidateDiagnosticSchemaVersion = "candidate-diagnostic/v1alpha1"
	CandidateResultSchemaVersion     = "candidate-search-result/v1alpha1"
	ResultBatchSchemaVersion         = "candidate-result-batch/v1alpha1"
	ProviderReplaySchemaVersion      = "matcher-provider-replay-envelope/v1alpha1"
	RunnerVersion                    = "matcher-provider-runner/v0.1.0"

	RequestOrderingInputOrder      = "input_request_order"
	CandidateOrderingCanonical     = "score_desc_exact_desc_record_id_asc"
	ResultIdentityContentAddressed = "content_addressed"
	FailurePolicyAtomic            = "atomic_no_partial_results"
	LineagePolicyRequestAndCatalog = "full_request_plan_and_catalog_lineage"
)

type CatalogMode string

const (
	CatalogModeDirectList     CatalogMode = "direct_list"
	CatalogModeProviderEntity CatalogMode = "provider_entity"
	CatalogModeHybridOverlay  CatalogMode = "hybrid_overlay"
)

type ResultStatus string

const (
	ResultMatched      ResultStatus = "matched"
	ResultNoCandidates ResultStatus = "no_candidates"
)

type CatalogReference struct {
	CatalogID       string      `json:"catalog_id"`
	CatalogVersion  string      `json:"catalog_version"`
	CatalogChecksum string      `json:"catalog_checksum"`
	CatalogMode     CatalogMode `json:"catalog_mode"`
}

type ProviderCapabilities struct {
	SupportedRoutes          []canonical.MatchRoute    `json:"supported_routes"`
	SupportedEntityTypes     []canonical.CandidateType `json:"supported_entity_types"`
	MaxCandidatesPerRequest  int                       `json:"max_candidates_per_request"`
	Deterministic            bool                      `json:"deterministic"`
	SourceAssertionsIncluded bool                      `json:"source_assertions_included"`
}

type ProviderDescriptor struct {
	SchemaVersion   string               `json:"schema_version"`
	ProviderID      string               `json:"provider_id"`
	ProviderVersion string               `json:"provider_version"`
	Catalog         CatalogReference     `json:"catalog"`
	Capabilities    ProviderCapabilities `json:"capabilities"`
}

type SourceAssertion struct {
	SourceID       string   `json:"source_id"`
	Authority      string   `json:"authority"`
	ListID         string   `json:"list_id"`
	SourceRecordID string   `json:"source_record_id"`
	Programs       []string `json:"programs,omitempty"`
}

type FeatureEvidence struct {
	Name                    string `json:"name"`
	ScoreBasisPoints        int    `json:"score_basis_points"`
	WeightBasisPoints       int    `json:"weight_basis_points"`
	ContributionBasisPoints int    `json:"contribution_basis_points"`
}

type TokenWindow struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	Text  string `json:"text"`
}

type PolicyContext struct {
	PolicySetID       string `json:"policy_set_id"`
	PolicySetChecksum string `json:"policy_set_checksum"`
	PolicyEntryID     string `json:"policy_entry_id"`
	CountryCodeAlpha2 string `json:"country_code_alpha2"`
	CountryCodeAlpha3 string `json:"country_code_alpha3,omitempty"`
	CountryName       string `json:"country_name"`
}

type ContextEvidence struct {
	SchemaVersion   string         `json:"schema_version"`
	QueryTokens     []string       `json:"query_tokens"`
	MatchedTokens   []string       `json:"matched_tokens"`
	Window          *TokenWindow   `json:"window,omitempty"`
	NegationMarkers []string       `json:"negation_markers,omitempty"`
	Policy          *PolicyContext `json:"policy,omitempty"`
}

type MatchEvidence struct {
	SchemaVersion        string            `json:"schema_version"`
	MatcherVersion       string            `json:"matcher_version"`
	ProfileSetID         string            `json:"profile_set_id"`
	ProfileSetChecksum   string            `json:"profile_set_checksum"`
	ThresholdProfile     string            `json:"threshold_profile"`
	ThresholdBasisPoints int               `json:"threshold_basis_points"`
	ReasonCodes          []string          `json:"reason_codes"`
	Features             []FeatureEvidence `json:"features"`
	PenaltyBasisPoints   int               `json:"penalty_basis_points,omitempty"`
	Context              *ContextEvidence  `json:"context,omitempty"`
}

type CandidateDiagnostic struct {
	SchemaVersion        string                  `json:"schema_version"`
	Code                 string                  `json:"code"`
	ProviderRecordID     string                  `json:"provider_record_id"`
	EntityType           canonical.CandidateType `json:"entity_type"`
	PrimaryName          string                  `json:"primary_name"`
	MatchedValue         string                  `json:"matched_value"`
	MatchRoute           canonical.MatchRoute    `json:"match_route"`
	ScoreBasisPoints     int                     `json:"score_basis_points"`
	ThresholdBasisPoints int                     `json:"threshold_basis_points"`
	Detail               string                  `json:"detail"`
	Evidence             *MatchEvidence          `json:"evidence,omitempty"`
	SourceAssertions     []SourceAssertion       `json:"source_assertions"`
}

// ProviderCandidate is the provider-neutral value returned by a catalog adapter.
// The platform validates and canonicalizes it before emitting a public result.
type ProviderCandidate struct {
	ProviderRecordID       string                  `json:"provider_record_id"`
	ProviderEntityID       string                  `json:"provider_entity_id,omitempty"`
	EntityType             canonical.CandidateType `json:"entity_type"`
	PrimaryName            string                  `json:"primary_name"`
	MatchedValue           string                  `json:"matched_value"`
	NormalizedMatchedValue string                  `json:"normalized_matched_value"`
	MatchRoute             canonical.MatchRoute    `json:"match_route"`
	ScoreBasisPoints       int                     `json:"score_basis_points"`
	Exact                  bool                    `json:"exact"`
	Attributes             map[string]string       `json:"attributes,omitempty"`
	Evidence               *MatchEvidence          `json:"evidence,omitempty"`
	SourceAssertions       []SourceAssertion       `json:"source_assertions"`
}

type Provider interface {
	Descriptor() ProviderDescriptor
	Search(context.Context, matcherrequest.CandidateSearchRequest) ([]ProviderCandidate, error)
}

// DiagnosticProvider optionally returns strong matches that were deliberately
// suppressed, for example because the catalog entity type is incompatible with
// the screened ISO 20022 field.
type DiagnosticProvider interface {
	SearchWithDiagnostics(context.Context, matcherrequest.CandidateSearchRequest) ([]ProviderCandidate, []CandidateDiagnostic, error)
}

type RequestLineage struct {
	RequestID            string                       `json:"request_id"`
	RequestKind          matcherrequest.RequestKind   `json:"request_kind"`
	MessageID            string                       `json:"message_id"`
	TransactionID        string                       `json:"transaction_id,omitempty"`
	TransactionIndex     *int                         `json:"transaction_index,omitempty"`
	NativePath           string                       `json:"native_path"`
	Occurrence           int                          `json:"occurrence"`
	SemanticRole         canonical.SemanticRole       `json:"semantic_role"`
	PartyRole            canonical.PartyRole          `json:"party_role,omitempty"`
	ValueType            canonical.ValueType          `json:"value_type"`
	TriggerPolicy        canonical.TriggerPolicy      `json:"trigger_policy"`
	Query                matcherrequest.QueryValue    `json:"query"`
	MatchRoutes          []canonical.MatchRoute       `json:"match_routes"`
	TargetEntityTypes    []canonical.CandidateType    `json:"target_entity_types"`
	NormalizationProfile string                       `json:"normalization_profile"`
	ThresholdProfile     string                       `json:"threshold_profile"`
	SupportingFields     []canonical.SemanticRole     `json:"supporting_fields,omitempty"`
	SourceLineage        matcherrequest.SourceLineage `json:"source_lineage"`
}

type CandidateMatch struct {
	CandidateID            string                  `json:"candidate_id"`
	ProviderRecordID       string                  `json:"provider_record_id"`
	ProviderEntityID       string                  `json:"provider_entity_id,omitempty"`
	EntityType             canonical.CandidateType `json:"entity_type"`
	PrimaryName            string                  `json:"primary_name"`
	MatchedValue           string                  `json:"matched_value"`
	NormalizedMatchedValue string                  `json:"normalized_matched_value"`
	MatchRoute             canonical.MatchRoute    `json:"match_route"`
	ScoreBasisPoints       int                     `json:"score_basis_points"`
	Exact                  bool                    `json:"exact"`
	Attributes             map[string]string       `json:"attributes,omitempty"`
	Evidence               *MatchEvidence          `json:"evidence,omitempty"`
	SourceAssertions       []SourceAssertion       `json:"source_assertions"`
}

type CandidateSearchResult struct {
	SchemaVersion     string                          `json:"schema_version"`
	ResultID          string                          `json:"result_id"`
	Status            ResultStatus                    `json:"status"`
	Request           RequestLineage                  `json:"request"`
	Provider          ProviderDescriptor              `json:"provider"`
	RuntimeGeneration *catalogruntime.GenerationStamp `json:"runtime_generation,omitempty"`
	CandidateCount    int                             `json:"candidate_count"`
	Candidates        []CandidateMatch                `json:"candidates"`
	Diagnostics       []CandidateDiagnostic           `json:"diagnostics,omitempty"`
}

type NamedCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type ResultSummary struct {
	TotalRequests       int          `json:"total_requests"`
	MatchedRequests     int          `json:"matched_requests"`
	NoCandidateRequests int          `json:"no_candidate_requests"`
	TotalCandidates     int          `json:"total_candidates"`
	CandidateTypeCounts []NamedCount `json:"candidate_type_counts,omitempty"`
	MatchRouteCounts    []NamedCount `json:"match_route_counts,omitempty"`
	DiagnosticCounts    []NamedCount `json:"diagnostic_counts,omitempty"`
}

type ResultBatch struct {
	SchemaVersion       string                          `json:"schema_version"`
	ResultBatchID       string                          `json:"result_batch_id"`
	InputRequestBatchID string                          `json:"input_request_batch_id"`
	MessageID           string                          `json:"message_id"`
	RunnerVersion       string                          `json:"runner_version"`
	Provider            ProviderDescriptor              `json:"provider"`
	RuntimeGeneration   *catalogruntime.GenerationStamp `json:"runtime_generation,omitempty"`
	Summary             ResultSummary                   `json:"summary"`
	Results             []CandidateSearchResult         `json:"results"`
}

type ExecutionContract struct {
	RequestOrdering   string `json:"request_ordering"`
	CandidateOrdering string `json:"candidate_ordering"`
	IdentityPolicy    string `json:"identity_policy"`
	FailurePolicy     string `json:"failure_policy"`
	LineagePolicy     string `json:"lineage_policy"`
}

type ProviderReplayEnvelope struct {
	SchemaVersion     string                        `json:"schema_version"`
	ReplayID          string                        `json:"replay_id"`
	RunnerVersion     string                        `json:"runner_version"`
	ExecutionContract ExecutionContract             `json:"execution_contract"`
	InputReplay       matcherrequest.ReplayEnvelope `json:"input_replay"`
	ResultBatch       ResultBatch                   `json:"result_batch"`
}
