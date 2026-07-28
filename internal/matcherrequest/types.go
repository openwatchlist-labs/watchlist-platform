package matcherrequest

import (
	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/screening"
)

const (
	RequestSchemaVersion = "candidate-search-request/v1alpha1"
	BatchSchemaVersion   = "candidate-search-request-batch/v1alpha1"
	ReplaySchemaVersion  = "matcher-replay-envelope/v1alpha1"
	ProjectorVersion     = "matcher-request-projector/v0.1.0"

	SelectionPolicyEligibleOnly    = "eligible_for_matching_only"
	OrderingPolicyEvidenceOrder    = "evidence_order"
	IdentityPolicyContentAddressed = "content_addressed"
	LineagePolicyFull              = "full_source_and_plan_lineage"
)

type RequestKind string

const (
	RequestCandidateAlert     RequestKind = "candidate_alert_lookup"
	RequestSupportingEvidence RequestKind = "supporting_evidence_lookup"
)

type QueryValue struct {
	OriginalValue   string            `json:"original_value"`
	NormalizedValue string            `json:"normalized_value"`
	Attributes      map[string]string `json:"attributes,omitempty"`
}

type SourceLineage struct {
	SourcePayloadReference string                      `json:"source_payload_reference"`
	ParserVersion          string                      `json:"parser_version"`
	ExecutorVersion        string                      `json:"executor_version"`
	EvidenceBundleID       string                      `json:"evidence_bundle_id"`
	EvidenceID             string                      `json:"evidence_id"`
	ElementID              string                      `json:"element_id"`
	MessageDefinition      canonical.MessageDefinition `json:"message_definition"`
	MessageNamespace       string                      `json:"message_namespace"`
	ScreeningPlan          screening.PlanReference     `json:"screening_plan"`
}

type CandidateSearchRequest struct {
	SchemaVersion        string                    `json:"schema_version"`
	RequestID            string                    `json:"request_id"`
	RequestKind          RequestKind               `json:"request_kind"`
	MessageID            string                    `json:"message_id"`
	TransactionID        string                    `json:"transaction_id,omitempty"`
	TransactionIndex     *int                      `json:"transaction_index,omitempty"`
	NativePath           string                    `json:"native_path"`
	Occurrence           int                       `json:"occurrence"`
	SemanticRole         canonical.SemanticRole    `json:"semantic_role"`
	PartyRole            canonical.PartyRole       `json:"party_role,omitempty"`
	ValueType            canonical.ValueType       `json:"value_type"`
	TriggerPolicy        canonical.TriggerPolicy   `json:"trigger_policy"`
	Query                QueryValue                `json:"query"`
	MatchRoutes          []canonical.MatchRoute    `json:"match_routes"`
	TargetEntityTypes    []canonical.CandidateType `json:"target_entity_types"`
	NormalizationProfile string                    `json:"normalization_profile"`
	ThresholdProfile     string                    `json:"threshold_profile"`
	SupportingFields     []canonical.SemanticRole  `json:"supporting_fields,omitempty"`
	SourceLineage        SourceLineage             `json:"source_lineage"`
}

type NamedCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type RequestSummary struct {
	TotalRequests              int          `json:"total_requests"`
	TransactionCount           int          `json:"transaction_count"`
	CandidateAlertRequests     int          `json:"candidate_alert_requests"`
	SupportingEvidenceRequests int          `json:"supporting_evidence_requests"`
	RouteCounts                []NamedCount `json:"route_counts,omitempty"`
	TargetEntityTypeCounts     []NamedCount `json:"target_entity_type_counts,omitempty"`
}

type RequestBatch struct {
	SchemaVersion          string                      `json:"schema_version"`
	BatchID                string                      `json:"batch_id"`
	InputEvidenceBundleID  string                      `json:"input_evidence_bundle_id"`
	MessageID              string                      `json:"message_id"`
	MessageDefinition      canonical.MessageDefinition `json:"message_definition"`
	MessageNamespace       string                      `json:"message_namespace"`
	SourcePayloadReference string                      `json:"source_payload_reference"`
	ParserVersion          string                      `json:"parser_version"`
	ExecutorVersion        string                      `json:"executor_version"`
	ProjectorVersion       string                      `json:"projector_version"`
	ScreeningPlan          screening.PlanReference     `json:"screening_plan"`
	Summary                RequestSummary              `json:"summary"`
	Requests               []CandidateSearchRequest    `json:"requests"`
}

type ProjectionContract struct {
	SelectionPolicy string `json:"selection_policy"`
	OrderingPolicy  string `json:"ordering_policy"`
	IdentityPolicy  string `json:"identity_policy"`
	LineagePolicy   string `json:"lineage_policy"`
}

type ReplayInput struct {
	EvidenceSchemaVersion  string                  `json:"evidence_schema_version"`
	EvidenceBundleID       string                  `json:"evidence_bundle_id"`
	SourcePayloadReference string                  `json:"source_payload_reference"`
	ParserVersion          string                  `json:"parser_version"`
	ExecutorVersion        string                  `json:"executor_version"`
	ScreeningPlan          screening.PlanReference `json:"screening_plan"`
}

type ReplayEnvelope struct {
	SchemaVersion      string             `json:"schema_version"`
	ReplayID           string             `json:"replay_id"`
	ProjectorVersion   string             `json:"projector_version"`
	ProjectionContract ProjectionContract `json:"projection_contract"`
	Input              ReplayInput        `json:"input"`
	RequestBatch       RequestBatch       `json:"request_batch"`
}
