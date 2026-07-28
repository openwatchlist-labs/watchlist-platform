package falsepositive

import (
	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
)

const (
	ObservationSchemaVersion          = "transaction-screening-observation/v1alpha1"
	ObservationBatchSchema            = "transaction-screening-observation-batch/v1alpha1"
	PatternLibrarySchemaVersion       = "false-positive-pattern-library/v1alpha1"
	PatternEvidenceSchema             = "false-positive-pattern-evidence/v1alpha1"
	CountervailingPolicySchemaVersion = "countervailing-evidence-policy/v1alpha1"
	CountervailingSignalSchemaVersion = "false-positive-countervailing-signal/v1alpha1"
	ClassificationSchemaVersion       = "false-positive-classification/v1alpha2"
	ClassificationBatchSchema         = "false-positive-classification-batch/v1alpha2"
	ClassifierVersion                 = "false-positive-classifier/v0.1.1"
)

type RouteHint string

const (
	RouteClearEligible       RouteHint = "clear_or_auto_release_eligible"
	RouteInvestigate         RouteHint = "investigate"
	RouteManualReview        RouteHint = "manual_review"
	RouteEscalationCandidate RouteHint = "escalation_candidate"
)

type EvidenceClass string

const (
	EvidenceClassPrimaryIdentifier  EvidenceClass = "primary_identifier"
	EvidenceClassSecondaryAttribute EvidenceClass = "secondary_attribute"
	EvidenceClassSecondarySupport   EvidenceClass = "secondary_support"
)

type PatternDefinition struct {
	Code                       string    `json:"code"`
	DefaultStrengthBasisPoints int       `json:"default_strength_basis_points"`
	RouteHint                  RouteHint `json:"route_hint"`
	EscalationBlockers         []string  `json:"escalation_blockers"`
	ReasonCodes                []string  `json:"reason_codes"`
}

type PatternLibrary struct {
	SchemaVersion   string              `json:"schema_version"`
	LibraryID       string              `json:"library_id"`
	LibraryVersion  string              `json:"library_version"`
	LibraryChecksum string              `json:"library_checksum"`
	Patterns        []PatternDefinition `json:"patterns"`
}

type PatternLibraryReference struct {
	LibraryID       string `json:"library_id"`
	LibraryVersion  string `json:"library_version"`
	LibraryChecksum string `json:"library_checksum"`
}

type CountervailingRule struct {
	MatchRoute             canonical.MatchRoute      `json:"match_route"`
	EvidenceClass          EvidenceClass             `json:"evidence_class"`
	SignalCode             string                    `json:"signal_code"`
	StrengthBasisPoints    int                       `json:"strength_basis_points"`
	EscalationEligible     bool                      `json:"escalation_eligible"`
	AllowedTriggerPolicies []canonical.TriggerPolicy `json:"allowed_trigger_policies"`
}

type SecondarySupportRule struct {
	EvidenceClass       EvidenceClass `json:"evidence_class"`
	SignalCode          string        `json:"signal_code"`
	StrengthBasisPoints int           `json:"strength_basis_points"`
	EscalationEligible  bool          `json:"escalation_eligible"`
}

type CountervailingPolicy struct {
	SchemaVersion        string               `json:"schema_version"`
	PolicyID             string               `json:"policy_id"`
	PolicyVersion        string               `json:"policy_version"`
	PolicyChecksum       string               `json:"policy_checksum"`
	ExactRouteRules      []CountervailingRule `json:"exact_route_rules"`
	SecondarySupportRule SecondarySupportRule `json:"secondary_identifier_support_rule"`
}

type CountervailingPolicyReference struct {
	PolicyID       string `json:"policy_id"`
	PolicyVersion  string `json:"policy_version"`
	PolicyChecksum string `json:"policy_checksum"`
}

type Observation struct {
	SchemaVersion              string                            `json:"schema_version"`
	ObservationID              string                            `json:"observation_id"`
	CaseID                     string                            `json:"case_id"`
	MessageID                  string                            `json:"message_id"`
	MessageType                string                            `json:"message_type"`
	SourceSystem               string                            `json:"source_system"`
	MatchedField               string                            `json:"matched_field"`
	NativePath                 string                            `json:"native_path,omitempty"`
	SemanticRole               canonical.SemanticRole            `json:"semantic_role"`
	ValueType                  canonical.ValueType               `json:"value_type"`
	TriggerPolicy              canonical.TriggerPolicy           `json:"trigger_policy"`
	InputValue                 string                            `json:"input_value"`
	NormalizedInputValue       string                            `json:"normalized_input_value"`
	WatchlistValue             string                            `json:"watchlist_value"`
	NormalizedWatchlistValue   string                            `json:"normalized_watchlist_value"`
	WatchlistEntityType        canonical.CandidateType           `json:"watchlist_entity_type"`
	MatchRoute                 canonical.MatchRoute              `json:"match_route"`
	ScreeningScoreBasisPoints  int                               `json:"screening_score_basis_points"`
	Exact                      bool                              `json:"exact"`
	MatcherReasonCodes         []string                          `json:"matcher_reason_codes,omitempty"`
	MatcherDiagnosticCodes     []string                          `json:"matcher_diagnostic_codes,omitempty"`
	TargetEntityTypes          []canonical.CandidateType         `json:"target_entity_types,omitempty"`
	SecondaryIdentifierMatches []string                          `json:"secondary_identifier_matches,omitempty"`
	RequiredQualifiers         []string                          `json:"required_qualifiers,omitempty"`
	PresentQualifiers          []string                          `json:"present_qualifiers,omitempty"`
	TechnicalMarkers           []string                          `json:"technical_markers,omitempty"`
	ContextMarkers             []string                          `json:"context_markers,omitempty"`
	SourceAssertions           []matcherprovider.SourceAssertion `json:"source_assertions,omitempty"`
}

type ObservationBatch struct {
	SchemaVersion   string        `json:"schema_version"`
	BatchID         string        `json:"batch_id"`
	SourceReference string        `json:"source_reference"`
	Observations    []Observation `json:"observations"`
}

type PatternEvidence struct {
	SchemaVersion       string    `json:"schema_version"`
	Code                string    `json:"code"`
	StrengthBasisPoints int       `json:"strength_basis_points"`
	RouteHint           RouteHint `json:"route_hint"`
	EscalationBlockers  []string  `json:"escalation_blockers"`
	ReasonCodes         []string  `json:"reason_codes"`
	Detail              string    `json:"detail"`
}

type CountervailingSignal struct {
	SchemaVersion       string        `json:"schema_version"`
	Code                string        `json:"code"`
	EvidenceClass       EvidenceClass `json:"evidence_class"`
	StrengthBasisPoints int           `json:"strength_basis_points"`
	EscalationEligible  bool          `json:"escalation_eligible"`
	Detail              string        `json:"detail"`
}

type ClassificationSummary struct {
	PatternCount                     int `json:"pattern_count"`
	StrongestPatternBasisPoints      int `json:"strongest_pattern_basis_points"`
	ReleaseSupportBasisPoints        int `json:"release_support_basis_points"`
	CountervailingSupportBasisPoints int `json:"countervailing_support_basis_points"`
}

type Classification struct {
	SchemaVersion         string                        `json:"schema_version"`
	ClassificationID      string                        `json:"classification_id"`
	Observation           Observation                   `json:"observation"`
	ClassifierVersion     string                        `json:"classifier_version"`
	PatternLibrary        PatternLibraryReference       `json:"pattern_library"`
	CountervailingPolicy  CountervailingPolicyReference `json:"countervailing_policy"`
	Patterns              []PatternEvidence             `json:"patterns,omitempty"`
	CountervailingSignals []CountervailingSignal        `json:"countervailing_signals,omitempty"`
	RouteHint             RouteHint                     `json:"route_hint"`
	EscalationBlockers    []string                      `json:"escalation_blockers,omitempty"`
	RequiresEvidence      []string                      `json:"requires_evidence,omitempty"`
	Summary               ClassificationSummary         `json:"summary"`
}

type NamedCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type BatchSummary struct {
	TotalObservations int          `json:"total_observations"`
	PatternCounts     []NamedCount `json:"pattern_counts,omitempty"`
	RouteHintCounts   []NamedCount `json:"route_hint_counts,omitempty"`
	BlockerCounts     []NamedCount `json:"blocker_counts,omitempty"`
}

type ClassificationBatch struct {
	SchemaVersion           string                        `json:"schema_version"`
	ClassificationBatchID   string                        `json:"classification_batch_id"`
	InputObservationBatchID string                        `json:"input_observation_batch_id"`
	ClassifierVersion       string                        `json:"classifier_version"`
	PatternLibrary          PatternLibraryReference       `json:"pattern_library"`
	CountervailingPolicy    CountervailingPolicyReference `json:"countervailing_policy"`
	Summary                 BatchSummary                  `json:"summary"`
	Classifications         []Classification              `json:"classifications"`
}
