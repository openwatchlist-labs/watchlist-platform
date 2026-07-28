package screening

import "github.com/openwatchlist-labs/watchlist-platform/internal/canonical"

const (
	EvidenceBundleSchemaVersion  = "screening-evidence-bundle/v1alpha1"
	ElementEvidenceSchemaVersion = "screening-element-evidence/v1alpha1"
	InspectionSchemaVersion      = "iso20022-inspection/v1alpha1"
	ExecutorVersion              = "screening-plan-executor/v0.1.0"
)

type ResolutionStatus string

type EffectiveAction string

const (
	ResolutionResolved ResolutionStatus = "resolved"
)

const (
	ActionCandidateLookup  EffectiveAction = "candidate_lookup"
	ActionSupportingLookup EffectiveAction = "supporting_lookup"
	ActionRetainOnly       EffectiveAction = "retain_only"
	ActionDisabled         EffectiveAction = "disabled"
	ActionSkipEmpty        EffectiveAction = "skip_empty"
	ActionSkipInvalid      EffectiveAction = "skip_invalid"
)

type PlanReference struct {
	PlanID       string `json:"plan_id"`
	PlanVersion  string `json:"plan_version"`
	PlanChecksum string `json:"plan_checksum"`
}

type PlanResolution struct {
	Status               ResolutionStatus          `json:"status"`
	EntryID              string                    `json:"entry_id"`
	SemanticRole         canonical.SemanticRole    `json:"semantic_role"`
	PartyRole            canonical.PartyRole       `json:"party_role,omitempty"`
	ValueType            canonical.ValueType       `json:"value_type"`
	TriggerPolicy        canonical.TriggerPolicy   `json:"trigger_policy"`
	MatchRoutes          []canonical.MatchRoute    `json:"match_routes,omitempty"`
	TargetEntityTypes    []canonical.CandidateType `json:"target_entity_types,omitempty"`
	NormalizationProfile string                    `json:"normalization_profile"`
	ThresholdProfile     string                    `json:"threshold_profile"`
	SupportingFields     []canonical.SemanticRole  `json:"supporting_fields,omitempty"`
	EligibleForMatching  bool                      `json:"eligible_for_matching"`
	EffectiveAction      EffectiveAction           `json:"effective_action"`
}

type ElementEvidence struct {
	SchemaVersion          string                      `json:"schema_version"`
	EvidenceID             string                      `json:"evidence_id"`
	ElementID              string                      `json:"element_id"`
	MessageID              string                      `json:"message_id"`
	TransactionID          string                      `json:"transaction_id,omitempty"`
	TransactionIndex       *int                        `json:"transaction_index,omitempty"`
	MessageDefinition      canonical.MessageDefinition `json:"message_definition"`
	MessageNamespace       string                      `json:"message_namespace"`
	NativePath             string                      `json:"native_path"`
	Occurrence             int                         `json:"occurrence"`
	Presence               canonical.PresenceState     `json:"presence"`
	OriginalValue          string                      `json:"original_value"`
	NormalizedValue        string                      `json:"normalized_value"`
	Attributes             map[string]string           `json:"attributes,omitempty"`
	Resolution             PlanResolution              `json:"resolution"`
	SourcePayloadReference string                      `json:"source_payload_reference"`
	ParserVersion          string                      `json:"parser_version"`
	Warnings               []canonical.ParserWarning   `json:"warnings,omitempty"`
}

type NamedCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type EvidenceSummary struct {
	TotalElements              int          `json:"total_elements"`
	TransactionCount           int          `json:"transaction_count"`
	CandidateAlertElements     int          `json:"candidate_alert_elements"`
	SupportingEvidenceElements int          `json:"supporting_evidence_elements"`
	RetainOnlyElements         int          `json:"retain_only_elements"`
	DisabledElements           int          `json:"disabled_elements"`
	MatchEligibleElements      int          `json:"match_eligible_elements"`
	SkippedEmptyElements       int          `json:"skipped_empty_elements"`
	SkippedInvalidElements     int          `json:"skipped_invalid_elements"`
	ElementWarningCount        int          `json:"element_warning_count"`
	RouteCounts                []NamedCount `json:"route_counts,omitempty"`
	TargetEntityTypeCounts     []NamedCount `json:"target_entity_type_counts,omitempty"`
}

type EvidenceBundle struct {
	SchemaVersion          string                      `json:"schema_version"`
	BundleID               string                      `json:"bundle_id"`
	MessageID              string                      `json:"message_id"`
	MessageDefinition      canonical.MessageDefinition `json:"message_definition"`
	MessageNamespace       string                      `json:"message_namespace"`
	SourcePayloadReference string                      `json:"source_payload_reference"`
	ParserVersion          string                      `json:"parser_version"`
	ExecutorVersion        string                      `json:"executor_version"`
	ScreeningPlan          PlanReference               `json:"screening_plan"`
	Summary                EvidenceSummary             `json:"summary"`
	Elements               []ElementEvidence           `json:"elements"`
	Warnings               []canonical.ParserWarning   `json:"warnings,omitempty"`
}

type InspectionOutput struct {
	SchemaVersion string                  `json:"schema_version"`
	Canonical     canonical.ParsedMessage `json:"canonical"`
	Evidence      EvidenceBundle          `json:"evidence"`
}
