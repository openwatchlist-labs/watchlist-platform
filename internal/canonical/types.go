package canonical

const (
	CanonicalSchemaVersion = "canonical-message/v1alpha1"
	ElementSchemaVersion   = "screenable-element/v1alpha1"
)

type MessageDefinition string

type SemanticRole string

type PartyRole string

type ValueType string

type PresenceState string

type TriggerPolicy string

type MatchRoute string

type CandidateType string

type WarningSeverity string

const (
	PresencePresent PresenceState = "present"
	PresenceEmpty   PresenceState = "empty"
	PresenceInvalid PresenceState = "invalid"
)

const (
	TriggerCandidateAlert     TriggerPolicy = "candidate_alert"
	TriggerSupportingEvidence TriggerPolicy = "supporting_evidence"
	TriggerRetainOnly         TriggerPolicy = "retain_only"
	TriggerDisabled           TriggerPolicy = "disabled"
)

const (
	RouteNormalizedName     MatchRoute = "normalized_name"
	RouteAlias              MatchRoute = "alias"
	RouteTransliteration    MatchRoute = "transliteration"
	RouteExactBIC           MatchRoute = "exact_bic"
	RouteExactLEI           MatchRoute = "exact_lei"
	RouteExactAccount       MatchRoute = "exact_account"
	RouteExactDate          MatchRoute = "exact_date"
	RouteJurisdictionPolicy MatchRoute = "jurisdiction_policy"
	RouteContextualAddress  MatchRoute = "contextual_address"
	RouteContextualPhrase   MatchRoute = "contextual_phrase_window"
)

const (
	CandidateIndividual           CandidateType = "individual"
	CandidateOrganization         CandidateType = "organization"
	CandidateGovernmentEntity     CandidateType = "government_entity"
	CandidateFinancialInstitution CandidateType = "financial_institution"
	CandidateVessel               CandidateType = "vessel"
	CandidateAircraft             CandidateType = "aircraft"
	CandidateJurisdiction         CandidateType = "jurisdiction"
)

const (
	SeverityInfo    WarningSeverity = "info"
	SeverityWarning WarningSeverity = "warning"
	SeverityError   WarningSeverity = "error"
)

type ParserWarning struct {
	Code     string          `json:"code"`
	Severity WarningSeverity `json:"severity"`
	Message  string          `json:"message"`
	Path     string          `json:"path,omitempty"`
}

type ScreeningPlanReference struct {
	PlanID       string `json:"plan_id"`
	PlanVersion  string `json:"plan_version"`
	PlanChecksum string `json:"plan_checksum"`
	EntryID      string `json:"entry_id"`
}

type ScreeningDirective struct {
	TriggerPolicy         TriggerPolicy   `json:"trigger_policy"`
	MatchRoutes           []MatchRoute    `json:"match_routes,omitempty"`
	AllowedCandidateTypes []CandidateType `json:"allowed_candidate_types,omitempty"`
	NormalizationProfile  string          `json:"normalization_profile"`
	ThresholdProfile      string          `json:"threshold_profile"`
	SupportingFields      []SemanticRole  `json:"supporting_fields,omitempty"`
}

type ScreenableElement struct {
	SchemaVersion          string                 `json:"schema_version"`
	ElementID              string                 `json:"element_id"`
	MessageID              string                 `json:"message_id"`
	TransactionID          string                 `json:"transaction_id,omitempty"`
	TransactionIndex       *int                   `json:"transaction_index,omitempty"`
	MessageDefinition      MessageDefinition      `json:"message_definition"`
	MessageNamespace       string                 `json:"message_namespace"`
	NativePath             string                 `json:"native_path"`
	Occurrence             int                    `json:"occurrence"`
	SemanticRole           SemanticRole           `json:"semantic_role"`
	PartyRole              PartyRole              `json:"party_role,omitempty"`
	ValueType              ValueType              `json:"value_type"`
	Presence               PresenceState          `json:"presence"`
	OriginalValue          string                 `json:"original_value"`
	NormalizedValue        string                 `json:"normalized_value"`
	Attributes             map[string]string      `json:"attributes,omitempty"`
	ScreeningPlan          ScreeningPlanReference `json:"screening_plan"`
	Screening              ScreeningDirective     `json:"screening"`
	SourcePayloadReference string                 `json:"source_payload_reference"`
	ParserVersion          string                 `json:"parser_version"`
	Warnings               []ParserWarning        `json:"warnings,omitempty"`
}

type ParsedMessage struct {
	SchemaVersion          string              `json:"schema_version"`
	MessageID              string              `json:"message_id"`
	MessageDefinition      MessageDefinition   `json:"message_definition"`
	MessageNamespace       string              `json:"message_namespace"`
	SourcePayloadReference string              `json:"source_payload_reference"`
	ParserVersion          string              `json:"parser_version"`
	ScreeningPlanID        string              `json:"screening_plan_id"`
	ScreeningPlanVersion   string              `json:"screening_plan_version"`
	ScreeningPlanChecksum  string              `json:"screening_plan_checksum"`
	Elements               []ScreenableElement `json:"elements"`
	Warnings               []ParserWarning     `json:"warnings,omitempty"`
}
