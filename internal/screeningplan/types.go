package screeningplan

import "github.com/openwatchlist-labs/watchlist-platform/internal/canonical"

const SchemaVersion = "screening-plan/v1alpha1"

type Plan struct {
	SchemaVersion      string                        `json:"schema_version"`
	ID                 string                        `json:"id"`
	Version            string                        `json:"version"`
	Description        string                        `json:"description,omitempty"`
	MessageDefinitions []canonical.MessageDefinition `json:"message_definitions"`
	Entries            []Entry                       `json:"entries"`
}

type Entry struct {
	ID                    string                    `json:"id"`
	PathPattern           string                    `json:"path_pattern"`
	SemanticRole          canonical.SemanticRole    `json:"semantic_role"`
	PartyRole             canonical.PartyRole       `json:"party_role,omitempty"`
	ValueType             canonical.ValueType       `json:"value_type"`
	TriggerPolicy         canonical.TriggerPolicy   `json:"trigger_policy"`
	MatchRoutes           []canonical.MatchRoute    `json:"match_routes,omitempty"`
	AllowedCandidateTypes []canonical.CandidateType `json:"allowed_candidate_types,omitempty"`
	NormalizationProfile  string                    `json:"normalization_profile"`
	ThresholdProfile      string                    `json:"threshold_profile"`
	SupportingFields      []canonical.SemanticRole  `json:"supporting_fields,omitempty"`
}
