package matchercontext

import (
	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
)

const (
	ProfileSetSchemaVersion = "matcher-context-profile-set/v1alpha1"
	PolicySetSchemaVersion  = "jurisdiction-policy-set/v1alpha1"
	MatcherVersion          = "deterministic-context-matcher/v0.1.0"
	ProviderID              = "ofac-context-baseline"
	ProviderVersion         = "v0.1.0"
)

const (
	ContextKindNarrative    = "narrative"
	ContextKindJurisdiction = "jurisdiction"
	PolicyStatusRestricted  = "restricted"
)

type FeatureWeight struct {
	Name              string `json:"name"`
	WeightBasisPoints int    `json:"weight_basis_points"`
}

type ContextProfile struct {
	ProfileID                     string          `json:"profile_id"`
	ContextKind                   string          `json:"context_kind"`
	ThresholdBasisPoints          int             `json:"threshold_basis_points"`
	DiagnosticFloorBasisPoints    int             `json:"diagnostic_floor_basis_points"`
	FeatureWeights                []FeatureWeight `json:"feature_weights"`
	OrderedWindowScoreBasisPoints int             `json:"ordered_window_score_basis_points,omitempty"`
	MaxWindowExtraTokens          int             `json:"max_window_extra_tokens,omitempty"`
	MinSingleTokenLength          int             `json:"min_single_token_length,omitempty"`
	WeakAliasPenaltyBasisPoints   int             `json:"weak_alias_penalty_basis_points,omitempty"`
	DenialPenaltyBasisPoints      int             `json:"denial_penalty_basis_points,omitempty"`
	DenialWindowTokens            int             `json:"denial_window_tokens,omitempty"`
	DenialMarkers                 []string        `json:"denial_markers,omitempty"`
}

type ProfileSet struct {
	SchemaVersion      string           `json:"schema_version"`
	ProfileSetID       string           `json:"profile_set_id"`
	ProfileSetVersion  string           `json:"profile_set_version"`
	ProfileSetChecksum string           `json:"profile_set_checksum"`
	MatcherVersion     string           `json:"matcher_version"`
	Profiles           []ContextProfile `json:"profiles"`
}

type PolicySource struct {
	SourceID      string `json:"source_id"`
	Authority     string `json:"authority"`
	ListID        string `json:"list_id"`
	SourceVersion string `json:"source_version"`
}

type JurisdictionEntry struct {
	EntryID           string   `json:"entry_id"`
	CountryCodeAlpha2 string   `json:"country_code_alpha2"`
	CountryCodeAlpha3 string   `json:"country_code_alpha3,omitempty"`
	CountryName       string   `json:"country_name"`
	Aliases           []string `json:"aliases,omitempty"`
	Status            string   `json:"status"`
	Programs          []string `json:"programs"`
}

type JurisdictionPolicySet struct {
	SchemaVersion     string              `json:"schema_version"`
	PolicySetID       string              `json:"policy_set_id"`
	PolicySetVersion  string              `json:"policy_set_version"`
	PolicySetChecksum string              `json:"policy_set_checksum"`
	Source            PolicySource        `json:"source"`
	Entries           []JurisdictionEntry `json:"entries"`
}

type narrativeEntry struct {
	ProviderRecordID string
	EntityType       canonical.CandidateType
	PrimaryName      string
	MatchedValue     string
	SourceRoute      canonical.MatchRoute
	AliasStrength    string
	SourceAssertions []matcherprovider.SourceAssertion
}
