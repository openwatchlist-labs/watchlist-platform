package matcherbaseline

import (
	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
)

const (
	ProfileSetSchemaVersion = "matcher-threshold-profile-set/v1alpha1"
	MatcherVersion          = "deterministic-name-matcher/v0.1.0"
	ProviderID              = "ofac-deterministic-baseline"
	ProviderVersion         = "v0.1.0"
)

type ThresholdProfile struct {
	ProfileID                       string `json:"profile_id"`
	ThresholdBasisPoints            int    `json:"threshold_basis_points"`
	DiagnosticFloorBasisPoints      int    `json:"diagnostic_floor_basis_points"`
	TokenAlignmentWeightBasisPoints int    `json:"token_alignment_weight_basis_points"`
	EditSimilarityWeightBasisPoints int    `json:"edit_similarity_weight_basis_points"`
	OrderedTokenWeightBasisPoints   int    `json:"ordered_token_weight_basis_points"`
	PhoneticWeightBasisPoints       int    `json:"phonetic_weight_basis_points"`
	LengthWeightBasisPoints         int    `json:"length_weight_basis_points"`
	SingleTokenPenaltyBasisPoints   int    `json:"single_token_penalty_basis_points"`
	WeakAliasPenaltyBasisPoints     int    `json:"weak_alias_penalty_basis_points"`
}

type ProfileSet struct {
	SchemaVersion      string             `json:"schema_version"`
	ProfileSetID       string             `json:"profile_set_id"`
	ProfileSetVersion  string             `json:"profile_set_version"`
	ProfileSetChecksum string             `json:"profile_set_checksum"`
	MatcherVersion     string             `json:"matcher_version"`
	Profiles           []ThresholdProfile `json:"profiles"`
}

type nameEntry struct {
	ProviderRecordID       string
	EntityType             canonical.CandidateType
	PrimaryName            string
	MatchedValue           string
	NormalizedMatchedValue string
	MatchRoute             canonical.MatchRoute
	Attributes             map[string]string
	SourceAssertions       []matcherprovider.SourceAssertion
}
