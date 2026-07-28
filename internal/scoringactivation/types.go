package scoringactivation

import (
	"github.com/openwatchlist-labs/watchlist-platform/internal/candidatescoring"
	"github.com/openwatchlist-labs/watchlist-platform/internal/projectionpackage"
)

const (
	ActivationSchemaV1 = "openwatchlist.scoring-activation.v1"
	PendingSchemaV1    = "openwatchlist.scoring-activation-pending.v1"
)

// Activation is one immutable catalog/projection/policy tuple.
type Activation struct {
	SchemaVersion        string                              `json:"schema_version"`
	ActivationID         string                              `json:"activation_id"`
	PreviousActivationID string                              `json:"previous_activation_id,omitempty"`
	Catalog              projectionpackage.CatalogDescriptor `json:"catalog"`
	Projection           ProjectionBinding                   `json:"projection"`
	Policy               PolicyBinding                       `json:"policy"`
}

type ProjectionBinding struct {
	PackagePath        string `json:"package_path"`
	PackageSHA256      string `json:"package_sha256"`
	ProjectionsSHA256  string `json:"projections_sha256"`
	ProjectionCount    int    `json:"projection_count"`
	CandidateIDsSHA256 string `json:"candidate_ids_sha256"`
}

type PolicyBinding struct {
	Path                 string `json:"path"`
	PolicyID             string `json:"policy_id"`
	PolicyVersion        string `json:"policy_version"`
	PolicySHA256         string `json:"policy_sha256"`
	NormalizationProfile string `json:"normalization_profile"`
}

// ActivateRequest validates all referenced immutable content before the pointer moves.
type ActivateRequest struct {
	ActivationID          string
	CatalogDescriptorPath string
	ProjectionPackagePath string
	ScoringPolicyPath     string
}

// Snapshot is a verified active runtime binding.
type Snapshot struct {
	Activation        Activation
	ProjectionPackage projectionpackage.Package
	Policy            candidatescoring.LoadedPolicy
}

type pendingDocument struct {
	SchemaVersion        string `json:"schema_version"`
	TargetActivationID   string `json:"target_activation_id"`
	PreviousActivationID string `json:"previous_activation_id,omitempty"`
}
