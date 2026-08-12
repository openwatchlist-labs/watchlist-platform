package screeningapi

import (
	"fmt"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/candidatescoring"
	"github.com/openwatchlist-labs/watchlist-platform/internal/scoringactivation"
)

// ScoringBinding is the scoring engine, lineage, projection index, and
// policy reference held once at startup from a verified
// scoringactivation.Snapshot (ADR-0004 §4). It is read-only for the process
// lifetime: built once, shared across concurrent requests.
type ScoringBinding struct {
	engine  *Phase8CCandidateScorer
	lineage candidatescoring.Lineage
	index   map[string]candidatescoring.Candidate
	policy  candidatescoring.PolicyReference
}

// NewScoringBinding builds the binding from one verified activation
// snapshot. Every lineage field traces to Snapshot.Activation content --
// none is config-declared (ADR-0004 §2, §4).
func NewScoringBinding(snapshot scoringactivation.Snapshot) (*ScoringBinding, error) {
	engine, err := candidatescoring.NewEngine(snapshot.Policy)
	if err != nil {
		return nil, fmt.Errorf("construct scoring engine: %w", err)
	}
	scorer := NewPhase8CCandidateScorer(engine)
	lineage := candidatescoring.Lineage{
		Provider:             snapshot.Activation.Catalog.Provider,
		CatalogID:            snapshot.Activation.Catalog.CatalogID,
		ComponentID:          snapshot.Activation.Catalog.ComponentID,
		ComponentVersion:     snapshot.Activation.Catalog.ComponentVersion,
		ActivationID:         snapshot.Activation.ActivationID,
		NormalizationProfile: snapshot.Activation.Catalog.NormalizationProfile,
	}
	candidates := snapshot.ProjectionPackage.Projections.Candidates
	index := make(map[string]candidatescoring.Candidate, len(candidates))
	for _, candidate := range candidates {
		index[candidate.CandidateID] = candidate
	}
	return &ScoringBinding{engine: scorer, lineage: lineage, index: index, policy: scorer.PolicyReference()}, nil
}

// ValidateScoringRuntimeProfile proves the runtime package the screening
// service actually serves carries the same normalization_profile as the
// scoring policy, reading the value from the runtime's own PackageInfo
// (sourced from internal/mmapcatalogcontract.ReadNormalizationProfile, see
// ADR-0004 §8) rather than from any config-declared descriptor field. This
// is precisely the check v8d only pretended to perform (ADR-0004 §2):
// comparing config against config always passes.
func ValidateScoringRuntimeProfile(runtime RuntimeProvider, snapshot scoringactivation.Snapshot) error {
	sha := snapshot.Activation.Catalog.CatalogPackageSHA256
	info, ok := runtime.PackageInfo(sha)
	if !ok {
		return fmt.Errorf("no bound runtime package matches scoring activation catalog_package_sha256 %s", sha)
	}
	policyProfile := snapshot.Policy.Policy.NormalizationProfile
	if !strings.EqualFold(info.NormalizationProfile, policyProfile) {
		return fmt.Errorf("runtime package normalization_profile %q does not match scoring policy normalization_profile %q (catalog_package_sha256 %s)", info.NormalizationProfile, policyProfile, sha)
	}
	return nil
}
