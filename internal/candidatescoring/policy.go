package candidatescoring

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// LoadedPolicy is immutable policy content plus its canonical checksum.
type LoadedPolicy struct {
	Policy Policy
	SHA256 string
}

func LoadPolicy(path string) (LoadedPolicy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return LoadedPolicy{}, fmt.Errorf("read policy: %w", err)
	}
	return ParsePolicy(raw)
}

func ParsePolicy(raw []byte) (LoadedPolicy, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var policy Policy
	if err := dec.Decode(&policy); err != nil {
		return LoadedPolicy{}, fmt.Errorf("decode policy: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return LoadedPolicy{}, errors.New("decode policy: trailing JSON value")
		}
		return LoadedPolicy{}, fmt.Errorf("decode policy trailing content: %w", err)
	}
	if err := validatePolicy(policy); err != nil {
		return LoadedPolicy{}, err
	}
	canonical, err := json.Marshal(policy)
	if err != nil {
		return LoadedPolicy{}, fmt.Errorf("marshal canonical policy: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return LoadedPolicy{Policy: policy, SHA256: hex.EncodeToString(digest[:])}, nil
}

func validatePolicy(policy Policy) error {
	if policy.SchemaVersion != PolicySchemaV1 {
		return fmt.Errorf("policy schema_version %q is not %q", policy.SchemaVersion, PolicySchemaV1)
	}
	if strings.TrimSpace(policy.PolicyID) == "" || strings.TrimSpace(policy.PolicyVersion) == "" {
		return errors.New("policy_id and policy_version are required")
	}
	if strings.TrimSpace(policy.NormalizationProfile) == "" {
		return errors.New("normalization_profile is required")
	}
	if policy.MaxEvidenceItems < 1 || policy.MaxEvidenceItems > 64 {
		return errors.New("max_evidence_items must be between 1 and 64")
	}
	if policy.ScoreFloor < 0 || policy.ScoreCeiling <= policy.ScoreFloor {
		return errors.New("score_floor must be non-negative and score_ceiling must exceed it")
	}
	if policy.Thresholds.WeakCandidate < policy.ScoreFloor ||
		policy.Thresholds.ReviewCandidate < policy.Thresholds.WeakCandidate ||
		policy.Thresholds.StrongCandidate < policy.Thresholds.ReviewCandidate ||
		policy.Thresholds.StrongCandidate > policy.ScoreCeiling {
		return errors.New("thresholds must be ordered within score bounds")
	}
	positive := []int{
		policy.Weights.TypedIdentifierExact,
		policy.Weights.NameExact,
		policy.Weights.NameTokenSet,
		policy.Weights.NameParticleStripped,
		policy.Weights.NamePrefix,
		policy.Weights.NameContainment,
		policy.Weights.DateOfBirthExact,
		policy.Weights.DateOfBirthYear,
		policy.Weights.CountryExact,
		policy.Weights.EntityTypeExact,
	}
	for _, weight := range positive {
		if weight < 0 {
			return errors.New("supporting weights must be non-negative")
		}
	}
	negative := []int{
		policy.Weights.DateOfBirthConflict,
		policy.Weights.CountryConflict,
		policy.Weights.EntityTypeConflict,
	}
	for _, weight := range negative {
		if weight > 0 {
			return errors.New("conflict weights must be non-positive")
		}
	}
	return nil
}
