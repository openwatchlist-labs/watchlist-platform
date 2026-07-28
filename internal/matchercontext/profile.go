package matchercontext

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

var ErrInvalidProfileSet = errors.New("invalid matcher context profile set")

func LoadProfileSet(reader io.Reader) (ProfileSet, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var set ProfileSet
	if err := decoder.Decode(&set); err != nil {
		return ProfileSet{}, fmt.Errorf("%w: decode: %v", ErrInvalidProfileSet, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return ProfileSet{}, fmt.Errorf("%w: multiple JSON values are not allowed", ErrInvalidProfileSet)
		}
		return ProfileSet{}, fmt.Errorf("%w: trailing data: %v", ErrInvalidProfileSet, err)
	}
	if err := ValidateProfileSet(set); err != nil {
		return ProfileSet{}, err
	}
	return set, nil
}

func ValidateProfileSet(set ProfileSet) error {
	if set.SchemaVersion != ProfileSetSchemaVersion {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidProfileSet, ProfileSetSchemaVersion)
	}
	for field, value := range map[string]string{
		"profile_set_id": set.ProfileSetID, "profile_set_version": set.ProfileSetVersion,
		"profile_set_checksum": set.ProfileSetChecksum, "matcher_version": set.MatcherVersion,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidProfileSet, field)
		}
	}
	if set.MatcherVersion != MatcherVersion {
		return fmt.Errorf("%w: matcher_version must be %q", ErrInvalidProfileSet, MatcherVersion)
	}
	if err := validateDigest(set.ProfileSetChecksum, "profile_set_checksum", ErrInvalidProfileSet); err != nil {
		return err
	}
	if len(set.Profiles) == 0 {
		return fmt.Errorf("%w: profiles must not be empty", ErrInvalidProfileSet)
	}
	previous := ""
	for index, profile := range set.Profiles {
		if strings.TrimSpace(profile.ProfileID) == "" {
			return fmt.Errorf("%w: profiles[%d].profile_id is required", ErrInvalidProfileSet, index)
		}
		if index > 0 && previous >= profile.ProfileID {
			return fmt.Errorf("%w: profiles must be sorted by unique profile_id", ErrInvalidProfileSet)
		}
		previous = profile.ProfileID
		if profile.ContextKind != ContextKindNarrative && profile.ContextKind != ContextKindJurisdiction {
			return fmt.Errorf("%w: profiles[%d].context_kind is unsupported", ErrInvalidProfileSet, index)
		}
		if profile.ThresholdBasisPoints < 0 || profile.ThresholdBasisPoints > 10000 || profile.DiagnosticFloorBasisPoints < 0 || profile.DiagnosticFloorBasisPoints > profile.ThresholdBasisPoints {
			return fmt.Errorf("%w: profiles[%d] thresholds are invalid", ErrInvalidProfileSet, index)
		}
		if len(profile.FeatureWeights) == 0 {
			return fmt.Errorf("%w: profiles[%d].feature_weights must not be empty", ErrInvalidProfileSet, index)
		}
		weightTotal, featurePrevious := 0, ""
		for featureIndex, feature := range profile.FeatureWeights {
			if strings.TrimSpace(feature.Name) == "" || (featureIndex > 0 && featurePrevious >= feature.Name) {
				return fmt.Errorf("%w: profiles[%d].feature_weights must be sorted by unique name", ErrInvalidProfileSet, index)
			}
			featurePrevious = feature.Name
			if feature.WeightBasisPoints < 0 || feature.WeightBasisPoints > 10000 {
				return fmt.Errorf("%w: profiles[%d].feature_weights[%d] is invalid", ErrInvalidProfileSet, index, featureIndex)
			}
			weightTotal += feature.WeightBasisPoints
		}
		if weightTotal != 10000 {
			return fmt.Errorf("%w: profiles[%d] feature weights total %d, expected 10000", ErrInvalidProfileSet, index, weightTotal)
		}
		if profile.ContextKind == ContextKindNarrative {
			if profile.OrderedWindowScoreBasisPoints <= 0 || profile.OrderedWindowScoreBasisPoints > 10000 || profile.MaxWindowExtraTokens < 0 || profile.MinSingleTokenLength < 1 || profile.DenialWindowTokens < 0 {
				return fmt.Errorf("%w: profiles[%d] narrative parameters are invalid", ErrInvalidProfileSet, index)
			}
			if profile.WeakAliasPenaltyBasisPoints < 0 || profile.WeakAliasPenaltyBasisPoints > 10000 || profile.DenialPenaltyBasisPoints < 0 || profile.DenialPenaltyBasisPoints > 10000 {
				return fmt.Errorf("%w: profiles[%d] narrative penalties are invalid", ErrInvalidProfileSet, index)
			}
			markerPrevious := ""
			for markerIndex, marker := range profile.DenialMarkers {
				canonical := fold(marker)
				if canonical == "" || canonical != marker || (markerIndex > 0 && markerPrevious >= marker) {
					return fmt.Errorf("%w: profiles[%d].denial_markers must be folded, sorted, and unique", ErrInvalidProfileSet, index)
				}
				markerPrevious = marker
			}
		}
	}
	if expected := StableProfileSetChecksum(set); set.ProfileSetChecksum != expected {
		return fmt.Errorf("%w: profile_set_checksum=%q expected %q", ErrInvalidProfileSet, set.ProfileSetChecksum, expected)
	}
	return nil
}

func StableProfileSetChecksum(set ProfileSet) string {
	parts := []string{ProfileSetSchemaVersion, set.ProfileSetID, set.ProfileSetVersion, set.MatcherVersion}
	profiles := append([]ContextProfile(nil), set.Profiles...)
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].ProfileID < profiles[j].ProfileID })
	for _, profile := range profiles {
		parts = append(parts, profile.ProfileID, profile.ContextKind, strconv.Itoa(profile.ThresholdBasisPoints), strconv.Itoa(profile.DiagnosticFloorBasisPoints))
		for _, feature := range profile.FeatureWeights {
			parts = append(parts, feature.Name, strconv.Itoa(feature.WeightBasisPoints))
		}
		parts = append(parts,
			strconv.Itoa(profile.OrderedWindowScoreBasisPoints), strconv.Itoa(profile.MaxWindowExtraTokens),
			strconv.Itoa(profile.MinSingleTokenLength), strconv.Itoa(profile.WeakAliasPenaltyBasisPoints),
			strconv.Itoa(profile.DenialPenaltyBasisPoints), strconv.Itoa(profile.DenialWindowTokens),
			strings.Join(profile.DenialMarkers, "\x1e"),
		)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(sum[:])
}

func (set ProfileSet) Profile(profileID, kind string) (ContextProfile, bool) {
	index := sort.Search(len(set.Profiles), func(index int) bool { return set.Profiles[index].ProfileID >= profileID })
	if index < len(set.Profiles) && set.Profiles[index].ProfileID == profileID && set.Profiles[index].ContextKind == kind {
		return set.Profiles[index], true
	}
	return ContextProfile{}, false
}

func validateDigest(value, field string, sentinel error) error {
	if len(value) != 64 {
		return fmt.Errorf("%w: %s must be a SHA-256 hex digest", sentinel, field)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("%w: %s is not hexadecimal", sentinel, field)
	}
	return nil
}
