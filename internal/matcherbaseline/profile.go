package matcherbaseline

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

var ErrInvalidProfileSet = errors.New("invalid matcher threshold profile set")

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
		"profile_set_id":       set.ProfileSetID,
		"profile_set_version":  set.ProfileSetVersion,
		"profile_set_checksum": set.ProfileSetChecksum,
		"matcher_version":      set.MatcherVersion,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidProfileSet, field)
		}
	}
	if set.MatcherVersion != MatcherVersion {
		return fmt.Errorf("%w: matcher_version must be %q", ErrInvalidProfileSet, MatcherVersion)
	}
	if len(set.ProfileSetChecksum) != 64 {
		return fmt.Errorf("%w: profile_set_checksum must be a SHA-256 hex digest", ErrInvalidProfileSet)
	}
	if _, err := hex.DecodeString(set.ProfileSetChecksum); err != nil {
		return fmt.Errorf("%w: profile_set_checksum is not hexadecimal", ErrInvalidProfileSet)
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
		if profile.ThresholdBasisPoints < 0 || profile.ThresholdBasisPoints > 10000 || profile.DiagnosticFloorBasisPoints < 0 || profile.DiagnosticFloorBasisPoints > profile.ThresholdBasisPoints {
			return fmt.Errorf("%w: profiles[%d] thresholds are invalid", ErrInvalidProfileSet, index)
		}
		weights := []int{profile.TokenAlignmentWeightBasisPoints, profile.EditSimilarityWeightBasisPoints, profile.OrderedTokenWeightBasisPoints, profile.PhoneticWeightBasisPoints, profile.LengthWeightBasisPoints}
		total := 0
		for _, weight := range weights {
			if weight < 0 || weight > 10000 {
				return fmt.Errorf("%w: profiles[%d] weight is outside 0..10000", ErrInvalidProfileSet, index)
			}
			total += weight
		}
		if total != 10000 {
			return fmt.Errorf("%w: profiles[%d] weights total %d, expected 10000", ErrInvalidProfileSet, index, total)
		}
		if profile.SingleTokenPenaltyBasisPoints < 0 || profile.SingleTokenPenaltyBasisPoints > 10000 || profile.WeakAliasPenaltyBasisPoints < 0 || profile.WeakAliasPenaltyBasisPoints > 10000 {
			return fmt.Errorf("%w: profiles[%d] penalties are invalid", ErrInvalidProfileSet, index)
		}
	}
	if expected := StableProfileSetChecksum(set); set.ProfileSetChecksum != expected {
		return fmt.Errorf("%w: profile_set_checksum=%q expected %q", ErrInvalidProfileSet, set.ProfileSetChecksum, expected)
	}
	return nil
}

func StableProfileSetChecksum(set ProfileSet) string {
	parts := []string{ProfileSetSchemaVersion, set.ProfileSetID, set.ProfileSetVersion, set.MatcherVersion}
	profiles := append([]ThresholdProfile(nil), set.Profiles...)
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].ProfileID < profiles[j].ProfileID })
	for _, profile := range profiles {
		parts = append(parts,
			profile.ProfileID,
			strconv.Itoa(profile.ThresholdBasisPoints),
			strconv.Itoa(profile.DiagnosticFloorBasisPoints),
			strconv.Itoa(profile.TokenAlignmentWeightBasisPoints),
			strconv.Itoa(profile.EditSimilarityWeightBasisPoints),
			strconv.Itoa(profile.OrderedTokenWeightBasisPoints),
			strconv.Itoa(profile.PhoneticWeightBasisPoints),
			strconv.Itoa(profile.LengthWeightBasisPoints),
			strconv.Itoa(profile.SingleTokenPenaltyBasisPoints),
			strconv.Itoa(profile.WeakAliasPenaltyBasisPoints),
		)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(sum[:])
}

func (set ProfileSet) Profile(profileID string) (ThresholdProfile, bool) {
	index := sort.Search(len(set.Profiles), func(index int) bool { return set.Profiles[index].ProfileID >= profileID })
	if index < len(set.Profiles) && set.Profiles[index].ProfileID == profileID {
		return set.Profiles[index], true
	}
	return ThresholdProfile{}, false
}
