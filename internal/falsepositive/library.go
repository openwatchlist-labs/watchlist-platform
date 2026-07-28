package falsepositive

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
)

var ErrInvalidPatternLibrary = errors.New("invalid false-positive pattern library")

func LoadPatternLibrary(path string) (PatternLibrary, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return PatternLibrary{}, fmt.Errorf("%w: read: %v", ErrInvalidPatternLibrary, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var library PatternLibrary
	if err := decoder.Decode(&library); err != nil {
		return PatternLibrary{}, fmt.Errorf("%w: decode: %v", ErrInvalidPatternLibrary, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return PatternLibrary{}, fmt.Errorf("%w: trailing JSON value", ErrInvalidPatternLibrary)
		}
		return PatternLibrary{}, fmt.Errorf("%w: trailing JSON: %v", ErrInvalidPatternLibrary, err)
	}
	if err := ValidatePatternLibrary(library); err != nil {
		return PatternLibrary{}, err
	}
	return library, nil
}

func ValidatePatternLibrary(library PatternLibrary) error {
	if library.SchemaVersion != PatternLibrarySchemaVersion {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidPatternLibrary, PatternLibrarySchemaVersion)
	}
	for field, value := range map[string]string{
		"library_id":       library.LibraryID,
		"library_version":  library.LibraryVersion,
		"library_checksum": library.LibraryChecksum,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidPatternLibrary, field)
		}
	}
	if len(library.Patterns) == 0 {
		return fmt.Errorf("%w: patterns are required", ErrInvalidPatternLibrary)
	}
	seen := map[string]struct{}{}
	codes := make([]string, 0, len(library.Patterns))
	for index, pattern := range library.Patterns {
		if strings.TrimSpace(pattern.Code) == "" {
			return fmt.Errorf("%w: patterns[%d].code is required", ErrInvalidPatternLibrary, index)
		}
		if _, exists := seen[pattern.Code]; exists {
			return fmt.Errorf("%w: duplicate pattern %q", ErrInvalidPatternLibrary, pattern.Code)
		}
		seen[pattern.Code] = struct{}{}
		codes = append(codes, pattern.Code)
		if pattern.DefaultStrengthBasisPoints < 0 || pattern.DefaultStrengthBasisPoints > 10000 {
			return fmt.Errorf("%w: pattern %q strength outside 0..10000", ErrInvalidPatternLibrary, pattern.Code)
		}
		if !validRouteHint(pattern.RouteHint) {
			return fmt.Errorf("%w: pattern %q has invalid route_hint %q", ErrInvalidPatternLibrary, pattern.Code, pattern.RouteHint)
		}
		if !reflect.DeepEqual(pattern.EscalationBlockers, canonicalStrings(pattern.EscalationBlockers)) {
			return fmt.Errorf("%w: pattern %q escalation_blockers must be sorted and unique", ErrInvalidPatternLibrary, pattern.Code)
		}
		if !reflect.DeepEqual(pattern.ReasonCodes, canonicalStrings(pattern.ReasonCodes)) {
			return fmt.Errorf("%w: pattern %q reason_codes must be sorted and unique", ErrInvalidPatternLibrary, pattern.Code)
		}
	}
	if !sort.StringsAreSorted(codes) {
		return fmt.Errorf("%w: patterns must be ordered by code", ErrInvalidPatternLibrary)
	}
	if expected := PatternLibraryChecksum(library); library.LibraryChecksum != expected {
		return fmt.Errorf("%w: library_checksum=%q expected %q", ErrInvalidPatternLibrary, library.LibraryChecksum, expected)
	}
	return nil
}

func PatternLibraryChecksum(library PatternLibrary) string {
	copy := library
	copy.LibraryChecksum = ""
	data, _ := json.Marshal(copy)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (library PatternLibrary) Reference() PatternLibraryReference {
	return PatternLibraryReference{
		LibraryID:       library.LibraryID,
		LibraryVersion:  library.LibraryVersion,
		LibraryChecksum: library.LibraryChecksum,
	}
}

func (library PatternLibrary) definition(code string) (PatternDefinition, bool) {
	index := sort.Search(len(library.Patterns), func(index int) bool {
		return library.Patterns[index].Code >= code
	})
	if index < len(library.Patterns) && library.Patterns[index].Code == code {
		return library.Patterns[index], true
	}
	return PatternDefinition{}, false
}

func validRouteHint(value RouteHint) bool {
	switch value {
	case RouteClearEligible, RouteInvestigate, RouteManualReview, RouteEscalationCandidate:
		return true
	default:
		return false
	}
}
