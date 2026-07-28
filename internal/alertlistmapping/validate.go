package alertlistmapping

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogregistry"
)

var (
	ErrInvalidRegistry  = errors.New("invalid alert-list mapping registry")
	sourceSystemPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
)

func ValidateMappingInput(input MappingInput) error {
	if !sourceSystemPattern.MatchString(input.SourceSystemID) {
		return fmt.Errorf("source_system_id must match %s", sourceSystemPattern.String())
	}
	if err := validateRawListName(input.RawListName); err != nil {
		return err
	}
	if input.Action != MappingActionBind && input.Action != MappingActionRetire {
		return fmt.Errorf("unsupported mapping action %q", input.Action)
	}
	if input.Action == MappingActionBind && strings.TrimSpace(input.ComponentID) == "" {
		return fmt.Errorf("component_id is required for bind action")
	}
	if input.Action == MappingActionRetire && strings.TrimSpace(input.ComponentID) != "" {
		return fmt.Errorf("component_id must be empty for retire action")
	}
	if input.EffectiveFrom.IsZero() {
		return fmt.Errorf("effective_from is required")
	}
	if input.EffectiveTo != nil && !input.EffectiveTo.After(input.EffectiveFrom) {
		return fmt.Errorf("effective_to must be after effective_from")
	}
	if strings.TrimSpace(input.Reason) == "" || strings.TrimSpace(input.CreatedBy) == "" || input.CreatedAt.IsZero() {
		return fmt.Errorf("reason, created_at, and created_by are required")
	}
	return nil
}

func ValidateKey(key MappingKey) error {
	if key.SchemaVersion != MappingKeySchemaVersion || key.RegistryID == "" || key.Namespace == "" || key.MappingID == "" {
		return fmt.Errorf("%w: invalid mapping key identity", ErrInvalidRegistry)
	}
	if !sourceSystemPattern.MatchString(key.SourceSystemID) {
		return fmt.Errorf("%w: invalid source_system_id", ErrInvalidRegistry)
	}
	if err := validateRawListName(key.RawListName); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRegistry, err)
	}
	if key.CreatedAt.IsZero() || strings.TrimSpace(key.CreatedBy) == "" {
		return fmt.Errorf("%w: missing key audit metadata", ErrInvalidRegistry)
	}
	if key.MappingID != mappingID(key.Namespace, key.SourceSystemID, key.RawListName) {
		return fmt.Errorf("%w: mapping ID mismatch", ErrInvalidRegistry)
	}
	if !isSHA256(key.KeyChecksum) || key.KeyChecksum != keyChecksum(key) {
		return fmt.Errorf("%w: key checksum mismatch", ErrInvalidRegistry)
	}
	return nil
}

func ValidateVersion(version MappingVersion, registry Registry, catalog catalogregistry.Registry) error {
	if version.SchemaVersion != MappingVersionSchemaVersion || version.RegistryID != registry.RegistryID || version.Namespace != registry.Namespace {
		return fmt.Errorf("%w: invalid mapping version identity", ErrInvalidRegistry)
	}
	input := MappingInput{
		SourceSystemID: version.SourceSystemID,
		RawListName:    version.RawListName,
		Action:         version.Action,
		ComponentID:    version.ComponentID,
		EffectiveFrom:  version.EffectiveFrom,
		EffectiveTo:    version.EffectiveTo,
		Reason:         version.Reason,
		CreatedAt:      version.CreatedAt,
		CreatedBy:      version.CreatedBy,
	}
	if err := ValidateMappingInput(input); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRegistry, err)
	}
	if version.MappingID != mappingID(version.Namespace, version.SourceSystemID, version.RawListName) || version.MappingVersionID != mappingVersionID(version.RegistryID, version.MappingID, input) {
		return fmt.Errorf("%w: mapping version ID mismatch", ErrInvalidRegistry)
	}
	if version.Sequence == 0 || !isSHA256(version.EventHash) || version.EventHash != eventHash(version) || !isSHA256(version.VersionChecksum) || version.VersionChecksum != versionChecksum(version) {
		return fmt.Errorf("%w: invalid version audit hashes", ErrInvalidRegistry)
	}
	if version.Action == MappingActionBind && catalog.RegistryID != "" {
		component, ok := catalogComponent(catalog, version.ComponentID)
		if !ok {
			return fmt.Errorf("%w: catalog component %s is not registered", ErrInvalidRegistry, version.ComponentID)
		}
		if component.Namespace != version.Namespace {
			return fmt.Errorf("%w: component namespace mismatch", ErrInvalidRegistry)
		}
	}
	return nil
}

func ValidateRegistry(registry Registry, catalog catalogregistry.Registry) error {
	if registry.SchemaVersion != MappingRegistrySchemaVersion || registry.RegistryID != registryID(registry.Namespace) || registry.Namespace == "" || registry.EngineVersion != EngineVersion {
		return fmt.Errorf("%w: invalid registry identity", ErrInvalidRegistry)
	}
	if catalog.RegistryID != "" && catalog.Namespace != registry.Namespace {
		return fmt.Errorf("%w: catalog namespace mismatch", ErrInvalidRegistry)
	}
	keyByID := map[string]MappingKey{}
	for _, key := range registry.Keys {
		if err := ValidateKey(key); err != nil {
			return err
		}
		if key.RegistryID != registry.RegistryID || key.Namespace != registry.Namespace {
			return fmt.Errorf("%w: key registry mismatch", ErrInvalidRegistry)
		}
		if _, exists := keyByID[key.MappingID]; exists {
			return fmt.Errorf("%w: duplicate mapping key", ErrInvalidRegistry)
		}
		keyByID[key.MappingID] = key
	}
	previousHash := ""
	lastByMapping := map[string]MappingVersion{}
	seenVersions := map[string]struct{}{}
	for index, version := range registry.Versions {
		if version.Sequence != uint64(index+1) || version.PreviousEventHash != previousHash {
			return fmt.Errorf("%w: sequence or audit chain discontinuity", ErrInvalidRegistry)
		}
		if _, exists := seenVersions[version.MappingVersionID]; exists {
			return fmt.Errorf("%w: duplicate mapping version", ErrInvalidRegistry)
		}
		key, ok := keyByID[version.MappingID]
		if !ok || key.SourceSystemID != version.SourceSystemID || key.RawListName != version.RawListName {
			return fmt.Errorf("%w: version does not match mapping key", ErrInvalidRegistry)
		}
		previous, hasPrevious := lastByMapping[version.MappingID]
		if hasPrevious {
			if !version.EffectiveFrom.After(previous.EffectiveFrom) || version.SupersedesVersionID != previous.MappingVersionID {
				return fmt.Errorf("%w: mapping timeline is not strictly advancing", ErrInvalidRegistry)
			}
		} else if version.SupersedesVersionID != "" {
			return fmt.Errorf("%w: initial mapping version has supersedes_version_id", ErrInvalidRegistry)
		}
		if err := ValidateVersion(version, registry, catalog); err != nil {
			return err
		}
		lastByMapping[version.MappingID] = version
		seenVersions[version.MappingVersionID] = struct{}{}
		previousHash = version.EventHash
	}
	if registry.LastSequence != uint64(len(registry.Versions)) || registry.AuditHead != previousHash {
		return fmt.Errorf("%w: last_sequence or audit_head mismatch", ErrInvalidRegistry)
	}
	if !sort.SliceIsSorted(registry.Keys, func(i, j int) bool { return registry.Keys[i].MappingID < registry.Keys[j].MappingID }) {
		return fmt.Errorf("%w: mapping keys must be sorted", ErrInvalidRegistry)
	}
	if !isSHA256(registry.RegistryChecksum) || registry.RegistryChecksum != registryChecksum(registry) {
		return fmt.Errorf("%w: registry checksum mismatch", ErrInvalidRegistry)
	}
	return nil
}

func validateRawListName(value string) error {
	if value == "" {
		return fmt.Errorf("raw_list_name is required")
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("raw_list_name must be valid UTF-8")
	}
	if len(value) > 512 {
		return fmt.Errorf("raw_list_name exceeds 512 bytes")
	}
	for _, r := range value {
		if r == 0 || r == '\n' || r == '\r' {
			return fmt.Errorf("raw_list_name contains a forbidden control character")
		}
	}
	return nil
}

func isSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
