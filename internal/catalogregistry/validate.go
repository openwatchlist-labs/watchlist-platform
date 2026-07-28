package catalogregistry

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var (
	ErrInvalidComponent  = errors.New("invalid catalog component")
	ErrInvalidVersion    = errors.New("invalid catalog component version")
	ErrInvalidActivation = errors.New("invalid catalog component activation")
	ErrInvalidRegistry   = errors.New("invalid catalog component registry")
)

func ValidateComponent(component Component) error {
	if component.SchemaVersion != ComponentSchemaVersion {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidComponent, ComponentSchemaVersion)
	}
	for field, value := range map[string]string{
		"component_id":       component.ComponentID,
		"namespace":          component.Namespace,
		"component_key":      component.ComponentKey,
		"display_name":       component.DisplayName,
		"created_by":         component.CreatedBy,
		"component_checksum": component.ComponentChecksum,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidComponent, field)
		}
	}
	if component.CatalogMode != CatalogModeOfficial && component.CatalogMode != CatalogModeProvider {
		return fmt.Errorf("%w: unsupported catalog_mode %q", ErrInvalidComponent, component.CatalogMode)
	}
	if component.Status != ComponentStatusActive && component.Status != ComponentStatusRetired {
		return fmt.Errorf("%w: unsupported status %q", ErrInvalidComponent, component.Status)
	}
	if component.CreatedAt.IsZero() {
		return fmt.Errorf("%w: created_at is required", ErrInvalidComponent)
	}
	if expected := componentID(component.Namespace, component.ComponentKey); component.ComponentID != expected {
		return fmt.Errorf("%w: component_id=%q expected %q", ErrInvalidComponent, component.ComponentID, expected)
	}
	if !isSHA256(component.ComponentChecksum) || component.ComponentChecksum != componentChecksum(component) {
		return fmt.Errorf("%w: component checksum mismatch", ErrInvalidComponent)
	}
	return nil
}

func ValidateVersion(version CatalogVersion, component Component) error {
	if version.SchemaVersion != VersionSchemaVersion {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidVersion, VersionSchemaVersion)
	}
	if err := ValidateComponent(component); err != nil {
		return err
	}
	for field, value := range map[string]string{
		"version_id":         version.VersionID,
		"component_id":       version.ComponentID,
		"catalog_id":         version.CatalogID,
		"catalog_version":    version.CatalogVersion,
		"catalog_checksum":   version.CatalogChecksum,
		"catalog_schema":     version.CatalogSchema,
		"artifact_uri":       version.ArtifactURI,
		"artifact_sha256":    version.ArtifactSHA256,
		"source_manifest_id": version.SourceManifestID,
		"producer_version":   version.ProducerVersion,
		"registered_by":      version.RegisteredBy,
		"version_checksum":   version.VersionChecksum,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidVersion, field)
		}
	}
	if version.ComponentID != component.ComponentID {
		return fmt.Errorf("%w: component_id does not match component", ErrInvalidVersion)
	}
	if !isSHA256(version.CatalogChecksum) || !isSHA256(version.ArtifactSHA256) || !isSHA256(version.VersionChecksum) {
		return fmt.Errorf("%w: catalog, artifact, and version checksums must be SHA-256", ErrInvalidVersion)
	}
	if version.SourceManifestHash != "" && !isSHA256(version.SourceManifestHash) {
		return fmt.Errorf("%w: source_manifest_checksum must be SHA-256", ErrInvalidVersion)
	}
	if version.RecordCount < 1 || version.RegisteredAt.IsZero() {
		return fmt.Errorf("%w: record_count and registered_at are required", ErrInvalidVersion)
	}
	if err := validateSource(version.Source, component.CatalogMode); err != nil {
		return err
	}
	input := VersionInput{
		ComponentID: version.ComponentID, CatalogID: version.CatalogID, CatalogVersion: version.CatalogVersion,
		CatalogChecksum: version.CatalogChecksum, ArtifactSHA256: version.ArtifactSHA256,
	}
	if expected := versionID(input); version.VersionID != expected {
		return fmt.Errorf("%w: version_id=%q expected %q", ErrInvalidVersion, version.VersionID, expected)
	}
	if version.VersionChecksum != versionChecksum(version) {
		return fmt.Errorf("%w: version checksum mismatch", ErrInvalidVersion)
	}
	return nil
}

func validateSource(source SourceDescriptor, mode CatalogMode) error {
	switch source.Kind {
	case SourceKindOfficial:
		if mode != CatalogModeOfficial || source.Official == nil || source.Provider != nil {
			return fmt.Errorf("%w: official source must be used only by official_list components", ErrInvalidVersion)
		}
		if source.Official.Authority == "" || source.Official.ListKey == "" || source.Official.SourceFormat == "" {
			return fmt.Errorf("%w: official authority, list_key, and source_format are required", ErrInvalidVersion)
		}
		if source.Official.Authority == "US_TREASURY_OFAC" && source.Official.SourceFormat != "ofac_advanced_xml" {
			return fmt.Errorf("%w: OFAC official mode supports only ofac_advanced_xml", ErrInvalidVersion)
		}
	case SourceKindProvider:
		if mode != CatalogModeProvider || source.Provider == nil || source.Official != nil {
			return fmt.Errorf("%w: provider source must be used only by provider components", ErrInvalidVersion)
		}
		if source.Provider.ProviderID == "" || source.Provider.ProviderComponentRef == "" {
			return fmt.Errorf("%w: provider_id and provider_component_ref are required", ErrInvalidVersion)
		}
	default:
		return fmt.Errorf("%w: unsupported source kind %q", ErrInvalidVersion, source.Kind)
	}
	return nil
}

func ValidateActivation(record ActivationRecord, registry Registry) error {
	if record.SchemaVersion != ActivationSchemaVersion {
		return fmt.Errorf("%w: invalid schema_version", ErrInvalidActivation)
	}
	for field, value := range map[string]string{
		"activation_id":     record.ActivationID,
		"registry_id":       record.RegistryID,
		"component_id":      record.ComponentID,
		"target_version_id": record.TargetVersionID,
		"reason":            record.Reason,
		"activated_by":      record.ActivatedBy,
		"event_hash":        record.EventHash,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidActivation, field)
		}
	}
	if record.RegistryID != registry.RegistryID || record.Sequence == 0 || record.ComponentEpoch == 0 || record.ActivatedAt.IsZero() {
		return fmt.Errorf("%w: registry, sequence, epoch, and activated_at are required", ErrInvalidActivation)
	}
	if record.Action != ActivationActionActivate && record.Action != ActivationActionRollback {
		return fmt.Errorf("%w: unsupported action %q", ErrInvalidActivation, record.Action)
	}
	if record.Action == ActivationActionRollback && record.PreviousVersionID == "" {
		return fmt.Errorf("%w: rollback requires previous_version_id", ErrInvalidActivation)
	}
	if record.ActivationID != activationID(record) || !isSHA256(record.EventHash) || record.EventHash != activationEventHash(record) {
		return fmt.Errorf("%w: activation identity or event hash mismatch", ErrInvalidActivation)
	}
	return nil
}

func ValidatePointer(pointer ActivePointer) error {
	if pointer.SchemaVersion != PointerSchemaVersion || pointer.ComponentID == "" || pointer.VersionID == "" || pointer.ActivationID == "" || pointer.Epoch == 0 || pointer.ActivatedAt.IsZero() || pointer.ActivatedBy == "" {
		return fmt.Errorf("%w: invalid active pointer", ErrInvalidRegistry)
	}
	return nil
}

func ValidateRegistry(registry Registry) error {
	if registry.SchemaVersion != RegistrySchemaVersion || registry.EngineVersion != EngineVersion {
		return fmt.Errorf("%w: invalid registry contract", ErrInvalidRegistry)
	}
	if strings.TrimSpace(registry.Namespace) == "" || registry.RegistryID != registryID(registry.Namespace) {
		return fmt.Errorf("%w: invalid namespace or registry_id", ErrInvalidRegistry)
	}
	componentByID := map[string]Component{}
	componentKey := map[string]struct{}{}
	for _, component := range registry.Components {
		if err := ValidateComponent(component); err != nil {
			return err
		}
		if component.Namespace != registry.Namespace {
			return fmt.Errorf("%w: component %s belongs to another namespace", ErrInvalidRegistry, component.ComponentID)
		}
		if _, ok := componentByID[component.ComponentID]; ok {
			return fmt.Errorf("%w: duplicate component %s", ErrInvalidRegistry, component.ComponentID)
		}
		if _, ok := componentKey[component.ComponentKey]; ok {
			return fmt.Errorf("%w: duplicate component_key %s", ErrInvalidRegistry, component.ComponentKey)
		}
		componentByID[component.ComponentID] = component
		componentKey[component.ComponentKey] = struct{}{}
	}
	versionByID := map[string]CatalogVersion{}
	for _, version := range registry.Versions {
		component, ok := componentByID[version.ComponentID]
		if !ok {
			return fmt.Errorf("%w: version %s references unknown component", ErrInvalidRegistry, version.VersionID)
		}
		if err := ValidateVersion(version, component); err != nil {
			return err
		}
		if _, ok := versionByID[version.VersionID]; ok {
			return fmt.Errorf("%w: duplicate version %s", ErrInvalidRegistry, version.VersionID)
		}
		versionByID[version.VersionID] = version
	}
	var previousHash string
	var expectedSequence uint64 = 1
	lastEpoch := map[string]uint64{}
	activatedVersions := map[string]map[string]struct{}{}
	activationByID := map[string]ActivationRecord{}
	for _, activation := range registry.Activations {
		if activation.Sequence != expectedSequence || activation.PreviousEventHash != previousHash {
			return fmt.Errorf("%w: activation chain discontinuity at sequence %d", ErrInvalidRegistry, activation.Sequence)
		}
		if _, ok := componentByID[activation.ComponentID]; !ok {
			return fmt.Errorf("%w: activation references unknown component", ErrInvalidRegistry)
		}
		version, ok := versionByID[activation.TargetVersionID]
		if !ok || version.ComponentID != activation.ComponentID {
			return fmt.Errorf("%w: activation references invalid target version", ErrInvalidRegistry)
		}
		if activation.ComponentEpoch != lastEpoch[activation.ComponentID]+1 {
			return fmt.Errorf("%w: component epoch discontinuity", ErrInvalidRegistry)
		}
		if activation.Action == ActivationActionRollback {
			if _, ok := activatedVersions[activation.ComponentID][activation.TargetVersionID]; !ok {
				return fmt.Errorf("%w: rollback target was never active", ErrInvalidRegistry)
			}
		}
		if err := ValidateActivation(activation, registry); err != nil {
			return err
		}
		if activatedVersions[activation.ComponentID] == nil {
			activatedVersions[activation.ComponentID] = map[string]struct{}{}
		}
		activatedVersions[activation.ComponentID][activation.TargetVersionID] = struct{}{}
		activationByID[activation.ActivationID] = activation
		lastEpoch[activation.ComponentID] = activation.ComponentEpoch
		previousHash = activation.EventHash
		expectedSequence++
	}
	if registry.LastSequence != uint64(len(registry.Activations)) || registry.AuditHead != previousHash {
		return fmt.Errorf("%w: last_sequence or audit_head mismatch", ErrInvalidRegistry)
	}
	activeByComponent := map[string]struct{}{}
	for _, pointer := range registry.Active {
		if err := ValidatePointer(pointer); err != nil {
			return err
		}
		if _, ok := activeByComponent[pointer.ComponentID]; ok {
			return fmt.Errorf("%w: duplicate active pointer", ErrInvalidRegistry)
		}
		version, ok := versionByID[pointer.VersionID]
		activation, activationOK := activationByID[pointer.ActivationID]
		if !ok || !activationOK || version.ComponentID != pointer.ComponentID || activation.TargetVersionID != pointer.VersionID || activation.ComponentEpoch != pointer.Epoch {
			return fmt.Errorf("%w: inconsistent active pointer", ErrInvalidRegistry)
		}
		activeByComponent[pointer.ComponentID] = struct{}{}
	}
	if !sort.SliceIsSorted(registry.Components, func(i, j int) bool { return registry.Components[i].ComponentID < registry.Components[j].ComponentID }) ||
		!sort.SliceIsSorted(registry.Versions, func(i, j int) bool { return registry.Versions[i].VersionID < registry.Versions[j].VersionID }) ||
		!sort.SliceIsSorted(registry.Active, func(i, j int) bool { return registry.Active[i].ComponentID < registry.Active[j].ComponentID }) {
		return fmt.Errorf("%w: components, versions, and active pointers must be sorted", ErrInvalidRegistry)
	}
	if !isSHA256(registry.RegistryChecksum) || registry.RegistryChecksum != registryChecksum(registry) {
		return fmt.Errorf("%w: registry checksum mismatch", ErrInvalidRegistry)
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
