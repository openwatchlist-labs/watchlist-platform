package alertlistmapping

import (
	"fmt"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogregistry"
)

func NewRegistry(namespace string) (Registry, error) {
	namespace = strings.TrimSpace(namespace)
	registry := Registry{
		SchemaVersion: MappingRegistrySchemaVersion,
		RegistryID:    registryID(namespace),
		Namespace:     namespace,
		EngineVersion: EngineVersion,
		Keys:          []MappingKey{},
		Versions:      []MappingVersion{},
	}
	registry.RegistryChecksum = registryChecksum(registry)
	if err := ValidateRegistry(registry, catalogregistry.Registry{}); err != nil {
		return Registry{}, err
	}
	return registry, nil
}

func BuildKey(registry Registry, input MappingInput) (MappingKey, error) {
	key := MappingKey{
		SchemaVersion:  MappingKeySchemaVersion,
		MappingID:      mappingID(registry.Namespace, input.SourceSystemID, input.RawListName),
		RegistryID:     registry.RegistryID,
		Namespace:      registry.Namespace,
		SourceSystemID: input.SourceSystemID,
		RawListName:    input.RawListName,
		CreatedAt:      input.CreatedAt.UTC(),
		CreatedBy:      strings.TrimSpace(input.CreatedBy),
	}
	key.KeyChecksum = keyChecksum(key)
	if err := ValidateKey(key); err != nil {
		return MappingKey{}, err
	}
	return key, nil
}

func BuildVersion(registry Registry, input MappingInput, catalog catalogregistry.Registry) (MappingVersion, error) {
	if err := ValidateMappingInput(input); err != nil {
		return MappingVersion{}, err
	}
	if catalog.Namespace != registry.Namespace {
		return MappingVersion{}, fmt.Errorf("catalog registry namespace %q does not match mapping registry %q", catalog.Namespace, registry.Namespace)
	}
	mappingID := mappingID(registry.Namespace, input.SourceSystemID, input.RawListName)
	var previous *MappingVersion
	for index := range registry.Versions {
		candidate := &registry.Versions[index]
		if candidate.MappingID != mappingID {
			continue
		}
		if previous == nil || candidate.EffectiveFrom.After(previous.EffectiveFrom) {
			previous = candidate
		}
	}
	if previous != nil && !input.EffectiveFrom.After(previous.EffectiveFrom) {
		candidateID := mappingVersionID(registry.RegistryID, mappingID, input)
		if previous.MappingVersionID == candidateID {
			return *previous, nil
		}
		return MappingVersion{}, fmt.Errorf("effective_from must advance beyond existing mapping version %s at %s", previous.MappingVersionID, previous.EffectiveFrom.Format("2006-01-02T15:04:05Z07:00"))
	}
	if input.Action == MappingActionBind {
		component, ok := catalogComponent(catalog, input.ComponentID)
		if !ok {
			return MappingVersion{}, fmt.Errorf("catalog component %q is not registered", input.ComponentID)
		}
		if component.Status != catalogregistry.ComponentStatusActive {
			return MappingVersion{}, fmt.Errorf("catalog component %q is not active", input.ComponentID)
		}
	}
	version := MappingVersion{
		SchemaVersion:     MappingVersionSchemaVersion,
		MappingVersionID:  mappingVersionID(registry.RegistryID, mappingID, input),
		MappingID:         mappingID,
		RegistryID:        registry.RegistryID,
		Namespace:         registry.Namespace,
		Sequence:          registry.LastSequence + 1,
		SourceSystemID:    input.SourceSystemID,
		RawListName:       input.RawListName,
		Action:            input.Action,
		ComponentID:       strings.TrimSpace(input.ComponentID),
		EffectiveFrom:     input.EffectiveFrom.UTC(),
		EffectiveTo:       normalizeTimePointer(input.EffectiveTo),
		Reason:            strings.TrimSpace(input.Reason),
		CreatedAt:         input.CreatedAt.UTC(),
		CreatedBy:         strings.TrimSpace(input.CreatedBy),
		PreviousEventHash: registry.AuditHead,
	}
	if previous != nil {
		version.SupersedesVersionID = previous.MappingVersionID
	}
	version.EventHash = eventHash(version)
	version.VersionChecksum = versionChecksum(version)
	if err := ValidateVersion(version, registry, catalog); err != nil {
		return MappingVersion{}, err
	}
	return version, nil
}

func normalizeTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	normalized := value.UTC()
	return &normalized
}

func catalogComponent(registry catalogregistry.Registry, componentID string) (catalogregistry.Component, bool) {
	for _, component := range registry.Components {
		if component.ComponentID == componentID {
			return component, true
		}
	}
	return catalogregistry.Component{}, false
}

func activePointer(registry catalogregistry.Registry, componentID string) (catalogregistry.ActivePointer, bool) {
	for _, pointer := range registry.Active {
		if pointer.ComponentID == componentID {
			return pointer, true
		}
	}
	return catalogregistry.ActivePointer{}, false
}

func catalogVersion(registry catalogregistry.Registry, versionID string) (catalogregistry.CatalogVersion, bool) {
	for _, version := range registry.Versions {
		if version.VersionID == versionID {
			return version, true
		}
	}
	return catalogregistry.CatalogVersion{}, false
}
