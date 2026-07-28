package catalogregistry

import (
	"fmt"
	"strings"
)

func BuildComponent(input ComponentInput) (Component, error) {
	component := Component{
		SchemaVersion: ComponentSchemaVersion,
		Namespace:     strings.TrimSpace(input.Namespace),
		ComponentKey:  strings.TrimSpace(input.ComponentKey),
		DisplayName:   strings.TrimSpace(input.DisplayName),
		CatalogMode:   input.CatalogMode,
		Status:        ComponentStatusActive,
		Description:   strings.TrimSpace(input.Description),
		Labels:        normalizedMap(input.Labels),
		CreatedAt:     input.CreatedAt.UTC(),
		CreatedBy:     strings.TrimSpace(input.CreatedBy),
	}
	component.ComponentID = componentID(component.Namespace, component.ComponentKey)
	component.ComponentChecksum = componentChecksum(component)
	if err := ValidateComponent(component); err != nil {
		return Component{}, err
	}
	return component, nil
}

func BuildVersion(input VersionInput, component Component) (CatalogVersion, error) {
	if err := ValidateComponent(component); err != nil {
		return CatalogVersion{}, err
	}
	if strings.TrimSpace(input.ComponentID) != component.ComponentID {
		return CatalogVersion{}, fmt.Errorf("version component_id %q does not match component %q", input.ComponentID, component.ComponentID)
	}
	version := CatalogVersion{
		SchemaVersion:      VersionSchemaVersion,
		ComponentID:        component.ComponentID,
		CatalogID:          strings.TrimSpace(input.CatalogID),
		CatalogVersion:     strings.TrimSpace(input.CatalogVersion),
		CatalogChecksum:    strings.ToLower(strings.TrimSpace(input.CatalogChecksum)),
		CatalogSchema:      strings.TrimSpace(input.CatalogSchema),
		ArtifactURI:        strings.TrimSpace(input.ArtifactURI),
		ArtifactSHA256:     strings.ToLower(strings.TrimSpace(input.ArtifactSHA256)),
		SourceManifestID:   strings.TrimSpace(input.SourceManifestID),
		SourceManifestHash: strings.ToLower(strings.TrimSpace(input.SourceManifestHash)),
		RecordCount:        input.RecordCount,
		ProducerVersion:    strings.TrimSpace(input.ProducerVersion),
		Source:             normalizeSource(input.Source),
		Metadata:           normalizedMap(input.Metadata),
		RegisteredAt:       input.RegisteredAt.UTC(),
		RegisteredBy:       strings.TrimSpace(input.RegisteredBy),
	}
	version.VersionID = versionID(input)
	version.VersionChecksum = versionChecksum(version)
	if err := ValidateVersion(version, component); err != nil {
		return CatalogVersion{}, err
	}
	return version, nil
}

func NewRegistry(namespace string) (Registry, error) {
	registry := Registry{
		SchemaVersion: RegistrySchemaVersion,
		RegistryID:    registryID(namespace),
		Namespace:     strings.TrimSpace(namespace),
		EngineVersion: EngineVersion,
		Components:    []Component{},
		Versions:      []CatalogVersion{},
		Activations:   []ActivationRecord{},
		Active:        []ActivePointer{},
	}
	registry.RegistryChecksum = registryChecksum(registry)
	if err := ValidateRegistry(registry); err != nil {
		return Registry{}, err
	}
	return registry, nil
}

func normalizedMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeSource(source SourceDescriptor) SourceDescriptor {
	source.Kind = SourceKind(strings.TrimSpace(string(source.Kind)))
	if source.Official != nil {
		copy := *source.Official
		copy.Authority = strings.TrimSpace(copy.Authority)
		copy.ListKey = strings.TrimSpace(copy.ListKey)
		copy.SourceFormat = strings.TrimSpace(copy.SourceFormat)
		copy.XMLVersion = strings.TrimSpace(copy.XMLVersion)
		source.Official = &copy
	}
	if source.Provider != nil {
		copy := *source.Provider
		copy.ProviderID = strings.TrimSpace(copy.ProviderID)
		copy.ProviderComponentRef = strings.TrimSpace(copy.ProviderComponentRef)
		copy.ProviderTitle = strings.TrimSpace(copy.ProviderTitle)
		copy.ProviderVersion = strings.TrimSpace(copy.ProviderVersion)
		source.Provider = &copy
	}
	return source
}
