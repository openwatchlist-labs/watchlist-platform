package catalogregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

func digest(value any) string {
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func stableID(prefix string, value any) string {
	return prefix + digest(value)[:24]
}

func registryID(namespace string) string {
	return stableID("catalog_registry_", struct {
		Namespace string `json:"namespace"`
	}{Namespace: strings.TrimSpace(namespace)})
}

func componentID(namespace, key string) string {
	return stableID("catalog_component_", struct {
		Namespace    string `json:"namespace"`
		ComponentKey string `json:"component_key"`
	}{Namespace: strings.TrimSpace(namespace), ComponentKey: strings.TrimSpace(key)})
}

func versionID(input VersionInput) string {
	return stableID("catalog_version_", struct {
		ComponentID     string `json:"component_id"`
		CatalogID       string `json:"catalog_id"`
		CatalogVersion  string `json:"catalog_version"`
		CatalogChecksum string `json:"catalog_checksum"`
		ArtifactSHA256  string `json:"artifact_sha256"`
	}{
		ComponentID:     strings.TrimSpace(input.ComponentID),
		CatalogID:       strings.TrimSpace(input.CatalogID),
		CatalogVersion:  strings.TrimSpace(input.CatalogVersion),
		CatalogChecksum: strings.ToLower(strings.TrimSpace(input.CatalogChecksum)),
		ArtifactSHA256:  strings.ToLower(strings.TrimSpace(input.ArtifactSHA256)),
	})
}

func activationID(record ActivationRecord) string {
	copy := record
	copy.ActivationID = ""
	copy.EventHash = ""
	return stableID("catalog_activation_", copy)
}

func componentChecksum(component Component) string {
	copy := component
	copy.ComponentChecksum = ""
	return digest(copy)
}

func versionChecksum(version CatalogVersion) string {
	copy := version
	copy.VersionChecksum = ""
	return digest(copy)
}

func activationEventHash(record ActivationRecord) string {
	copy := record
	copy.EventHash = ""
	return digest(copy)
}

func registryChecksum(registry Registry) string {
	copy := registry
	copy.RegistryChecksum = ""
	return digest(copy)
}
