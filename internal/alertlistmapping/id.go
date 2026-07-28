package alertlistmapping

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
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
	return stableID("alert_list_mapping_registry_", struct {
		Namespace string `json:"namespace"`
	}{Namespace: namespace})
}

func mappingID(namespace, sourceSystemID, rawListName string) string {
	return stableID("alert_list_mapping_", struct {
		Namespace      string `json:"namespace"`
		SourceSystemID string `json:"source_system_id"`
		RawListName    string `json:"raw_list_name"`
	}{Namespace: namespace, SourceSystemID: sourceSystemID, RawListName: rawListName})
}

func mappingVersionID(registryID, mappingID string, input MappingInput) string {
	return stableID("alert_list_mapping_version_", struct {
		RegistryID    string        `json:"registry_id"`
		MappingID     string        `json:"mapping_id"`
		Action        MappingAction `json:"action"`
		ComponentID   string        `json:"component_id,omitempty"`
		EffectiveFrom string        `json:"effective_from"`
		EffectiveTo   string        `json:"effective_to,omitempty"`
		Reason        string        `json:"reason"`
		CreatedAt     string        `json:"created_at"`
		CreatedBy     string        `json:"created_by"`
	}{
		RegistryID:    registryID,
		MappingID:     mappingID,
		Action:        input.Action,
		ComponentID:   strings.TrimSpace(input.ComponentID),
		EffectiveFrom: input.EffectiveFrom.UTC().Format("2006-01-02T15:04:05Z07:00"),
		EffectiveTo:   timeString(input.EffectiveTo),
		Reason:        strings.TrimSpace(input.Reason),
		CreatedAt:     input.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		CreatedBy:     strings.TrimSpace(input.CreatedBy),
	})
}

func timeString(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format("2006-01-02T15:04:05Z07:00")
}

func keyChecksum(key MappingKey) string {
	copy := key
	copy.KeyChecksum = ""
	return digest(copy)
}

func versionChecksum(version MappingVersion) string {
	copy := version
	copy.VersionChecksum = ""
	return digest(copy)
}

func eventHash(version MappingVersion) string {
	copy := version
	copy.EventHash = ""
	copy.VersionChecksum = ""
	return digest(copy)
}

func registryChecksum(registry Registry) string {
	copy := registry
	copy.RegistryChecksum = ""
	return digest(copy)
}
