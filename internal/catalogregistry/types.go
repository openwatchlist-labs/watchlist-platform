package catalogregistry

import "time"

const (
	ComponentSchemaVersion  = "catalog-component/v1alpha1"
	VersionSchemaVersion    = "catalog-component-version/v1alpha1"
	ActivationSchemaVersion = "catalog-component-activation/v1alpha1"
	PointerSchemaVersion    = "catalog-component-active-pointer/v1alpha1"
	RegistrySchemaVersion   = "catalog-component-registry/v1alpha1"
	EngineVersion           = "catalog-component-registry/v0.1.0"
)

type CatalogMode string

const (
	CatalogModeOfficial CatalogMode = "official_list"
	CatalogModeProvider CatalogMode = "provider"
)

type ComponentStatus string

const (
	ComponentStatusActive  ComponentStatus = "active"
	ComponentStatusRetired ComponentStatus = "retired"
)

type SourceKind string

const (
	SourceKindOfficial SourceKind = "official"
	SourceKindProvider SourceKind = "provider"
)

type ActivationAction string

const (
	ActivationActionActivate ActivationAction = "activate"
	ActivationActionRollback ActivationAction = "rollback"
)

type Component struct {
	SchemaVersion     string            `json:"schema_version"`
	ComponentID       string            `json:"component_id"`
	Namespace         string            `json:"namespace"`
	ComponentKey      string            `json:"component_key"`
	DisplayName       string            `json:"display_name"`
	CatalogMode       CatalogMode       `json:"catalog_mode"`
	Status            ComponentStatus   `json:"status"`
	Description       string            `json:"description,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	CreatedBy         string            `json:"created_by"`
	ComponentChecksum string            `json:"component_checksum"`
}

type OfficialSource struct {
	Authority    string `json:"authority"`
	ListKey      string `json:"list_key"`
	SourceFormat string `json:"source_format"`
	XMLVersion   string `json:"xml_version,omitempty"`
}

type ProviderSource struct {
	ProviderID           string `json:"provider_id"`
	ProviderComponentRef string `json:"provider_component_ref"`
	ProviderTitle        string `json:"provider_title,omitempty"`
	ProviderVersion      string `json:"provider_version,omitempty"`
}

type SourceDescriptor struct {
	Kind     SourceKind      `json:"kind"`
	Official *OfficialSource `json:"official,omitempty"`
	Provider *ProviderSource `json:"provider,omitempty"`
}

type CatalogVersion struct {
	SchemaVersion      string            `json:"schema_version"`
	VersionID          string            `json:"version_id"`
	ComponentID        string            `json:"component_id"`
	CatalogID          string            `json:"catalog_id"`
	CatalogVersion     string            `json:"catalog_version"`
	CatalogChecksum    string            `json:"catalog_checksum"`
	CatalogSchema      string            `json:"catalog_schema"`
	ArtifactURI        string            `json:"artifact_uri"`
	ArtifactSHA256     string            `json:"artifact_sha256"`
	SourceManifestID   string            `json:"source_manifest_id"`
	SourceManifestHash string            `json:"source_manifest_checksum,omitempty"`
	RecordCount        int               `json:"record_count"`
	ProducerVersion    string            `json:"producer_version"`
	Source             SourceDescriptor  `json:"source"`
	Metadata           map[string]string `json:"metadata,omitempty"`
	RegisteredAt       time.Time         `json:"registered_at"`
	RegisteredBy       string            `json:"registered_by"`
	VersionChecksum    string            `json:"version_checksum"`
}

type ActivationRecord struct {
	SchemaVersion     string           `json:"schema_version"`
	ActivationID      string           `json:"activation_id"`
	RegistryID        string           `json:"registry_id"`
	Sequence          uint64           `json:"sequence"`
	ComponentID       string           `json:"component_id"`
	Action            ActivationAction `json:"action"`
	TargetVersionID   string           `json:"target_version_id"`
	PreviousVersionID string           `json:"previous_version_id,omitempty"`
	ComponentEpoch    uint64           `json:"component_epoch"`
	Reason            string           `json:"reason"`
	ActivatedAt       time.Time        `json:"activated_at"`
	ActivatedBy       string           `json:"activated_by"`
	PreviousEventHash string           `json:"previous_event_hash"`
	EventHash         string           `json:"event_hash"`
}

type ActivePointer struct {
	SchemaVersion string    `json:"schema_version"`
	ComponentID   string    `json:"component_id"`
	VersionID     string    `json:"version_id"`
	ActivationID  string    `json:"activation_id"`
	Epoch         uint64    `json:"epoch"`
	ActivatedAt   time.Time `json:"activated_at"`
	ActivatedBy   string    `json:"activated_by"`
}

type Registry struct {
	SchemaVersion    string             `json:"schema_version"`
	RegistryID       string             `json:"registry_id"`
	Namespace        string             `json:"namespace"`
	EngineVersion    string             `json:"engine_version"`
	LastSequence     uint64             `json:"last_sequence"`
	AuditHead        string             `json:"audit_head"`
	Components       []Component        `json:"components"`
	Versions         []CatalogVersion   `json:"versions"`
	Activations      []ActivationRecord `json:"activations"`
	Active           []ActivePointer    `json:"active"`
	RegistryChecksum string             `json:"registry_checksum"`
}

type ComponentInput struct {
	Namespace    string            `json:"namespace"`
	ComponentKey string            `json:"component_key"`
	DisplayName  string            `json:"display_name"`
	CatalogMode  CatalogMode       `json:"catalog_mode"`
	Description  string            `json:"description,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	CreatedBy    string            `json:"created_by"`
}

type VersionInput struct {
	ComponentID        string            `json:"component_id"`
	CatalogID          string            `json:"catalog_id"`
	CatalogVersion     string            `json:"catalog_version"`
	CatalogChecksum    string            `json:"catalog_checksum"`
	CatalogSchema      string            `json:"catalog_schema"`
	ArtifactURI        string            `json:"artifact_uri"`
	ArtifactSHA256     string            `json:"artifact_sha256"`
	SourceManifestID   string            `json:"source_manifest_id"`
	SourceManifestHash string            `json:"source_manifest_checksum,omitempty"`
	RecordCount        int               `json:"record_count"`
	ProducerVersion    string            `json:"producer_version"`
	Source             SourceDescriptor  `json:"source"`
	Metadata           map[string]string `json:"metadata,omitempty"`
	RegisteredAt       time.Time         `json:"registered_at"`
	RegisteredBy       string            `json:"registered_by"`
}

type ActivationRequest struct {
	ComponentID              string           `json:"component_id"`
	TargetVersionID          string           `json:"target_version_id"`
	Action                   ActivationAction `json:"action"`
	ExpectedCurrentVersionID string           `json:"expected_current_version_id,omitempty"`
	Reason                   string           `json:"reason"`
	ActivatedAt              time.Time        `json:"activated_at"`
	ActivatedBy              string           `json:"activated_by"`
}
