package alertlistmapping

import "time"

const (
	MappingKeySchemaVersion      = "alert-list-mapping-key/v1alpha1"
	MappingVersionSchemaVersion  = "alert-list-mapping-version/v1alpha1"
	MappingRegistrySchemaVersion = "alert-list-mapping-registry/v1alpha1"
	ResolutionSchemaVersion      = "alert-list-resolution/v1alpha1"
	BatchResolutionSchemaVersion = "alert-list-resolution-batch/v1alpha1"
	EngineVersion                = "alert-list-mapping/v0.1.0"
)

type MappingAction string

const (
	MappingActionBind   MappingAction = "bind"
	MappingActionRetire MappingAction = "retire"
)

type ResolutionStatus string

const (
	ResolutionResolved         ResolutionStatus = "resolved"
	ResolutionUnmapped         ResolutionStatus = "unmapped"
	ResolutionNotEffective     ResolutionStatus = "not_effective"
	ResolutionExpired          ResolutionStatus = "expired"
	ResolutionRetired          ResolutionStatus = "retired"
	ResolutionComponentMissing ResolutionStatus = "component_missing"
	ResolutionComponentRetired ResolutionStatus = "component_retired"
	ResolutionCatalogNotActive ResolutionStatus = "catalog_not_active"
)

const (
	BlockerMappingRequired     = "ALERT_LIST_MAPPING_REQUIRED"
	BlockerMappingNotEffective = "ALERT_LIST_MAPPING_NOT_EFFECTIVE"
	BlockerMappingExpired      = "ALERT_LIST_MAPPING_EXPIRED"
	BlockerMappingRetired      = "ALERT_LIST_MAPPING_RETIRED"
	BlockerComponentMissing    = "CATALOG_COMPONENT_NOT_FOUND"
	BlockerComponentRetired    = "CATALOG_COMPONENT_RETIRED"
	BlockerCatalogNotActive    = "CATALOG_COMPONENT_NOT_ACTIVE"
)

type MappingKey struct {
	SchemaVersion  string    `json:"schema_version"`
	MappingID      string    `json:"mapping_id"`
	RegistryID     string    `json:"registry_id"`
	Namespace      string    `json:"namespace"`
	SourceSystemID string    `json:"source_system_id"`
	RawListName    string    `json:"raw_list_name"`
	CreatedAt      time.Time `json:"created_at"`
	CreatedBy      string    `json:"created_by"`
	KeyChecksum    string    `json:"key_checksum"`
}

type MappingVersion struct {
	SchemaVersion       string        `json:"schema_version"`
	MappingVersionID    string        `json:"mapping_version_id"`
	MappingID           string        `json:"mapping_id"`
	RegistryID          string        `json:"registry_id"`
	Namespace           string        `json:"namespace"`
	Sequence            uint64        `json:"sequence"`
	SourceSystemID      string        `json:"source_system_id"`
	RawListName         string        `json:"raw_list_name"`
	Action              MappingAction `json:"action"`
	ComponentID         string        `json:"component_id,omitempty"`
	EffectiveFrom       time.Time     `json:"effective_from"`
	EffectiveTo         *time.Time    `json:"effective_to,omitempty"`
	SupersedesVersionID string        `json:"supersedes_version_id,omitempty"`
	Reason              string        `json:"reason"`
	CreatedAt           time.Time     `json:"created_at"`
	CreatedBy           string        `json:"created_by"`
	PreviousEventHash   string        `json:"previous_event_hash"`
	EventHash           string        `json:"event_hash"`
	VersionChecksum     string        `json:"version_checksum"`
}

type Registry struct {
	SchemaVersion    string           `json:"schema_version"`
	RegistryID       string           `json:"registry_id"`
	Namespace        string           `json:"namespace"`
	EngineVersion    string           `json:"engine_version"`
	LastSequence     uint64           `json:"last_sequence"`
	AuditHead        string           `json:"audit_head"`
	Keys             []MappingKey     `json:"keys"`
	Versions         []MappingVersion `json:"versions"`
	RegistryChecksum string           `json:"registry_checksum"`
}

type MappingInput struct {
	SourceSystemID string        `json:"source_system_id"`
	RawListName    string        `json:"raw_list_name"`
	Action         MappingAction `json:"action"`
	ComponentID    string        `json:"component_id,omitempty"`
	EffectiveFrom  time.Time     `json:"effective_from"`
	EffectiveTo    *time.Time    `json:"effective_to,omitempty"`
	Reason         string        `json:"reason"`
	CreatedAt      time.Time     `json:"created_at"`
	CreatedBy      string        `json:"created_by"`
}

type ResolveRequest struct {
	SourceSystemID string    `json:"source_system_id"`
	RawListName    string    `json:"raw_list_name"`
	At             time.Time `json:"at"`
}

type Resolution struct {
	SchemaVersion          string           `json:"schema_version"`
	MappingRegistryID      string           `json:"mapping_registry_id"`
	Namespace              string           `json:"namespace"`
	SourceSystemID         string           `json:"source_system_id"`
	RawListName            string           `json:"raw_list_name"`
	ResolvedAt             time.Time        `json:"resolved_at"`
	Status                 ResolutionStatus `json:"status"`
	Available              bool             `json:"available"`
	ExactMatch             bool             `json:"exact_match"`
	ReviewBlocker          string           `json:"review_blocker,omitempty"`
	MappingID              string           `json:"mapping_id,omitempty"`
	MappingVersionID       string           `json:"mapping_version_id,omitempty"`
	MappingEffectiveFrom   *time.Time       `json:"mapping_effective_from,omitempty"`
	MappingEffectiveTo     *time.Time       `json:"mapping_effective_to,omitempty"`
	ComponentID            string           `json:"component_id,omitempty"`
	ComponentKey           string           `json:"component_key,omitempty"`
	ComponentDisplayName   string           `json:"component_display_name,omitempty"`
	CatalogMode            string           `json:"catalog_mode,omitempty"`
	ActiveCatalogVersionID string           `json:"active_catalog_version_id,omitempty"`
	ActiveCatalogID        string           `json:"active_catalog_id,omitempty"`
	ActiveCatalogVersion   string           `json:"active_catalog_version,omitempty"`
	ActiveCatalogChecksum  string           `json:"active_catalog_checksum,omitempty"`
	ActiveArtifactURI      string           `json:"active_artifact_uri,omitempty"`
}

type BatchAlert struct {
	AlertID        string `json:"alert_id"`
	SourceSystemID string `json:"source_system_id"`
	RawListName    string `json:"raw_list_name"`
}

type BatchInput struct {
	At     time.Time    `json:"at"`
	Alerts []BatchAlert `json:"alerts"`
}

type BatchSummary struct {
	Total            int `json:"total"`
	Resolved         int `json:"resolved"`
	Unmapped         int `json:"unmapped"`
	NotEffective     int `json:"not_effective"`
	Expired          int `json:"expired"`
	Retired          int `json:"retired"`
	ComponentMissing int `json:"component_missing"`
	ComponentRetired int `json:"component_retired"`
	CatalogNotActive int `json:"catalog_not_active"`
}

type BatchResultItem struct {
	AlertID    string     `json:"alert_id"`
	Resolution Resolution `json:"resolution"`
}

type BatchResult struct {
	SchemaVersion string            `json:"schema_version"`
	ResolvedAt    time.Time         `json:"resolved_at"`
	Summary       BatchSummary      `json:"summary"`
	Results       []BatchResultItem `json:"results"`
}
