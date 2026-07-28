package providerrefresh

import "time"

const (
	InventorySchemaVersion = "provider-inventory/v1alpha1"
	PolicySchemaVersion    = "provider-refresh-policy/v1alpha1"
	CandidateSchemaVersion = "provider-refresh-candidate/v1alpha1"
	DecisionSchemaVersion  = "provider-refresh-decision/v1alpha1"
	ExecutionSchemaVersion = "provider-refresh-execution/v1alpha1"
	RegistrySchemaVersion  = "provider-refresh-registry/v1alpha1"
	EngineVersion          = "provider-refresh-governance/v0.1.0"
)

type CandidateStatus string

const (
	CandidateReady   CandidateStatus = "ready"
	CandidateBlocked CandidateStatus = "blocked"
)

type ComponentChangeType string

const (
	ChangeAdded     ComponentChangeType = "added"
	ChangeRemoved   ComponentChangeType = "removed"
	ChangeRenamed   ComponentChangeType = "renamed"
	ChangeUnchanged ComponentChangeType = "unchanged"
)

type ImpactStatus string

const (
	ImpactAvailable ImpactStatus = "available"
	ImpactRenamed   ImpactStatus = "renamed"
	ImpactMissing   ImpactStatus = "missing"
)

type DecisionAction string

const (
	DecisionApprove DecisionAction = "approve"
	DecisionReject  DecisionAction = "reject"
)

type ExecutionAction string

const (
	ExecutionPromote  ExecutionAction = "promote"
	ExecutionRollback ExecutionAction = "rollback"
)

type ProviderComponent struct {
	ProviderComponentRef string            `json:"provider_component_ref"`
	ProviderTitle        string            `json:"provider_title,omitempty"`
	CatalogID            string            `json:"catalog_id"`
	CatalogVersion       string            `json:"catalog_version"`
	CatalogChecksum      string            `json:"catalog_checksum"`
	CatalogSchema        string            `json:"catalog_schema"`
	ArtifactURI          string            `json:"artifact_uri"`
	ArtifactSHA256       string            `json:"artifact_sha256"`
	SourceManifestID     string            `json:"source_manifest_id"`
	SourceManifestHash   string            `json:"source_manifest_checksum,omitempty"`
	RecordCount          int               `json:"record_count"`
	ProducerVersion      string            `json:"producer_version"`
	Metadata             map[string]string `json:"metadata,omitempty"`
}

type ProviderInventory struct {
	SchemaVersion     string              `json:"schema_version"`
	ProviderID        string              `json:"provider_id"`
	ProviderVersion   string              `json:"provider_version"`
	GeneratedAt       time.Time           `json:"generated_at"`
	Components        []ProviderComponent `json:"components"`
	InventoryChecksum string              `json:"inventory_checksum"`
}

type RenameDirective struct {
	FromProviderComponentRef string `json:"from_provider_component_ref"`
	ToProviderComponentRef   string `json:"to_provider_component_ref"`
	Reason                   string `json:"reason"`
}

type RefreshPolicy struct {
	SchemaVersion                       string  `json:"schema_version"`
	MaxAddedComponents                  int     `json:"max_added_components"`
	MaxRemovedComponents                int     `json:"max_removed_components"`
	MaxRenamedComponents                int     `json:"max_renamed_components"`
	MaxRecordCountDeltaPercent          float64 `json:"max_record_count_delta_percent"`
	RequireAllMappedComponentsAvailable bool    `json:"require_all_mapped_components_available"`
	RequireTargetComponentAvailable     bool    `json:"require_target_component_available"`
	RequireProviderIDUnchanged          bool    `json:"require_provider_id_unchanged"`
}

type AnalyzeInput struct {
	Namespace         string            `json:"namespace"`
	TargetComponentID string            `json:"target_component_id"`
	Previous          ProviderInventory `json:"previous_inventory"`
	Candidate         ProviderInventory `json:"candidate_inventory"`
	Renames           []RenameDirective `json:"renames,omitempty"`
	Policy            RefreshPolicy     `json:"policy"`
	AnalyzedAt        time.Time         `json:"analyzed_at"`
	AnalyzedBy        string            `json:"analyzed_by"`
	Reason            string            `json:"reason"`
}

type ComponentChange struct {
	ChangeType               ComponentChangeType `json:"change_type"`
	FromProviderComponentRef string              `json:"from_provider_component_ref,omitempty"`
	ToProviderComponentRef   string              `json:"to_provider_component_ref,omitempty"`
	Reason                   string              `json:"reason,omitempty"`
}

type MappingImpact struct {
	ComponentID                   string       `json:"component_id"`
	ComponentKey                  string       `json:"component_key"`
	CurrentVersionID              string       `json:"current_version_id"`
	CurrentProviderComponentRef   string       `json:"current_provider_component_ref"`
	CandidateProviderComponentRef string       `json:"candidate_provider_component_ref,omitempty"`
	Status                        ImpactStatus `json:"status"`
	ActiveMappingCount            int          `json:"active_mapping_count"`
	CurrentRecordCount            int          `json:"current_record_count"`
	CandidateRecordCount          int          `json:"candidate_record_count,omitempty"`
	RecordCountDeltaPercent       float64      `json:"record_count_delta_percent,omitempty"`
	Blockers                      []string     `json:"blockers,omitempty"`
}

type CandidateVersion struct {
	ComponentID              string            `json:"component_id"`
	ExpectedCurrentVersionID string            `json:"expected_current_version_id"`
	CatalogID                string            `json:"catalog_id"`
	CatalogVersion           string            `json:"catalog_version"`
	CatalogChecksum          string            `json:"catalog_checksum"`
	CatalogSchema            string            `json:"catalog_schema"`
	ArtifactURI              string            `json:"artifact_uri"`
	ArtifactSHA256           string            `json:"artifact_sha256"`
	SourceManifestID         string            `json:"source_manifest_id"`
	SourceManifestHash       string            `json:"source_manifest_checksum,omitempty"`
	RecordCount              int               `json:"record_count"`
	ProducerVersion          string            `json:"producer_version"`
	ProviderID               string            `json:"provider_id"`
	ProviderComponentRef     string            `json:"provider_component_ref"`
	ProviderTitle            string            `json:"provider_title,omitempty"`
	ProviderVersion          string            `json:"provider_version"`
	Metadata                 map[string]string `json:"metadata,omitempty"`
}

type RefreshCandidate struct {
	SchemaVersion        string            `json:"schema_version"`
	CandidateID          string            `json:"candidate_id"`
	RegistryID           string            `json:"registry_id"`
	Namespace            string            `json:"namespace"`
	Status               CandidateStatus   `json:"status"`
	TargetComponentID    string            `json:"target_component_id"`
	PreviousInventoryID  string            `json:"previous_inventory_checksum"`
	CandidateInventoryID string            `json:"candidate_inventory_checksum"`
	Policy               RefreshPolicy     `json:"policy"`
	Changes              []ComponentChange `json:"changes"`
	MappingImpacts       []MappingImpact   `json:"mapping_impacts"`
	PolicyViolations     []string          `json:"policy_violations,omitempty"`
	CandidateVersion     CandidateVersion  `json:"candidate_version"`
	AnalyzedAt           time.Time         `json:"analyzed_at"`
	AnalyzedBy           string            `json:"analyzed_by"`
	Reason               string            `json:"reason"`
	CandidateChecksum    string            `json:"candidate_checksum"`
}

type PromotionDecision struct {
	SchemaVersion     string         `json:"schema_version"`
	DecisionID        string         `json:"decision_id"`
	RegistryID        string         `json:"registry_id"`
	Sequence          uint64         `json:"sequence"`
	CandidateID       string         `json:"candidate_id"`
	Action            DecisionAction `json:"action"`
	Reason            string         `json:"reason"`
	DecidedAt         time.Time      `json:"decided_at"`
	DecidedBy         string         `json:"decided_by"`
	PreviousEventHash string         `json:"previous_event_hash"`
	EventHash         string         `json:"event_hash"`
	DecisionChecksum  string         `json:"decision_checksum"`
}

type PromotionExecution struct {
	SchemaVersion       string          `json:"schema_version"`
	ExecutionID         string          `json:"execution_id"`
	RegistryID          string          `json:"registry_id"`
	Sequence            uint64          `json:"sequence"`
	Action              ExecutionAction `json:"action"`
	CandidateID         string          `json:"candidate_id,omitempty"`
	DecisionID          string          `json:"decision_id,omitempty"`
	ComponentID         string          `json:"component_id"`
	PreviousVersionID   string          `json:"previous_version_id"`
	TargetVersionID     string          `json:"target_version_id"`
	CatalogActivationID string          `json:"catalog_activation_id"`
	Reason              string          `json:"reason"`
	ExecutedAt          time.Time       `json:"executed_at"`
	ExecutedBy          string          `json:"executed_by"`
	PreviousEventHash   string          `json:"previous_event_hash"`
	EventHash           string          `json:"event_hash"`
	ExecutionChecksum   string          `json:"execution_checksum"`
}

type Registry struct {
	SchemaVersion    string               `json:"schema_version"`
	RegistryID       string               `json:"registry_id"`
	Namespace        string               `json:"namespace"`
	EngineVersion    string               `json:"engine_version"`
	LastSequence     uint64               `json:"last_sequence"`
	AuditHead        string               `json:"audit_head"`
	Candidates       []RefreshCandidate   `json:"candidates"`
	Decisions        []PromotionDecision  `json:"decisions"`
	Executions       []PromotionExecution `json:"executions"`
	RegistryChecksum string               `json:"registry_checksum"`
}

type DecisionInput struct {
	CandidateID string         `json:"candidate_id"`
	Action      DecisionAction `json:"action"`
	Reason      string         `json:"reason"`
	DecidedAt   time.Time      `json:"decided_at"`
	DecidedBy   string         `json:"decided_by"`
}

type PromoteInput struct {
	CandidateID string    `json:"candidate_id"`
	Reason      string    `json:"reason"`
	ExecutedAt  time.Time `json:"executed_at"`
	ExecutedBy  string    `json:"executed_by"`
}

type RollbackInput struct {
	ComponentID              string    `json:"component_id"`
	TargetVersionID          string    `json:"target_version_id"`
	ExpectedCurrentVersionID string    `json:"expected_current_version_id"`
	Reason                   string    `json:"reason"`
	ExecutedAt               time.Time `json:"executed_at"`
	ExecutedBy               string    `json:"executed_by"`
}
