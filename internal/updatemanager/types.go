package updatemanager

import (
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogrefresh"
	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogruntime"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacruntime"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacsource"
)

const (
	UpdateSpecSchemaVersion       = "watchlist-update-spec/v1alpha1"
	UpdateRecordSchemaVersion     = "watchlist-update-record/v1alpha1"
	WorkerDescriptorSchemaVersion = "screening-worker-descriptor/v1alpha1"
	WorkerReadinessSchemaVersion  = "worker-readiness-ack/v1alpha1"
	WorkerActivationSchemaVersion = "worker-activation-ack/v1alpha1"
	FleetActivationSchemaVersion  = "fleet-activation-record/v1alpha1"
	FleetRollbackSchemaVersion    = "fleet-rollback-record/v1alpha1"
	FleetPointerSchemaVersion     = "fleet-active-pointer/v1alpha1"
	AuditEventSchemaVersion       = "update-audit-event/v1alpha1"
	AuditHistorySchemaVersion     = "update-audit-history/v1alpha1"
	ManagerVersion                = "watchlist-update-manager/v0.1.0"
)

type UpdateStatus string

const (
	StatusScheduled           UpdateStatus = "scheduled"
	StatusStaged              UpdateStatus = "staged"
	StatusCompiled            UpdateStatus = "compiled"
	StatusReady               UpdateStatus = "ready"
	StatusActive              UpdateStatus = "active"
	StatusFailed              UpdateStatus = "failed"
	StatusRolledBack          UpdateStatus = "rolled_back"
	StatusFullRebuildRequired UpdateStatus = "full_rebuild_required"
)

type RolloutPhase string

const (
	PhaseCanary   RolloutPhase = "canary"
	PhaseBroad    RolloutPhase = "broad"
	PhaseRollback RolloutPhase = "rollback"
)

type AckStatus string

const (
	AckPass AckStatus = "pass"
	AckFail AckStatus = "fail"
)

type UpdateSpec struct {
	SchemaVersion   string    `json:"schema_version"`
	UpdateID        string    `json:"update_id"`
	SourcePath      string    `json:"source_path,omitempty"`
	SourceURL       string    `json:"source_url"`
	ScheduledFor    time.Time `json:"scheduled_for"`
	RequestedAt     time.Time `json:"requested_at"`
	CanaryWorkers   []string  `json:"canary_workers"`
	RequiredWorkers []string  `json:"required_workers"`
}

type StagedArtifacts struct {
	Promotion         *catalogrefresh.PromotionDecision `json:"promotion,omitempty"`
	DeltaPath         string                            `json:"delta_path,omitempty"`
	SourceManifest    ofacsource.SourceManifest         `json:"source_manifest"`
	PackageInfo       ofacruntime.PackageInfo           `json:"package_info"`
	PackagePath       string                            `json:"package_path"`
	SourceArchivePath string                            `json:"source_archive_path"`
	CompiledAt        time.Time                         `json:"compiled_at"`
}

type UpdateRecord struct {
	SchemaVersion  string           `json:"schema_version"`
	UpdateID       string           `json:"update_id"`
	ManagerVersion string           `json:"manager_version"`
	Status         UpdateStatus     `json:"status"`
	Spec           UpdateSpec       `json:"spec"`
	Staged         *StagedArtifacts `json:"staged,omitempty"`
	Failure        string           `json:"failure,omitempty"`
	UpdatedAt      time.Time        `json:"updated_at"`
}

type WorkerDescriptor struct {
	SchemaVersion string `json:"schema_version"`
	WorkerID      string `json:"worker_id"`
	Zone          string `json:"zone"`
	Required      bool   `json:"required"`
}

type WorkerReadinessAck struct {
	SchemaVersion   string                          `json:"schema_version"`
	AckID           string                          `json:"ack_id"`
	UpdateID        string                          `json:"update_id"`
	Worker          WorkerDescriptor                `json:"worker"`
	PackageID       string                          `json:"package_id"`
	PackageChecksum string                          `json:"package_checksum"`
	CheckedAt       time.Time                       `json:"checked_at"`
	Ready           bool                            `json:"ready"`
	Checks          []catalogruntime.ReadinessCheck `json:"checks"`
}

type ActivationCommand struct {
	UpdateID    string
	FleetEpoch  uint64
	Phase       RolloutPhase
	PackageData []byte
	PackageInfo ofacruntime.PackageInfo
	CompiledAt  time.Time
	ActivatedAt time.Time
}

type WorkerActivationAck struct {
	SchemaVersion string                         `json:"schema_version"`
	AckID         string                         `json:"ack_id"`
	UpdateID      string                         `json:"update_id"`
	Worker        WorkerDescriptor               `json:"worker"`
	FleetEpoch    uint64                         `json:"fleet_epoch"`
	Phase         RolloutPhase                   `json:"phase"`
	Status        AckStatus                      `json:"status"`
	ProbePassed   bool                           `json:"probe_passed"`
	Detail        string                         `json:"detail"`
	Generation    catalogruntime.GenerationStamp `json:"generation"`
	ActivatedAt   time.Time                      `json:"activated_at"`
}

type FleetActivationState string

const (
	FleetActivationComplete FleetActivationState = "complete"
	FleetActivationFailed   FleetActivationState = "failed"
)

type FleetActivationRecord struct {
	SchemaVersion   string                  `json:"schema_version"`
	ActivationID    string                  `json:"activation_id"`
	UpdateID        string                  `json:"update_id"`
	FleetEpoch      uint64                  `json:"fleet_epoch"`
	State           FleetActivationState    `json:"state"`
	PackageInfo     ofacruntime.PackageInfo `json:"package_info"`
	CanaryWorkers   []string                `json:"canary_workers"`
	RequiredWorkers []string                `json:"required_workers"`
	ReadinessAcks   []WorkerReadinessAck    `json:"readiness_acks"`
	ActivationAcks  []WorkerActivationAck   `json:"activation_acks"`
	Previous        *FleetPointer           `json:"previous,omitempty"`
	StartedAt       time.Time               `json:"started_at"`
	CompletedAt     time.Time               `json:"completed_at"`
	Failure         string                  `json:"failure,omitempty"`
}

type FleetRollbackRecord struct {
	SchemaVersion    string                `json:"schema_version"`
	RollbackID       string                `json:"rollback_id"`
	FromActivationID string                `json:"from_activation_id"`
	ToPackageID      string                `json:"to_package_id"`
	Reason           string                `json:"reason"`
	FleetEpoch       uint64                `json:"fleet_epoch"`
	ActivationAcks   []WorkerActivationAck `json:"activation_acks"`
	RequestedAt      time.Time             `json:"requested_at"`
	CompletedAt      time.Time             `json:"completed_at"`
}

type FleetPointer struct {
	SchemaVersion    string    `json:"schema_version"`
	ActivationID     string    `json:"activation_id"`
	UpdateID         string    `json:"update_id"`
	FleetEpoch       uint64    `json:"fleet_epoch"`
	PackageID        string    `json:"package_id"`
	PackageChecksum  string    `json:"package_checksum"`
	CatalogID        string    `json:"catalog_id"`
	CatalogVersion   string    `json:"catalog_version"`
	CatalogChecksum  string    `json:"catalog_checksum"`
	SourceManifestID string    `json:"source_manifest_id"`
	ActivatedAt      time.Time `json:"activated_at"`
}

type AuditEvent struct {
	SchemaVersion string    `json:"schema_version"`
	Sequence      uint64    `json:"sequence"`
	EventID       string    `json:"event_id"`
	PreviousHash  string    `json:"previous_hash"`
	EventHash     string    `json:"event_hash"`
	EventType     string    `json:"event_type"`
	SubjectID     string    `json:"subject_id"`
	OccurredAt    time.Time `json:"occurred_at"`
	PayloadSHA256 string    `json:"payload_sha256"`
}

type AuditHistory struct {
	SchemaVersion string       `json:"schema_version"`
	HeadHash      string       `json:"head_hash"`
	Events        []AuditEvent `json:"events"`
}

type RunResult struct {
	Update     UpdateRecord          `json:"update"`
	Activation FleetActivationRecord `json:"activation"`
	Audit      AuditHistory          `json:"audit"`
}
