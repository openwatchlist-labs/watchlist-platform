package catalogrefresh

import (
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacsource"
)

const (
	DeltaSchemaVersion    = "ofac-catalog-delta/v1alpha1"
	DiffSchemaVersion     = "catalog-diff-report/v1alpha1"
	PolicySchemaVersion   = "catalog-promotion-policy/v1alpha1"
	DecisionSchemaVersion = "catalog-promotion-decision/v1alpha1"
	ReplaySchemaVersion   = "catalog-refresh-replay/v1alpha1"
	EngineVersion         = "catalog-refresh-engine/v0.1.0"
)

type OperationType string

const (
	OperationAdd     OperationType = "add"
	OperationReplace OperationType = "replace"
	OperationRemove  OperationType = "remove"
)

type CatalogRef struct {
	CatalogID       string `json:"catalog_id"`
	CatalogVersion  string `json:"catalog_version"`
	CatalogChecksum string `json:"catalog_checksum"`
	RecordCount     int    `json:"record_count"`
}

type DeltaOperation struct {
	Operation          OperationType                 `json:"operation"`
	ProviderRecordID   string                        `json:"provider_record_id"`
	BeforeRecordSHA256 string                        `json:"before_record_sha256,omitempty"`
	After              *ofaccatalog.DirectListRecord `json:"after,omitempty"`
}

type Delta struct {
	SchemaVersion        string                    `json:"schema_version"`
	DeltaID              string                    `json:"delta_id"`
	Sequence             uint64                    `json:"sequence"`
	Base                 CatalogRef                `json:"base"`
	Target               CatalogRef                `json:"target"`
	TargetSourceManifest ofacsource.SourceManifest `json:"target_source_manifest"`
	GeneratedAt          time.Time                 `json:"generated_at"`
	Operations           []DeltaOperation          `json:"operations"`
	DeltaChecksum        string                    `json:"delta_checksum"`
}

type NamedCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type DiffReport struct {
	SchemaVersion            string       `json:"schema_version"`
	ReportID                 string       `json:"report_id"`
	Base                     CatalogRef   `json:"base"`
	Target                   CatalogRef   `json:"target"`
	Added                    int          `json:"added"`
	Modified                 int          `json:"modified"`
	Removed                  int          `json:"removed"`
	Unchanged                int          `json:"unchanged"`
	TotalChanges             int          `json:"total_changes"`
	ChangeRatioBasisPoints   int          `json:"change_ratio_basis_points"`
	DeletionRatioBasisPoints int          `json:"deletion_ratio_basis_points"`
	AddedRecordIDs           []string     `json:"added_record_ids,omitempty"`
	ModifiedRecordIDs        []string     `json:"modified_record_ids,omitempty"`
	RemovedRecordIDs         []string     `json:"removed_record_ids,omitempty"`
	ModifiedFieldCounts      []NamedCount `json:"modified_field_counts,omitempty"`
}

type PromotionPolicy struct {
	SchemaVersion                   string `json:"schema_version"`
	PolicyID                        string `json:"policy_id"`
	PolicyVersion                   string `json:"policy_version"`
	MaxChangeRatioBasisPoints       int    `json:"max_change_ratio_basis_points"`
	MaxDeletionRatioBasisPoints     int    `json:"max_deletion_ratio_basis_points"`
	MaxOperations                   int    `json:"max_operations"`
	ForceFullAtOrAboveThreshold     bool   `json:"force_full_at_or_above_threshold"`
	RequireContiguousSequence       bool   `json:"require_contiguous_sequence"`
	RequireBaseChecksumMatch        bool   `json:"require_base_checksum_match"`
	RequireTargetChecksumMatch      bool   `json:"require_target_checksum_match"`
	FullRebuildVerificationInterval uint64 `json:"full_rebuild_verification_interval"`
}

type PromotionOutcome string

const (
	OutcomePromoteDelta PromotionOutcome = "promote_delta"
	OutcomeForceFull    PromotionOutcome = "force_full_rebuild"
	OutcomeReject       PromotionOutcome = "reject"
)

type DecisionReason struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

type PromotionDecision struct {
	SchemaVersion                string           `json:"schema_version"`
	DecisionID                   string           `json:"decision_id"`
	EngineVersion                string           `json:"engine_version"`
	Outcome                      PromotionOutcome `json:"outcome"`
	Policy                       PromotionPolicy  `json:"policy"`
	DeltaID                      string           `json:"delta_id"`
	Sequence                     uint64           `json:"sequence"`
	ExpectedSequence             uint64           `json:"expected_sequence"`
	Base                         CatalogRef       `json:"base"`
	Target                       CatalogRef       `json:"target"`
	Diff                         *DiffReport      `json:"diff,omitempty"`
	Reasons                      []DecisionReason `json:"reasons"`
	ReconstructedCatalogChecksum string           `json:"reconstructed_catalog_checksum,omitempty"`
	FullRebuildVerified          bool             `json:"full_rebuild_verified"`
	EvaluatedAt                  time.Time        `json:"evaluated_at"`
}

type Replay struct {
	SchemaVersion         string            `json:"schema_version"`
	EngineVersion         string            `json:"engine_version"`
	Policy                PromotionPolicy   `json:"policy"`
	Base                  CatalogRef        `json:"base"`
	SmallDelta            Delta             `json:"small_delta"`
	SmallDecision         PromotionDecision `json:"small_decision"`
	ThresholdDelta        Delta             `json:"threshold_delta"`
	ThresholdDecision     PromotionDecision `json:"threshold_decision"`
	LargeDelta            Delta             `json:"large_delta"`
	LargeDecision         PromotionDecision `json:"large_decision"`
	SequenceGapDecision   PromotionDecision `json:"sequence_gap_decision"`
	AcceptedTarget        CatalogRef        `json:"accepted_target"`
	AcceptedPackageID     string            `json:"accepted_package_id"`
	AcceptedPackageSHA256 string            `json:"accepted_package_checksum"`
}
