package screeningapi

import (
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertlistmapping"
)

const (
	ConfigSchemaVersion        = "screening-api-config/v1alpha1"
	RequestSchemaVersion       = "screening-request/v1alpha1"
	BatchRequestSchemaVersion  = "screening-batch-request/v1alpha1"
	ResponseSchemaVersion      = "screening-response/v1alpha1"
	BatchResponseSchemaVersion = "screening-batch-response/v1alpha1"
	RuntimeLineageSchema       = "screening-runtime-lineage/v1alpha1"
	ProblemSchemaVersion       = "screening-api-problem/v1alpha1"
	IdempotencySchemaVersion   = "screening-idempotency-record/v1alpha1"
	APIVersion                 = "screening-api/v0.1.0"
)

type RuntimeBinding struct {
	ComponentID   string `json:"component_id"`
	VersionID     string `json:"version_id"`
	PackagePath   string `json:"package_path"`
	PackageSHA256 string `json:"package_sha256"`
	WorkerCount   int    `json:"worker_count,omitempty"`
}

type Config struct {
	SchemaVersion       string           `json:"schema_version"`
	ListenAddress       string           `json:"listen_address"`
	CatalogRegistryPath string           `json:"catalog_registry_path"`
	MappingRegistryPath string           `json:"mapping_registry_path"`
	RuntimeBinaryPath   string           `json:"runtime_binary_path"`
	IdempotencyRoot     string           `json:"idempotency_root"`
	RuntimeBindings     []RuntimeBinding `json:"runtime_bindings"`
	MaxBodyBytes        int64            `json:"max_body_bytes"`
	MaxBatchItems       int              `json:"max_batch_items"`
	MaxCandidates       int              `json:"max_candidates"`
	RequestTimeoutMS    int              `json:"request_timeout_ms"`
}

type QueryKind string

const (
	QueryName       QueryKind = "name"
	QueryIdentifier QueryKind = "identifier"
	QueryRecordID   QueryKind = "record_id"
)

type Query struct {
	Kind              QueryKind `json:"kind"`
	Value             string    `json:"value"`
	IdentifierType    string    `json:"identifier_type,omitempty"`
	Prefix            bool      `json:"prefix,omitempty"`
	TargetEntityTypes []string  `json:"target_entity_types,omitempty"`
	Limit             int       `json:"limit,omitempty"`
}

type ScreeningRequest struct {
	SchemaVersion  string    `json:"schema_version"`
	RequestID      string    `json:"request_id"`
	SourceSystemID string    `json:"source_system_id"`
	RawListName    string    `json:"raw_list_name"`
	EffectiveAt    time.Time `json:"effective_at"`
	Query          Query     `json:"query"`
}

type BatchRequest struct {
	SchemaVersion string             `json:"schema_version"`
	Requests      []ScreeningRequest `json:"requests"`
}

type Candidate struct {
	CandidateID     string `json:"candidate_id"`
	RecordID        string `json:"record_id"`
	EntityType      string `json:"entity_type"`
	PrimaryName     string `json:"primary_name"`
	MatchKind       string `json:"match_kind"`
	MatchedValue    string `json:"matched_value"`
	NormalizedQuery string `json:"normalized_query"`
}

type RuntimeLineage struct {
	SchemaVersion       string `json:"schema_version"`
	ClientVersion       string `json:"client_version"`
	WorkerProtocol      string `json:"worker_protocol"`
	ComponentID         string `json:"component_id"`
	CatalogVersionID    string `json:"catalog_version_id"`
	CatalogActivationID string `json:"catalog_activation_id"`
	CatalogEpoch        uint64 `json:"catalog_epoch"`
	CatalogID           string `json:"catalog_id"`
	CatalogVersion      string `json:"catalog_version"`
	CatalogChecksum     string `json:"catalog_checksum"`
	CatalogMode         string `json:"catalog_mode"`
	PackageSHA256       string `json:"package_sha256"`
	RuntimeRecordCount  uint64 `json:"runtime_record_count"`
}

type ScreeningStatus string

const (
	StatusMatched      ScreeningStatus = "matched"
	StatusNoCandidates ScreeningStatus = "no_candidates"
	StatusBlocked      ScreeningStatus = "blocked"
)

type ScreeningResponse struct {
	SchemaVersion  string                      `json:"schema_version"`
	APIVersion     string                      `json:"api_version"`
	ScreeningID    string                      `json:"screening_id"`
	CorrelationID  string                      `json:"correlation_id"`
	IdempotencyKey string                      `json:"idempotency_key"`
	ProcessedAt    time.Time                   `json:"processed_at"`
	Status         ScreeningStatus             `json:"status"`
	Request        ScreeningRequest            `json:"request"`
	ListResolution alertlistmapping.Resolution `json:"list_resolution"`
	Runtime        *RuntimeLineage             `json:"runtime,omitempty"`
	CandidateCount int                         `json:"candidate_count"`
	Candidates     []Candidate                 `json:"candidates"`
	ReviewBlockers []string                    `json:"review_blockers,omitempty"`
}

type BatchSummary struct {
	Total        int `json:"total"`
	Matched      int `json:"matched"`
	NoCandidates int `json:"no_candidates"`
	Blocked      int `json:"blocked"`
	Candidates   int `json:"candidates"`
}

type BatchResponse struct {
	SchemaVersion  string              `json:"schema_version"`
	APIVersion     string              `json:"api_version"`
	BatchID        string              `json:"batch_id"`
	CorrelationID  string              `json:"correlation_id"`
	IdempotencyKey string              `json:"idempotency_key"`
	ProcessedAt    time.Time           `json:"processed_at"`
	FailurePolicy  string              `json:"failure_policy"`
	Summary        BatchSummary        `json:"summary"`
	Results        []ScreeningResponse `json:"results"`
}

type Problem struct {
	SchemaVersion string `json:"schema_version"`
	Type          string `json:"type"`
	Title         string `json:"title"`
	Status        int    `json:"status"`
	Code          string `json:"code"`
	Detail        string `json:"detail"`
	CorrelationID string `json:"correlation_id,omitempty"`
}

type idempotencyRecord struct {
	SchemaVersion string    `json:"schema_version"`
	Endpoint      string    `json:"endpoint"`
	Key           string    `json:"key"`
	RequestSHA256 string    `json:"request_sha256"`
	StatusCode    int       `json:"status_code"`
	CorrelationID string    `json:"correlation_id"`
	Response      []byte    `json:"response_bytes"`
	CreatedAt     time.Time `json:"created_at"`
}
