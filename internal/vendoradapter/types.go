package vendoradapter

import (
	"encoding/json"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertcase"
)

const (
	ProfileSchemaV1  = "openwatchlist.vendor-adapter-profile.v1"
	EnvelopeSchemaV1 = "openwatchlist.vendor-adapter-envelope.v1"
	BatchSchemaV1    = "openwatchlist.vendor-adapter-batch.v1"
	ReceiptSchemaV1  = "openwatchlist.vendor-adapter-receipt.v1"
	AuditSchemaV1    = "openwatchlist.vendor-adapter-audit.v1"
)

type ListResolution struct {
	CanonicalListID string `json:"canonical_list_id"`
	MappingID       string `json:"mapping_id"`
	MappingVersion  string `json:"mapping_version"`
	Status          string `json:"status"`
}

type Profile struct {
	SchemaVersion      string                    `json:"schema_version"`
	AdapterID          string                    `json:"adapter_id"`
	Version            string                    `json:"version"`
	Vendor             string                    `json:"vendor"`
	Description        string                    `json:"description"`
	InputFormat        string                    `json:"input_format"`
	MaxSourceBytes     int64                     `json:"max_source_bytes"`
	RequiredPaths      []string                  `json:"required_paths"`
	Mappings           map[string]string         `json:"mappings"`
	AdditionalEvidence map[string]string         `json:"additional_evidence,omitempty"`
	Constants          map[string]any            `json:"constants,omitempty"`
	ListMappings       map[string]ListResolution `json:"list_mappings"`
	ProfileSHA256      string                    `json:"profile_sha256"`
}

type MappingTrace struct {
	CanonicalField string `json:"canonical_field"`
	SourcePath     string `json:"source_path,omitempty"`
	ValueSHA256    string `json:"value_sha256,omitempty"`
	Status         string `json:"status"`
}

type Envelope struct {
	SchemaVersion      string                       `json:"schema_version"`
	RecordID           string                       `json:"record_id"`
	AdapterID          string                       `json:"adapter_id"`
	AdapterVersion     string                       `json:"adapter_version"`
	Vendor             string                       `json:"vendor"`
	ProfileSHA256      string                       `json:"profile_sha256"`
	SourceRef          string                       `json:"source_ref"`
	SourceSHA256       string                       `json:"source_sha256"`
	MappingTrace       []MappingTrace               `json:"mapping_trace"`
	CreateAlertRequest alertcase.CreateAlertRequest `json:"create_alert_request"`
	ConvertedAt        string                       `json:"converted_at"`
	EnvelopeSHA256     string                       `json:"envelope_sha256"`
}

type BatchInput struct {
	SourceRef string
	Bytes     []byte
}

type BatchItem struct {
	SourceRef    string    `json:"source_ref"`
	SourceSHA256 string    `json:"source_sha256"`
	Status       string    `json:"status"`
	Envelope     *Envelope `json:"envelope,omitempty"`
	ErrorCode    string    `json:"error_code,omitempty"`
	Error        string    `json:"error,omitempty"`
}

type Batch struct {
	SchemaVersion string      `json:"schema_version"`
	AdapterID     string      `json:"adapter_id"`
	ProfileSHA256 string      `json:"profile_sha256"`
	Items         []BatchItem `json:"items"`
	AcceptedCount int         `json:"accepted_count"`
	RejectedCount int         `json:"rejected_count"`
	BatchSHA256   string      `json:"batch_sha256"`
}

type Receipt struct {
	SchemaVersion  string `json:"schema_version"`
	Scope          string `json:"scope"`
	IdempotencyKey string `json:"idempotency_key"`
	SourceSHA256   string `json:"source_sha256"`
	RecordID       string `json:"record_id"`
	CreatedAt      string `json:"created_at"`
}

type AuditEvent struct {
	SchemaVersion       string          `json:"schema_version"`
	StreamID            string          `json:"stream_id"`
	Sequence            uint64          `json:"sequence"`
	PreviousAuditSHA256 string          `json:"previous_audit_sha256"`
	AuditSHA256         string          `json:"audit_sha256"`
	OccurredAt          string          `json:"occurred_at"`
	Action              string          `json:"action"`
	ObjectType          string          `json:"object_type"`
	ObjectID            string          `json:"object_id"`
	Details             json.RawMessage `json:"details,omitempty"`
}

type Status struct {
	Status       string `json:"status"`
	RecordCount  int    `json:"record_count"`
	ReceiptCount int    `json:"receipt_count"`
	AuditCount   int    `json:"audit_count"`
}

type Clock func() time.Time
