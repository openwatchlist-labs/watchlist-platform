package screeningledger

import "encoding/json"

const (
	EventSchemaV1    = "openwatchlist.screening-ledger-event.v1"
	SnapshotSchemaV1 = "openwatchlist.screening-ledger-snapshot.v1"
	HeadSchemaV1     = "openwatchlist.screening-ledger-head.v1"
	AuditSchemaV1    = "openwatchlist.screening-ledger-audit.v1"
	BundleSchemaV1   = "openwatchlist.screening-audit-bundle.v1"
)

type RetentionPolicy struct {
	Class            string   `json:"class"`
	RetentionDays    int      `json:"retention_days"`
	RedactKeys       []string `json:"redact_keys"`
	HashKeys         []string `json:"hash_keys"`
	MaxSnapshotBytes int      `json:"max_snapshot_bytes"`
}
type AppendInput struct {
	Route          string
	HTTPStatus     int
	CorrelationID  string
	IdempotencyKey string
	RequestBytes   []byte
	ResponseBytes  []byte
	OccurredAt     string
	Retention      RetentionPolicy
}
type Event struct {
	SchemaVersion          string          `json:"schema_version"`
	EventID                string          `json:"event_id"`
	LedgerID               string          `json:"ledger_id"`
	Sequence               uint64          `json:"sequence"`
	PreviousEventSHA256    string          `json:"previous_event_sha256"`
	EventSHA256            string          `json:"event_sha256"`
	OccurredAt             string          `json:"occurred_at"`
	Route                  string          `json:"route"`
	HTTPStatus             int             `json:"http_status"`
	CorrelationIDHash      string          `json:"correlation_id_hash"`
	IdempotencyKeyHash     string          `json:"idempotency_key_hash,omitempty"`
	RequestSHA256          string          `json:"request_sha256"`
	ResponseSHA256         string          `json:"response_sha256"`
	RequestSnapshotSHA256  string          `json:"request_snapshot_sha256"`
	ResponseSnapshotSHA256 string          `json:"response_snapshot_sha256"`
	ActivationLineage      json.RawMessage `json:"activation_lineage,omitempty"`
	PromotionLineage       json.RawMessage `json:"promotion_lineage,omitempty"`
	CandidateSummary       json.RawMessage `json:"candidate_summary,omitempty"`
	RetentionClass         string          `json:"retention_class"`
	ExpiresAt              string          `json:"expires_at"`
}
type SnapshotEnvelope struct {
	SchemaVersion    string `json:"schema_version"`
	SnapshotSHA256   string `json:"snapshot_sha256"`
	PlaintextSHA256  string `json:"plaintext_sha256"`
	Kind             string `json:"kind"`
	Cipher           string `json:"cipher"`
	NonceBase64      string `json:"nonce_base64"`
	CiphertextBase64 string `json:"ciphertext_base64,omitempty"`
	AAD              string `json:"aad"`
	PlaintextBytes   int    `json:"plaintext_bytes"`
	CreatedAt        string `json:"created_at"`
	ExpiresAt        string `json:"expires_at"`
	RetentionClass   string `json:"retention_class"`
	PurgedAt         string `json:"purged_at,omitempty"`
	PurgeReason      string `json:"purge_reason,omitempty"`
}
type Head struct {
	SchemaVersion string `json:"schema_version"`
	LedgerID      string `json:"ledger_id"`
	Sequence      uint64 `json:"sequence"`
	EventID       string `json:"event_id"`
	EventSHA256   string `json:"event_sha256"`
}
type AppendResult struct {
	Event    Event `json:"event"`
	Replayed bool  `json:"replayed"`
}
type AuditEvent struct {
	SchemaVersion       string          `json:"schema_version"`
	LedgerID            string          `json:"ledger_id"`
	Sequence            uint64          `json:"sequence"`
	PreviousAuditSHA256 string          `json:"previous_audit_sha256"`
	AuditSHA256         string          `json:"audit_sha256"`
	OccurredAt          string          `json:"occurred_at"`
	Action              string          `json:"action"`
	Operator            string          `json:"operator,omitempty"`
	Reason              string          `json:"reason,omitempty"`
	EventID             string          `json:"event_id,omitempty"`
	Details             json.RawMessage `json:"details,omitempty"`
}
type ReplayReport struct {
	SchemaVersion          string          `json:"schema_version"`
	EventID                string          `json:"event_id"`
	Classification         string          `json:"classification"`
	OriginalResponseSHA256 string          `json:"original_response_sha256"`
	ReplayResponseSHA256   string          `json:"replay_response_sha256,omitempty"`
	HTTPStatus             int             `json:"http_status,omitempty"`
	CandidateDelta         json.RawMessage `json:"candidate_delta,omitempty"`
	Error                  string          `json:"error,omitempty"`
}
type BundleManifest struct {
	SchemaVersion string            `json:"schema_version"`
	EventID       string            `json:"event_id"`
	Mode          string            `json:"mode"`
	CreatedAt     string            `json:"created_at"`
	Files         map[string]string `json:"files"`
	BundleSHA256  string            `json:"bundle_sha256"`
}
