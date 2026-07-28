package productionops

import "encoding/json"

const (
	ConfigSchemaV1         = "openwatchlist.production-runtime-config.v1"
	QuotaSchemaV1          = "openwatchlist.tenant-quota-registry.v1"
	OutboxMessageSchemaV1  = "openwatchlist.operational-outbox-message.v1"
	OutboxEventSchemaV1    = "openwatchlist.operational-outbox-event.v1"
	BackupManifestSchemaV1 = "openwatchlist.operational-backup-manifest.v1"
)

type TLSConfig struct {
	Required             bool   `json:"required"`
	TrustedProxy         bool   `json:"trusted_proxy"`
	ForwardedProtoHeader string `json:"forwarded_proto_header"`
}

type ReadinessConfig struct {
	RequiredPaths      []string `json:"required_paths"`
	MinFreeBytes       uint64   `json:"min_free_bytes"`
	PostgreSQLRequired bool     `json:"postgresql_required"`
	PostgreSQLDSNEnv   string   `json:"postgresql_dsn_env"`
	PSQLPath           string   `json:"psql_path"`
	VerifyOutbox       bool     `json:"verify_outbox"`
}

type RuntimeConfig struct {
	SchemaVersion            string          `json:"schema_version"`
	ConfigID                 string          `json:"config_id"`
	Version                  string          `json:"version"`
	Environment              string          `json:"environment"`
	ListenAddress            string          `json:"listen_address"`
	ReviewConsoleConfigPath  string          `json:"review_console_config_path"`
	SigningKeyEnv            string          `json:"signing_key_env,omitempty"`
	QuotaRegistryPath        string          `json:"quota_registry_path"`
	RuntimeStateDirectory    string          `json:"runtime_state_directory"`
	OutboxDirectory          string          `json:"outbox_directory"`
	BackupDirectory          string          `json:"backup_directory"`
	ShutdownGraceSeconds     int             `json:"shutdown_grace_seconds"`
	RequestTimeoutSeconds    int             `json:"request_timeout_seconds"`
	ReadHeaderTimeoutSeconds int             `json:"read_header_timeout_seconds"`
	ReadTimeoutSeconds       int             `json:"read_timeout_seconds"`
	WriteTimeoutSeconds      int             `json:"write_timeout_seconds"`
	IdleTimeoutSeconds       int             `json:"idle_timeout_seconds"`
	MaxHeaderBytes           int             `json:"max_header_bytes"`
	MaxBodyBytes             int64           `json:"max_body_bytes"`
	GlobalConcurrency        int             `json:"global_concurrency"`
	DefaultTenantConcurrency int             `json:"default_tenant_concurrency"`
	DefaultRequestsPerMinute int             `json:"default_requests_per_minute"`
	DefaultBurst             int             `json:"default_burst"`
	TLS                      TLSConfig       `json:"tls"`
	Readiness                ReadinessConfig `json:"readiness"`
	ConfigSHA256             string          `json:"config_sha256"`
}

type TenantQuota struct {
	TenantID          string `json:"tenant_id"`
	RequestsPerMinute int    `json:"requests_per_minute"`
	Burst             int    `json:"burst"`
	MaxConcurrent     int    `json:"max_concurrent"`
	MaxBodyBytes      int64  `json:"max_body_bytes"`
}

type QuotaRegistry struct {
	SchemaVersion  string        `json:"schema_version"`
	RegistryID     string        `json:"registry_id"`
	Version        string        `json:"version"`
	Default        TenantQuota   `json:"default"`
	Tenants        []TenantQuota `json:"tenants"`
	RegistrySHA256 string        `json:"registry_sha256"`
}

type OutboxMessage struct {
	SchemaVersion  string          `json:"schema_version"`
	MessageID      string          `json:"message_id"`
	Topic          string          `json:"topic"`
	TenantID       string          `json:"tenant_id"`
	IdempotencyKey string          `json:"idempotency_key"`
	PayloadSHA256  string          `json:"payload_sha256"`
	Payload        json.RawMessage `json:"payload"`
	MaxAttempts    int             `json:"max_attempts"`
	CreatedAt      string          `json:"created_at"`
	MessageSHA256  string          `json:"message_sha256"`
}

type OutboxEvent struct {
	SchemaVersion       string `json:"schema_version"`
	StreamID            string `json:"stream_id"`
	Sequence            uint64 `json:"sequence"`
	PreviousEventSHA256 string `json:"previous_event_sha256"`
	EventSHA256         string `json:"event_sha256"`
	OccurredAt          string `json:"occurred_at"`
	MessageID           string `json:"message_id"`
	Action              string `json:"action"`
	Attempt             int    `json:"attempt"`
	LeaseTokenHash      string `json:"lease_token_hash,omitempty"`
	LeaseExpiresAt      string `json:"lease_expires_at,omitempty"`
	NextAttemptAt       string `json:"next_attempt_at,omitempty"`
	Detail              string `json:"detail,omitempty"`
}

type OutboxReceipt struct {
	Scope          string `json:"scope"`
	IdempotencyKey string `json:"idempotency_key"`
	RequestSHA256  string `json:"request_sha256"`
	MessageID      string `json:"message_id"`
	CreatedAt      string `json:"created_at"`
}

type OutboxProjection struct {
	Message         OutboxMessage `json:"message"`
	State           string        `json:"state"`
	Attempt         int           `json:"attempt"`
	LeaseExpiresAt  string        `json:"lease_expires_at,omitempty"`
	NextAttemptAt   string        `json:"next_attempt_at,omitempty"`
	LastEventSHA256 string        `json:"last_event_sha256"`
}

type OutboxStatus struct {
	Status         string `json:"status"`
	MessageCount   int    `json:"message_count"`
	EventCount     int    `json:"event_count"`
	PendingCount   int    `json:"pending_count"`
	LeasedCount    int    `json:"leased_count"`
	CompletedCount int    `json:"completed_count"`
	DeadCount      int    `json:"dead_count"`
}

type BackupRoot struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type BackupEntry struct {
	Root   string `json:"root"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
}

type BackupManifest struct {
	SchemaVersion string        `json:"schema_version"`
	BackupID      string        `json:"backup_id"`
	CreatedAt     string        `json:"created_at"`
	Entries       []BackupEntry `json:"entries"`
	EntryCount    int           `json:"entry_count"`
	TotalBytes    int64         `json:"total_bytes"`
	ContentSHA256 string        `json:"content_sha256"`
}
