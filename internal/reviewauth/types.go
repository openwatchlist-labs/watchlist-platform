package reviewauth

import "encoding/json"

const (
	RegistrySchemaV1      = "openwatchlist.identity-role-registry.v1"
	ClaimsSchemaV1        = "openwatchlist.access-token-claims.v1"
	SecurityAuditSchemaV1 = "openwatchlist.security-audit.v1"
)

type Role struct {
	RoleID      string   `json:"role_id"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions"`
}
type RoleBinding struct {
	TenantID string   `json:"tenant_id"`
	Roles    []string `json:"roles"`
}
type User struct {
	UserID       string        `json:"user_id"`
	DisplayName  string        `json:"display_name"`
	Active       bool          `json:"active"`
	SessionEpoch uint64        `json:"session_epoch"`
	Bindings     []RoleBinding `json:"bindings"`
}
type Registry struct {
	SchemaVersion  string `json:"schema_version"`
	RegistryID     string `json:"registry_id"`
	Version        string `json:"version"`
	Roles          []Role `json:"roles"`
	Users          []User `json:"users"`
	RegistrySHA256 string `json:"registry_sha256"`

	// userIndex/roleIndex are a build-once cache mapping UserID/RoleID to
	// their position in Users/Roles, for O(1) User()/Role() lookups.
	// Unexported, so encoding/json ignores them entirely on both marshal
	// and unmarshal -- they never affect the registry's JSON shape or its
	// checksum. See buildIndex in registry.go.
	userIndex map[string]int
	roleIndex map[string]int
}
type Claims struct {
	SchemaVersion  string   `json:"schema_version"`
	TokenID        string   `json:"token_id"`
	Subject        string   `json:"sub"`
	DisplayName    string   `json:"display_name"`
	TenantID       string   `json:"tenant_id"`
	Roles          []string `json:"roles"`
	IssuedAt       string   `json:"issued_at"`
	ExpiresAt      string   `json:"expires_at"`
	RegistrySHA256 string   `json:"registry_sha256"`
	SessionEpoch   uint64   `json:"session_epoch"`
}
type SecurityAuditEvent struct {
	SchemaVersion       string          `json:"schema_version"`
	StreamID            string          `json:"stream_id"`
	Sequence            uint64          `json:"sequence"`
	PreviousEventSHA256 string          `json:"previous_event_sha256"`
	EventSHA256         string          `json:"event_sha256"`
	OccurredAt          string          `json:"occurred_at"`
	RequestID           string          `json:"request_id"`
	TokenIDHash         string          `json:"token_id_hash,omitempty"`
	Subject             string          `json:"subject,omitempty"`
	TenantID            string          `json:"tenant_id,omitempty"`
	Permission          string          `json:"permission,omitempty"`
	Method              string          `json:"method"`
	Path                string          `json:"path"`
	ResourceType        string          `json:"resource_type,omitempty"`
	ResourceID          string          `json:"resource_id,omitempty"`
	Outcome             string          `json:"outcome"`
	StatusCode          int             `json:"status_code"`
	Detail              json.RawMessage `json:"detail,omitempty"`
}
type AuditStatus struct {
	Status     string `json:"status"`
	EventCount int    `json:"event_count"`
	HeadSHA256 string `json:"head_sha256,omitempty"`
}
