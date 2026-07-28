package activationpromotion

import "time"

const (
	IntentSchemaV1     = "openwatchlist.activation-promotion-intent.v1"
	StateSchemaV1      = "openwatchlist.activation-promotion-state.v1"
	AuditEventSchemaV1 = "openwatchlist.activation-promotion-audit-event.v1"
	AuditHeadSchemaV1  = "openwatchlist.activation-promotion-audit-head.v1"
	AckSchemaV1        = "openwatchlist.activation-promotion-ack.v1"
	ShadowSchemaV1     = "openwatchlist.activation-shadow-observation.v1"
	ShadowSummaryV1    = "openwatchlist.activation-shadow-summary.v1"
	PendingSchemaV1    = "openwatchlist.activation-promotion-pending.v1"
	PhasePrepared      = "prepared"
	PhaseValidated     = "validated"
	PhaseCanary        = "canary"
	PhasePromoted      = "promoted"
	PhaseRolledBack    = "rolled_back"
	PhaseBlocked       = "blocked"
	AckReady           = "ready"
	AckNotReady        = "not_ready"
)

type Thresholds struct {
	MaxScoreDelta             int `json:"max_score_delta"`
	MaxTopCandidateChangeBPS  int `json:"max_top_candidate_change_bps"`
	MaxCandidateSetChangeBPS  int `json:"max_candidate_set_change_bps"`
	MaxCoverageLossCount      int `json:"max_coverage_loss_count"`
	MaxAdditionalBlockerCount int `json:"max_additional_blocker_count"`
}

type Intent struct {
	SchemaVersion              string     `json:"schema_version"`
	IntentID                   string     `json:"intent_id"`
	CreatedAt                  string     `json:"created_at"`
	Operator                   string     `json:"operator"`
	Reason                     string     `json:"reason"`
	CurrentActivationID        string     `json:"current_activation_id"`
	CurrentActivationSHA256    string     `json:"current_activation_sha256"`
	CandidateActivationID      string     `json:"candidate_activation_id"`
	CandidateActivationSHA256  string     `json:"candidate_activation_sha256"`
	CanaryBasisPoints          int        `json:"canary_basis_points"`
	CanaryCorrelationAllowlist []string   `json:"canary_correlation_allowlist,omitempty"`
	RequiredReadyAcks          int        `json:"required_ready_acks"`
	Thresholds                 Thresholds `json:"thresholds"`
}

type State struct {
	SchemaVersion         string   `json:"schema_version"`
	IntentID              string   `json:"intent_id"`
	Revision              int64    `json:"revision"`
	Phase                 string   `json:"phase"`
	CurrentActivationID   string   `json:"current_activation_id"`
	CandidateActivationID string   `json:"candidate_activation_id"`
	UpdatedAt             string   `json:"updated_at"`
	LastReportSHA256      string   `json:"last_report_sha256,omitempty"`
	Blockers              []string `json:"blockers,omitempty"`
}

type AuditEvent struct {
	SchemaVersion       string         `json:"schema_version"`
	Sequence            int64          `json:"sequence"`
	Timestamp           string         `json:"timestamp"`
	EventType           string         `json:"event_type"`
	IntentID            string         `json:"intent_id"`
	Revision            int64          `json:"revision"`
	Actor               string         `json:"actor"`
	Reason              string         `json:"reason,omitempty"`
	Payload             map[string]any `json:"payload,omitempty"`
	PreviousEventSHA256 string         `json:"previous_event_sha256,omitempty"`
	EventSHA256         string         `json:"event_sha256"`
}

type AuditHead struct {
	SchemaVersion string `json:"schema_version"`
	Sequence      int64  `json:"sequence"`
	EventSHA256   string `json:"event_sha256"`
}

type Ack struct {
	SchemaVersion string `json:"schema_version"`
	IntentID      string `json:"intent_id"`
	InstanceID    string `json:"instance_id"`
	ActivationID  string `json:"activation_id"`
	Status        string `json:"status"`
	ObservedAt    string `json:"observed_at"`
	TupleSHA256   string `json:"tuple_sha256"`
}

type ShadowObservation struct {
	SchemaVersion           string `json:"schema_version"`
	IntentID                string `json:"intent_id"`
	CorrelationID           string `json:"correlation_id"`
	ObservedAt              string `json:"observed_at"`
	CurrentResponseSHA256   string `json:"current_response_sha256"`
	CandidateResponseSHA256 string `json:"candidate_response_sha256"`
	ScreeningItems          int    `json:"screening_items"`
	CandidateSetChanges     int    `json:"candidate_set_changes"`
	TopCandidateChanges     int    `json:"top_candidate_changes"`
	MaxAbsoluteScoreDelta   int    `json:"max_absolute_score_delta"`
	CoverageLossCount       int    `json:"coverage_loss_count"`
	AdditionalBlockerCount  int    `json:"additional_blocker_count"`
	ObservationSHA256       string `json:"observation_sha256"`
}

type ShadowSummary struct {
	SchemaVersion          string `json:"schema_version"`
	IntentID               string `json:"intent_id"`
	GeneratedAt            string `json:"generated_at"`
	ObservationCount       int    `json:"observation_count"`
	ScreeningItems         int    `json:"screening_items"`
	CandidateSetChanges    int    `json:"candidate_set_changes"`
	TopCandidateChanges    int    `json:"top_candidate_changes"`
	MaxAbsoluteScoreDelta  int    `json:"max_absolute_score_delta"`
	CoverageLossCount      int    `json:"coverage_loss_count"`
	AdditionalBlockerCount int    `json:"additional_blocker_count"`
	CandidateSetChangeBPS  int    `json:"candidate_set_change_bps"`
	TopCandidateChangeBPS  int    `json:"top_candidate_change_bps"`
	SummarySHA256          string `json:"summary_sha256"`
}

type pendingDocument struct {
	SchemaVersion string     `json:"schema_version"`
	State         State      `json:"state"`
	AuditEvent    AuditEvent `json:"audit_event"`
}

type Status struct {
	Intent        Intent    `json:"intent"`
	State         State     `json:"state"`
	ReadyAckCount int       `json:"ready_ack_count"`
	AuditHead     AuditHead `json:"audit_head"`
}

type clock func() time.Time
