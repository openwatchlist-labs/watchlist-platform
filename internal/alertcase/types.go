package alertcase

import "encoding/json"

const (
	AlertSchemaV1          = "openwatchlist.alert-record.v1"
	CaseEventSchemaV1      = "openwatchlist.case-event.v1"
	CaseHeadSchemaV1       = "openwatchlist.case-head.v1"
	CaseProjectionSchemaV1 = "openwatchlist.case-projection.v1"
	AuditSchemaV1          = "openwatchlist.alert-case-audit.v1"
	PolicySchemaV1         = "openwatchlist.alert-policy.v1"
	ExternalAlertSchemaV1  = "openwatchlist.external-alert.v1"
)

type CandidateSummary struct {
	CandidateID string   `json:"candidate_id"`
	Score       int      `json:"score"`
	Band        string   `json:"band,omitempty"`
	ReasonCodes []string `json:"reason_codes,omitempty"`
}

type ScreeningLineage struct {
	LedgerID               string          `json:"ledger_id"`
	EventID                string          `json:"event_id"`
	EventSHA256            string          `json:"event_sha256"`
	RequestSHA256          string          `json:"request_sha256"`
	ResponseSHA256         string          `json:"response_sha256"`
	RequestSnapshotSHA256  string          `json:"request_snapshot_sha256"`
	ResponseSnapshotSHA256 string          `json:"response_snapshot_sha256"`
	ActivationLineage      json.RawMessage `json:"activation_lineage,omitempty"`
	PromotionLineage       json.RawMessage `json:"promotion_lineage,omitempty"`
}

type ExternalAlert struct {
	SchemaVersion        string            `json:"schema_version"`
	SourceSystemID       string            `json:"source_system_id"`
	SourceAlertID        string            `json:"source_alert_id"`
	RawListName          string            `json:"raw_list_name"`
	OccurredAt           string            `json:"occurred_at"`
	ExternalScore        int               `json:"external_score,omitempty"`
	ExternalReasons      []string          `json:"external_reason_codes,omitempty"`
	MatchedFields        []string          `json:"matched_fields,omitempty"`
	CandidateReferences  []string          `json:"candidate_references,omitempty"`
	MessageReferences    []string          `json:"message_references,omitempty"`
	AttachmentReferences []string          `json:"attachment_references,omitempty"`
	AlertListResolution  json.RawMessage   `json:"alert_list_resolution"`
	AdditionalEvidence   map[string]string `json:"additional_evidence,omitempty"`
}

type Classification struct {
	SchemaVersion       string   `json:"schema_version"`
	ClassificationID    string   `json:"classification_id"`
	PatternCodes        []string `json:"pattern_codes"`
	CountervailingCodes []string `json:"countervailing_codes,omitempty"`
	MissingEvidence     []string `json:"missing_evidence,omitempty"`
	RouteHint           string   `json:"route_hint"`
	ScoreBasis          int      `json:"score_basis"`
}

type PolicyDecision struct {
	SchemaVersion    string   `json:"schema_version"`
	DecisionID       string   `json:"decision_id"`
	PolicyID         string   `json:"policy_id"`
	PolicyVersion    string   `json:"policy_version"`
	PolicySHA256     string   `json:"policy_sha256"`
	Route            string   `json:"route"`
	Score            int      `json:"score"`
	Threshold        int      `json:"threshold"`
	Blockers         []string `json:"blockers,omitempty"`
	ReasonCodes      []string `json:"reason_codes"`
	OrderedRuleTrace []string `json:"ordered_rule_trace"`
}

type CreateAlertRequest struct {
	TenantID       string          `json:"tenant_id"`
	SourceType     string          `json:"source_type"`
	ScreeningEvent json.RawMessage `json:"screening_event,omitempty"`
	ExternalAlert  *ExternalAlert  `json:"external_alert,omitempty"`
	Subject        json.RawMessage `json:"subject,omitempty"`
	CorrelationID  string          `json:"correlation_id"`
	IdempotencyKey string          `json:"idempotency_key"`
	OccurredAt     string          `json:"occurred_at"`
}

type AlertRecord struct {
	SchemaVersion     string             `json:"schema_version"`
	AlertID           string             `json:"alert_id"`
	TenantID          string             `json:"tenant_id"`
	SourceType        string             `json:"source_type"`
	SourceIdentity    string             `json:"source_identity"`
	ScreeningLineage  *ScreeningLineage  `json:"screening_lineage,omitempty"`
	ExternalAlert     *ExternalAlert     `json:"external_alert,omitempty"`
	Subject           json.RawMessage    `json:"subject,omitempty"`
	CandidateSummary  []CandidateSummary `json:"candidate_summary,omitempty"`
	Classification    Classification     `json:"classification"`
	PolicyDecision    PolicyDecision     `json:"policy_decision"`
	CorrelationIDHash string             `json:"correlation_id_hash"`
	CreatedAt         string             `json:"created_at"`
	RecordSHA256      string             `json:"record_sha256"`
}

type CreateAlertBatchRequest struct {
	Requests       []CreateAlertRequest `json:"requests"`
	CorrelationID  string               `json:"correlation_id"`
	IdempotencyKey string               `json:"idempotency_key"`
	OccurredAt     string               `json:"occurred_at"`
}

type AlertBatchResult struct {
	Alerts   []AlertRecord `json:"alerts"`
	Replayed bool          `json:"replayed"`
}

type CreateCaseRequest struct {
	TenantID       string   `json:"tenant_id"`
	AlertIDs       []string `json:"alert_ids"`
	GroupingKey    string   `json:"grouping_key,omitempty"`
	CreatedBy      string   `json:"created_by"`
	Reason         string   `json:"reason"`
	OccurredAt     string   `json:"occurred_at"`
	IdempotencyKey string   `json:"idempotency_key"`
}

type CaseEventRequest struct {
	CaseID           string          `json:"case_id"`
	ExpectedRevision uint64          `json:"expected_revision"`
	Action           string          `json:"action"`
	Actor            string          `json:"actor"`
	Reason           string          `json:"reason,omitempty"`
	OccurredAt       string          `json:"occurred_at"`
	IdempotencyKey   string          `json:"idempotency_key"`
	Payload          json.RawMessage `json:"payload,omitempty"`
}

type CaseEvent struct {
	SchemaVersion       string          `json:"schema_version"`
	CaseID              string          `json:"case_id"`
	Sequence            uint64          `json:"sequence"`
	Revision            uint64          `json:"revision"`
	PreviousEventSHA256 string          `json:"previous_event_sha256"`
	EventSHA256         string          `json:"event_sha256"`
	Action              string          `json:"action"`
	Actor               string          `json:"actor"`
	Reason              string          `json:"reason,omitempty"`
	OccurredAt          string          `json:"occurred_at"`
	Payload             json.RawMessage `json:"payload,omitempty"`
}

type CaseHead struct {
	SchemaVersion string `json:"schema_version"`
	CaseID        string `json:"case_id"`
	Sequence      uint64 `json:"sequence"`
	Revision      uint64 `json:"revision"`
	EventSHA256   string `json:"event_sha256"`
}

type CaseProjection struct {
	SchemaVersion         string          `json:"schema_version"`
	CaseID                string          `json:"case_id"`
	TenantID              string          `json:"tenant_id"`
	AlertIDs              []string        `json:"alert_ids"`
	GroupingKey           string          `json:"grouping_key,omitempty"`
	State                 string          `json:"state"`
	Revision              uint64          `json:"revision"`
	AssignedTo            string          `json:"assigned_to,omitempty"`
	DecisionProposer      string          `json:"decision_proposer,omitempty"`
	ProposedDecision      json.RawMessage `json:"proposed_decision,omitempty"`
	ApprovedDecision      json.RawMessage `json:"approved_decision,omitempty"`
	EvidenceRequestIDs    []string        `json:"evidence_request_ids,omitempty"`
	EvidenceSubmissionIDs []string        `json:"evidence_submission_ids,omitempty"`
	RescreenEventIDs      []string        `json:"rescreen_event_ids,omitempty"`
	CreatedAt             string          `json:"created_at"`
	UpdatedAt             string          `json:"updated_at"`
	HeadEventSHA256       string          `json:"head_event_sha256"`
}

type AuditEvent struct {
	SchemaVersion       string          `json:"schema_version"`
	StreamID            string          `json:"stream_id"`
	Sequence            uint64          `json:"sequence"`
	PreviousAuditSHA256 string          `json:"previous_audit_sha256"`
	AuditSHA256         string          `json:"audit_sha256"`
	OccurredAt          string          `json:"occurred_at"`
	Action              string          `json:"action"`
	Actor               string          `json:"actor,omitempty"`
	ObjectType          string          `json:"object_type"`
	ObjectID            string          `json:"object_id"`
	Details             json.RawMessage `json:"details,omitempty"`
}

type Policy struct {
	SchemaVersion             string `json:"schema_version"`
	PolicyID                  string `json:"policy_id"`
	Version                   string `json:"version"`
	HighScoreThreshold        int    `json:"high_score_threshold"`
	ReviewScoreThreshold      int    `json:"review_score_threshold"`
	ExternalEscalateThreshold int    `json:"external_escalate_threshold"`
	PolicySHA256              string `json:"policy_sha256,omitempty"`
}

type Status struct {
	Status     string `json:"status"`
	AlertCount int    `json:"alert_count"`
	CaseCount  int    `json:"case_count"`
	AuditCount int    `json:"audit_count"`
}
