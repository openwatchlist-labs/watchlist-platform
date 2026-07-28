package revieworchestrator

import (
	"github.com/openwatchlist-labs/watchlist-platform/internal/analystnote"
	"github.com/openwatchlist-labs/watchlist-platform/internal/falsepositive"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
	"github.com/openwatchlist-labs/watchlist-platform/internal/policyengine"
	"github.com/openwatchlist-labs/watchlist-platform/internal/rag"
)

const (
	RunBundleSchema      = "review-run-bundle/v1alpha1"
	CaseBundleSchema     = "review-case-bundle/v1alpha1"
	AuditEventSchema     = "review-audit-event/v1alpha1"
	OrchestratorVersion  = "review-orchestrator/v0.1.0"
	RetrievalCompleted   = "completed"
	RetrievalFailed      = "failed"
	NoteGenerated        = "generated"
	NoteDisabled         = "disabled"
	NoteSkippedAutoClear = "skipped_auto_clear"
	NoteRetrievalFailed  = "retrieval_failed"
	NoteGenerationFailed = "generation_failed"
)

type RunOptions struct {
	TenantID        string
	EffectiveAt     string
	SourceReference string
	CaseID          string
}

type CaseBundle struct {
	SchemaVersion     string                   `json:"schema_version"`
	CaseBundleID      string                   `json:"case_bundle_id"`
	CaseID            string                   `json:"case_id"`
	CorrelationID     string                   `json:"correlation_id"`
	ObservationID     string                   `json:"observation_id"`
	ClassificationID  string                   `json:"classification_id"`
	DecisionID        string                   `json:"decision_id"`
	Disposition       policyengine.Disposition `json:"disposition"`
	ReviewRoute       policyengine.ReviewRoute `json:"review_route"`
	RetrievalStatus   string                   `json:"retrieval_status"`
	CitationPackage   *rag.CitationPackage     `json:"citation_package,omitempty"`
	NoteStatus        string                   `json:"note_status"`
	AnalystInvocation *analystnote.Invocation  `json:"analyst_invocation,omitempty"`
	Warnings          []string                 `json:"warnings,omitempty"`
}

type RunSummary struct {
	TotalCases             int `json:"total_cases"`
	ClearCases             int `json:"clear_cases"`
	InvestigateCases       int `json:"investigate_cases"`
	EscalateCases          int `json:"escalate_cases"`
	RetrievalCompleted     int `json:"retrieval_completed"`
	RetrievalFailed        int `json:"retrieval_failed"`
	NotesGenerated         int `json:"notes_generated"`
	NotesDisabledOrSkipped int `json:"notes_disabled_or_skipped"`
	NotesFailed            int `json:"notes_failed"`
}

type AuditEvent struct {
	SchemaVersion string `json:"schema_version"`
	Sequence      int    `json:"sequence"`
	EventID       string `json:"event_id"`
	EventType     string `json:"event_type"`
	CaseID        string `json:"case_id,omitempty"`
	PayloadDigest string `json:"payload_digest"`
	PreviousHash  string `json:"previous_hash,omitempty"`
	EventHash     string `json:"event_hash"`
}

type RunBundle struct {
	SchemaVersion       string                            `json:"schema_version"`
	RunID               string                            `json:"run_id"`
	OrchestratorVersion string                            `json:"orchestrator_version"`
	TenantID            string                            `json:"tenant_id"`
	EffectiveAt         string                            `json:"effective_at"`
	SourceReference     string                            `json:"source_reference"`
	InputResultBatch    matcherprovider.ResultBatch       `json:"input_result_batch"`
	Observations        falsepositive.ObservationBatch    `json:"observations"`
	Classifications     falsepositive.ClassificationBatch `json:"classifications"`
	Decisions           policyengine.DecisionBatch        `json:"decisions"`
	Cases               []CaseBundle                      `json:"cases"`
	Summary             RunSummary                        `json:"summary"`
	AuditEvents         []AuditEvent                      `json:"audit_events"`
	AuditHead           string                            `json:"audit_head"`
}

type NoteProviderFactory func(analystnote.DraftInput) analystnote.Provider
