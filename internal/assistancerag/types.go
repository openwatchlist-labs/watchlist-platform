package assistancerag

import "encoding/json"

const (
	CorpusManifestSchemaV1 = "openwatchlist.rag-corpus-manifest.v1"
	CorpusSnapshotSchemaV1 = "openwatchlist.rag-corpus-snapshot.v1"
	RetrievalSchemaV1      = "openwatchlist.case-retrieval.v1"
	AssistanceSchemaV1     = "openwatchlist.case-assistance.v1"
	ReviewSchemaV1         = "openwatchlist.case-assistance-review.v1"
	AuditSchemaV1          = "openwatchlist.case-assistance-audit.v1"
	DraftSchemaV1          = "openwatchlist.analyst-assistance-draft.v1"
	GuardianSchemaV1       = "openwatchlist.guardian-assessment.v1"
)

type CorpusDocument struct {
	DocumentID  string `json:"document_id"`
	TenantID    string `json:"tenant_id"`
	Kind        string `json:"kind"`
	Title       string `json:"title"`
	SourceRef   string `json:"source_ref"`
	EffectiveAt string `json:"effective_at"`
	Text        string `json:"text"`
}

type CorpusManifest struct {
	SchemaVersion string           `json:"schema_version"`
	CorpusID      string           `json:"corpus_id"`
	Version       string           `json:"version"`
	BuiltAt       string           `json:"built_at"`
	Documents     []CorpusDocument `json:"documents"`
}

type Passage struct {
	PassageID   string `json:"passage_id"`
	DocumentID  string `json:"document_id"`
	TenantID    string `json:"tenant_id"`
	Kind        string `json:"kind"`
	Title       string `json:"title"`
	SourceRef   string `json:"source_ref"`
	EffectiveAt string `json:"effective_at"`
	Ordinal     int    `json:"ordinal"`
	Text        string `json:"text"`
	TextSHA256  string `json:"text_sha256"`
}

type CorpusSnapshot struct {
	SchemaVersion  string    `json:"schema_version"`
	CorpusID       string    `json:"corpus_id"`
	Version        string    `json:"version"`
	BuiltAt        string    `json:"built_at"`
	ManifestSHA256 string    `json:"manifest_sha256"`
	PassageCount   int       `json:"passage_count"`
	Passages       []Passage `json:"passages"`
	SnapshotSHA256 string    `json:"snapshot_sha256"`
}

type RetrievalQuery struct {
	TenantID string   `json:"tenant_id"`
	Terms    []string `json:"terms"`
	TopK     int      `json:"top_k"`
}

type RetrievedPassage struct {
	PassageID   string   `json:"passage_id"`
	DocumentID  string   `json:"document_id"`
	Kind        string   `json:"kind"`
	Title       string   `json:"title"`
	SourceRef   string   `json:"source_ref"`
	EffectiveAt string   `json:"effective_at"`
	Text        string   `json:"text"`
	TextSHA256  string   `json:"text_sha256"`
	Score       int      `json:"score"`
	MatchTerms  []string `json:"match_terms"`
}

type RetrievalPackage struct {
	SchemaVersion  string             `json:"schema_version"`
	CorpusID       string             `json:"corpus_id"`
	CorpusVersion  string             `json:"corpus_version"`
	SnapshotSHA256 string             `json:"snapshot_sha256"`
	TenantID       string             `json:"tenant_id"`
	QueryTerms     []string           `json:"query_terms"`
	Passages       []RetrievedPassage `json:"passages"`
	PackageSHA256  string             `json:"package_sha256"`
}

type AssistanceRequest struct {
	CaseID         string `json:"case_id"`
	TenantID       string `json:"tenant_id,omitempty"`
	Task           string `json:"task"`
	ModelRole      string `json:"model_role,omitempty"`
	Actor          string `json:"actor"`
	OccurredAt     string `json:"occurred_at"`
	IdempotencyKey string `json:"idempotency_key"`
}

type EvidenceFinding struct {
	Statement   string   `json:"statement"`
	CitationIDs []string `json:"citation_ids"`
}

type AssistanceDraft struct {
	SchemaVersion            string            `json:"schema_version"`
	Summary                  string            `json:"summary"`
	EvidenceFindings         []EvidenceFinding `json:"evidence_findings"`
	MissingEvidenceQuestions []string          `json:"missing_evidence_questions"`
	SuggestedNextSteps       []string          `json:"suggested_next_steps"`
}

type GuardianAssessment struct {
	SchemaVersion     string   `json:"schema_version"`
	Grounded          bool     `json:"grounded"`
	Relevant          bool     `json:"relevant"`
	Safe              bool     `json:"safe"`
	CitationsValid    bool     `json:"citations_valid"`
	UnsupportedClaims []string `json:"unsupported_claims,omitempty"`
	Notes             string   `json:"notes,omitempty"`
}

type ModelInvocation struct {
	Role            string `json:"role"`
	ModelID         string `json:"model_id"`
	RequestSHA256   string `json:"request_sha256"`
	ResponseSHA256  string `json:"response_sha256,omitempty"`
	DurationNanos   int64  `json:"duration_nanos,omitempty"`
	PromptTokens    int    `json:"prompt_tokens,omitempty"`
	GeneratedTokens int    `json:"generated_tokens,omitempty"`
	KeepAlive       string `json:"keep_alive"`
	ContextTokens   int    `json:"context_tokens"`
	Error           string `json:"error,omitempty"`
}

type CaseContext struct {
	CaseID        string          `json:"case_id"`
	TenantID      string          `json:"tenant_id"`
	State         string          `json:"state"`
	Revision      uint64          `json:"revision"`
	AlertIDs      []string        `json:"alert_ids"`
	AlertFacts    json.RawMessage `json:"alert_facts"`
	ContextSHA256 string          `json:"context_sha256"`
}

type AssistanceRecord struct {
	SchemaVersion      string              `json:"schema_version"`
	AssistanceID       string              `json:"assistance_id"`
	CaseID             string              `json:"case_id"`
	TenantID           string              `json:"tenant_id"`
	Task               string              `json:"task"`
	Status             string              `json:"status"`
	Actor              string              `json:"actor"`
	OccurredAt         string              `json:"occurred_at"`
	CaseContext        CaseContext         `json:"case_context"`
	Retrieval          RetrievalPackage    `json:"retrieval"`
	Generation         ModelInvocation     `json:"generation"`
	GuardianInvocation ModelInvocation     `json:"guardian_invocation"`
	Draft              *AssistanceDraft    `json:"draft,omitempty"`
	Guardian           *GuardianAssessment `json:"guardian,omitempty"`
	FailureCode        string              `json:"failure_code,omitempty"`
	FailureDetail      string              `json:"failure_detail,omitempty"`
	RecordSHA256       string              `json:"record_sha256"`
}

type ReviewRequest struct {
	CaseID         string `json:"case_id"`
	AssistanceID   string `json:"assistance_id"`
	Action         string `json:"action"`
	Actor          string `json:"actor"`
	Reason         string `json:"reason"`
	OccurredAt     string `json:"occurred_at"`
	IdempotencyKey string `json:"idempotency_key"`
}

type ReviewEvent struct {
	SchemaVersion       string `json:"schema_version"`
	AssistanceID        string `json:"assistance_id"`
	CaseID              string `json:"case_id"`
	Sequence            uint64 `json:"sequence"`
	PreviousEventSHA256 string `json:"previous_event_sha256"`
	EventSHA256         string `json:"event_sha256"`
	Action              string `json:"action"`
	Actor               string `json:"actor"`
	Reason              string `json:"reason"`
	OccurredAt          string `json:"occurred_at"`
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

type IdempotencyReceipt struct {
	Scope          string `json:"scope"`
	KeySHA256      string `json:"key_sha256"`
	RequestSHA256  string `json:"request_sha256"`
	ResponseSHA256 string `json:"response_sha256"`
	ObjectType     string `json:"object_type"`
	ObjectID       string `json:"object_id"`
	CreatedAt      string `json:"created_at"`
}

type ModelProfile struct {
	PrimaryModelID   string `json:"primary_model_id"`
	ReasoningModelID string `json:"reasoning_model_id"`
	GuardianModelID  string `json:"guardian_model_id"`
	ContextTokens    int    `json:"context_tokens"`
	KeepAlive        string `json:"keep_alive"`
	MaxOutputBytes   int    `json:"max_output_bytes"`
}

type Status struct {
	Status          string `json:"status"`
	AssistanceCount int    `json:"assistance_count"`
	ReviewCount     int    `json:"review_count"`
	AuditCount      int    `json:"audit_count"`
}
