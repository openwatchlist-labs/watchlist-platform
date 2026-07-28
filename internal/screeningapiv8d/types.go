package screeningapiv8d

import "github.com/openwatchlist-labs/watchlist-platform/internal/candidatescoring"

const (
	ResponseSchemaV2      = "openwatchlist.screening-response.v2"
	BatchResponseSchemaV2 = "openwatchlist.screening-batch-response.v2"
	ReadySchemaV1         = "openwatchlist.screening-ready.v1"
)

// Blocker is an explicit execution blocker, not a regulatory disposition.
type Blocker struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

// Lineage binds every result to the active retrieval component and scoring policy.
type Lineage struct {
	Provider             string `json:"provider"`
	CatalogID            string `json:"catalog_id"`
	ComponentID          string `json:"component_id"`
	ComponentVersion     string `json:"component_version"`
	ActivationID         string `json:"activation_id"`
	NormalizationProfile string `json:"normalization_profile"`
}

// Candidate is the policy-bound response projection. It is intentionally not a catalog row.
type Candidate struct {
	CandidateID            string                             `json:"candidate_id"`
	Score                  int                                `json:"score"`
	SimilarityBand         string                             `json:"similarity_band"`
	ExactIdentifierMatched bool                               `json:"exact_identifier_matched"`
	ExactNameMatched       bool                               `json:"exact_name_matched"`
	ReasonCodes            []string                           `json:"reason_codes"`
	Components             []candidatescoring.ScoreComponent  `json:"components"`
	Evidence               []candidatescoring.EvidenceItem    `json:"evidence"`
	Retrieval              candidatescoring.RetrievalEvidence `json:"retrieval,omitempty"`
	Lineage                Lineage                            `json:"lineage"`
}

// Response is returned from POST /v1/screenings.
type Response struct {
	SchemaVersion string                           `json:"schema_version"`
	RequestID     string                           `json:"request_id"`
	CorrelationID string                           `json:"correlation_id"`
	RequestSHA256 string                           `json:"request_sha256"`
	Status        string                           `json:"status"`
	Blockers      []Blocker                        `json:"blockers"`
	Field         candidatescoring.ScreenedField   `json:"field"`
	Policy        candidatescoring.PolicyReference `json:"policy"`
	Lineage       Lineage                          `json:"lineage"`
	Candidates    []Candidate                      `json:"candidates"`
}

// BatchItem preserves request order and embeds one response contract per item.
type BatchItem struct {
	Index    int      `json:"index"`
	Response Response `json:"response"`
}

// BatchResponse is returned from POST /v1/screenings/batch.
type BatchResponse struct {
	SchemaVersion string                           `json:"schema_version"`
	BatchID       string                           `json:"batch_id"`
	CorrelationID string                           `json:"correlation_id"`
	RequestSHA256 string                           `json:"request_sha256"`
	Policy        candidatescoring.PolicyReference `json:"policy"`
	Items         []BatchItem                      `json:"items"`
}

// ReadyResponse proves that both retrieval and policy bindings are usable.
type ReadyResponse struct {
	SchemaVersion string                           `json:"schema_version"`
	Ready         bool                             `json:"ready"`
	Policy        candidatescoring.PolicyReference `json:"policy"`
	Upstream      string                           `json:"upstream"`
	ProjectionSet string                           `json:"projection_set_sha256"`
	Blockers      []Blocker                        `json:"blockers"`
}
