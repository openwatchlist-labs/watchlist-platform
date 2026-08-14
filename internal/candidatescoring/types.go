package candidatescoring

// PolicySchemaV1 is the only policy schema accepted by Phase 8C.
const PolicySchemaV1 = "openwatchlist.candidate-scoring-policy.v1"

// RequestSchemaV1 is the deterministic candidate-scoring request contract.
const RequestSchemaV1 = "openwatchlist.candidate-scoring-request.v1"

// BatchRequestSchemaV1 is the ordered batch candidate-scoring contract.
const BatchRequestSchemaV1 = "openwatchlist.candidate-scoring-batch-request.v1"

// ResponseSchemaV1 is the deterministic evidence-projection response contract.
const ResponseSchemaV1 = "openwatchlist.candidate-scoring-response.v1"

// BatchResponseSchemaV1 is the ordered batch response contract.
const BatchResponseSchemaV1 = "openwatchlist.candidate-scoring-batch-response.v1"

// Policy defines integer-only candidate scoring. It deliberately does not
// express regulatory clearance, alert disposition, or analyst workflow state.
type Policy struct {
	SchemaVersion        string     `json:"schema_version"`
	PolicyID             string     `json:"policy_id"`
	PolicyVersion        string     `json:"policy_version"`
	NormalizationProfile string     `json:"normalization_profile"`
	MaxEvidenceItems     int        `json:"max_evidence_items"`
	ScoreFloor           int        `json:"score_floor"`
	ScoreCeiling         int        `json:"score_ceiling"`
	Weights              Weights    `json:"weights"`
	Thresholds           Thresholds `json:"thresholds"`
}

// Weights are additive integer points. Exactly one name-shape weight is used,
// and typed_identifier_exact is awarded at most once per candidate.
type Weights struct {
	TypedIdentifierExact int `json:"typed_identifier_exact"`
	NameExact            int `json:"name_exact"`
	NameTokenSet         int `json:"name_token_set"`
	NameParticleStripped int `json:"name_particle_stripped"`
	NamePrefix           int `json:"name_prefix"`
	NameContainment      int `json:"name_containment"`
	DateOfBirthExact     int `json:"date_of_birth_exact"`
	DateOfBirthYear      int `json:"date_of_birth_year"`
	CountryExact         int `json:"country_exact"`
	EntityTypeExact      int `json:"entity_type_exact"`
	DateOfBirthConflict  int `json:"date_of_birth_conflict"`
	CountryConflict      int `json:"country_conflict"`
	EntityTypeConflict   int `json:"entity_type_conflict"`
}

// Thresholds classify candidate strength only. They are not case decisions.
type Thresholds struct {
	StrongCandidate int `json:"strong_candidate"`
	ReviewCandidate int `json:"review_candidate"`
	WeakCandidate   int `json:"weak_candidate"`
}

// Identifier is compared only when both type and normalized value match.
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Subject is the bounded set of screenable attributes supplied by the caller.
type Subject struct {
	Names        []string     `json:"names,omitempty"`
	Identifiers  []Identifier `json:"identifiers,omitempty"`
	Countries    []string     `json:"countries,omitempty"`
	DatesOfBirth []string     `json:"dates_of_birth,omitempty"`
	EntityType   string       `json:"entity_type,omitempty"`
}

// Candidate is intentionally a scoring projection, not a full catalog row.
type Candidate struct {
	CandidateID  string       `json:"candidate_id"`
	Names        []string     `json:"names,omitempty"`
	Identifiers  []Identifier `json:"identifiers,omitempty"`
	Countries    []string     `json:"countries,omitempty"`
	DatesOfBirth []string     `json:"dates_of_birth,omitempty"`
	EntityType   string       `json:"entity_type,omitempty"`
}

// Lineage binds the score to the active catalog component/version and
// normalization profile selected by the Phase 8B runtime boundary.
type Lineage struct {
	Provider             string `json:"provider"`
	CatalogID            string `json:"catalog_id"`
	ComponentID          string `json:"component_id"`
	ComponentVersion     string `json:"component_version"`
	ActivationID         string `json:"activation_id"`
	NormalizationProfile string `json:"normalization_profile"`
}

// RetrievalEvidence records why Phase 8B retrieved the candidate. These
// values are retained in the projection but do not add hidden score points.
type RetrievalEvidence struct {
	Routes      []string `json:"routes,omitempty"`
	ReasonCodes []string `json:"reason_codes,omitempty"`
}

// Request scores a bounded candidate set for one screening item.
type Request struct {
	SchemaVersion   string              `json:"schema_version"`
	RequestID       string              `json:"request_id"`
	FieldPath       string              `json:"field_path,omitempty"`
	OriginalValue   string              `json:"original_value,omitempty"`
	NormalizedValue string              `json:"normalized_value,omitempty"`
	Subject         Subject             `json:"subject"`
	Lineage         Lineage             `json:"lineage"`
	Candidates      []CandidateEnvelope `json:"candidates"`
}

// CandidateEnvelope couples the candidate projection with retrieval evidence.
type CandidateEnvelope struct {
	Candidate Candidate         `json:"candidate"`
	Retrieval RetrievalEvidence `json:"retrieval,omitempty"`
}

// BatchRequest preserves item order and applies one immutable policy to all
// items in the batch.
type BatchRequest struct {
	SchemaVersion string    `json:"schema_version"`
	BatchID       string    `json:"batch_id"`
	Items         []Request `json:"items"`
}

// ScoreComponent is an immutable contribution to the candidate score.
type ScoreComponent struct {
	Component  string `json:"component"`
	Points     int    `json:"points"`
	ReasonCode string `json:"reason_code"`
}

// EvidenceItem is a bounded, analyst-readable projection of one comparison.
type EvidenceItem struct {
	Kind           string `json:"kind"`
	Outcome        string `json:"outcome"`
	SubjectValue   string `json:"subject_value,omitempty"`
	CandidateValue string `json:"candidate_value,omitempty"`
	Points         int    `json:"points"`
	ReasonCode     string `json:"reason_code"`
}

// CandidateResult contains score, strength band, stable reasons, bounded
// evidence, and lineage. It contains no policy disposition and no full row.
type CandidateResult struct {
	CandidateID            string            `json:"candidate_id"`
	Score                  int               `json:"score"`
	StrengthBand           string            `json:"strength_band"`
	ExactIdentifierMatched bool              `json:"exact_identifier_matched"`
	ExactNameMatched       bool              `json:"exact_name_matched"`
	ReasonCodes            []string          `json:"reason_codes"`
	Components             []ScoreComponent  `json:"components"`
	Evidence               []EvidenceItem    `json:"evidence"`
	Retrieval              RetrievalEvidence `json:"retrieval,omitempty"`
	Lineage                Lineage           `json:"lineage"`
}

// ScreenedField retains the source path and value projection that produced
// this candidate set without exposing the surrounding payment or alert.
type ScreenedField struct {
	Path            string `json:"path,omitempty"`
	OriginalValue   string `json:"original_value,omitempty"`
	NormalizedValue string `json:"normalized_value,omitempty"`
}

// PolicyReference makes replay lineage explicit.
type PolicyReference struct {
	PolicyID             string `json:"policy_id"`
	PolicyVersion        string `json:"policy_version"`
	PolicySHA256         string `json:"policy_sha256"`
	NormalizationProfile string `json:"normalization_profile"`
}

// Response is deterministic for identical request bytes and policy content.
type Response struct {
	SchemaVersion string            `json:"schema_version"`
	RequestID     string            `json:"request_id"`
	RequestSHA256 string            `json:"request_sha256"`
	Field         ScreenedField     `json:"field"`
	Policy        PolicyReference   `json:"policy"`
	Candidates    []CandidateResult `json:"candidates"`
}

// BatchResponse keeps input item order; each item's candidate order is
// independently canonicalized.
type BatchResponse struct {
	SchemaVersion string          `json:"schema_version"`
	BatchID       string          `json:"batch_id"`
	RequestSHA256 string          `json:"request_sha256"`
	Policy        PolicyReference `json:"policy"`
	Items         []Response      `json:"items"`
}
