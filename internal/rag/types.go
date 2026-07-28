package rag

const (
	CorpusManifestSchema  = "rag-corpus-manifest/v1alpha1"
	CorpusSnapshotSchema  = "rag-corpus-snapshot/v1alpha1"
	RetrievalPolicySchema = "rag-retrieval-policy/v1alpha1"
	RetrievalQuerySchema  = "rag-retrieval-query/v1alpha1"
	CitationPackageSchema = "rag-citation-package/v1alpha1"
	RetrieverVersion      = "deterministic-hybrid-retriever/v0.1.0"
)

type SourceTier string

const (
	TierA SourceTier = "A"
	TierB SourceTier = "B"
	TierC SourceTier = "C"
	TierD SourceTier = "D"
)

type DocumentSpec struct {
	SourceID        string     `json:"source_id"`
	Path            string     `json:"path"`
	Title           string     `json:"title"`
	Publisher       string     `json:"publisher"`
	SourceTier      SourceTier `json:"source_tier"`
	DocumentType    string     `json:"document_type"`
	Jurisdiction    string     `json:"jurisdiction,omitempty"`
	PublicationDate string     `json:"publication_date,omitempty"`
	EffectiveFrom   string     `json:"effective_from,omitempty"`
	EffectiveTo     string     `json:"effective_to,omitempty"`
	ApprovalStatus  string     `json:"approval_status"`
	TenantID        string     `json:"tenant_id,omitempty"`
	AccessScope     []string   `json:"access_scope"`
	Supersedes      []string   `json:"supersedes,omitempty"`
}

type CorpusManifest struct {
	SchemaVersion  string         `json:"schema_version"`
	CorpusID       string         `json:"corpus_id"`
	CorpusVersion  string         `json:"corpus_version"`
	SnapshotAt     string         `json:"snapshot_at"`
	CorpusChecksum string         `json:"corpus_checksum"`
	Documents      []DocumentSpec `json:"documents"`
}

type Chunk struct {
	ChunkID               string   `json:"chunk_id"`
	SourceID              string   `json:"source_id"`
	HeadingPath           []string `json:"heading_path,omitempty"`
	Locator               string   `json:"locator"`
	Text                  string   `json:"text"`
	ContentChecksum       string   `json:"content_checksum"`
	Tokens                []string `json:"tokens"`
	InstructionLike       bool     `json:"instruction_like_content,omitempty"`
	InstructionIndicators []string `json:"instruction_indicators,omitempty"`
}

type Document struct {
	Spec            DocumentSpec `json:"spec"`
	ContentChecksum string       `json:"content_checksum"`
	Chunks          []Chunk      `json:"chunks"`
}

type CorpusSnapshot struct {
	SchemaVersion  string     `json:"schema_version"`
	SnapshotID     string     `json:"snapshot_id"`
	CorpusID       string     `json:"corpus_id"`
	CorpusVersion  string     `json:"corpus_version"`
	SnapshotAt     string     `json:"snapshot_at"`
	CorpusChecksum string     `json:"corpus_checksum"`
	Documents      []Document `json:"documents"`
}

type RetrievalPolicy struct {
	SchemaVersion              string       `json:"schema_version"`
	PolicyID                   string       `json:"policy_id"`
	PolicyVersion              string       `json:"policy_version"`
	PolicyChecksum             string       `json:"policy_checksum"`
	AllowedSourceTiers         []SourceTier `json:"allowed_source_tiers"`
	AllowedApprovalStatuses    []string     `json:"allowed_approval_statuses"`
	MaxResults                 int          `json:"max_results"`
	MinimumScoreBasisPoints    int          `json:"minimum_score_basis_points"`
	MetadataWeightBasisPoints  int          `json:"metadata_weight_basis_points"`
	LexicalWeightBasisPoints   int          `json:"lexical_weight_basis_points"`
	VectorWeightBasisPoints    int          `json:"vector_weight_basis_points"`
	ExcludeInstructionLikeText bool         `json:"exclude_instruction_like_text"`
}

type RetrievalPolicyReference struct {
	PolicyID       string `json:"policy_id"`
	PolicyVersion  string `json:"policy_version"`
	PolicyChecksum string `json:"policy_checksum"`
}

type RetrievalQuery struct {
	SchemaVersion    string   `json:"schema_version"`
	QueryID          string   `json:"query_id"`
	Task             string   `json:"task"`
	TenantID         string   `json:"tenant_id"`
	DecisionID       string   `json:"decision_id"`
	Disposition      string   `json:"disposition"`
	ReviewRoute      string   `json:"review_route"`
	ReasonCodes      []string `json:"reason_codes"`
	Blockers         []string `json:"blockers,omitempty"`
	RequiredEvidence []string `json:"required_evidence,omitempty"`
	MessageType      string   `json:"message_type"`
	SemanticRole     string   `json:"semantic_role"`
	PolicyID         string   `json:"policy_id"`
	EffectiveAt      string   `json:"effective_at"`
	QueryText        string   `json:"query_text,omitempty"`
}

type RetrievalScore struct {
	MetadataBasisPoints int `json:"metadata_basis_points"`
	LexicalBasisPoints  int `json:"lexical_basis_points"`
	VectorBasisPoints   int `json:"vector_basis_points"`
	TotalBasisPoints    int `json:"total_basis_points"`
}

type Citation struct {
	CitationID       string         `json:"citation_id"`
	SourceID         string         `json:"source_id"`
	SourceTier       SourceTier     `json:"source_tier"`
	Title            string         `json:"title"`
	Publisher        string         `json:"publisher"`
	DocumentType     string         `json:"document_type"`
	Jurisdiction     string         `json:"jurisdiction,omitempty"`
	EffectiveFrom    string         `json:"effective_from,omitempty"`
	EffectiveTo      string         `json:"effective_to,omitempty"`
	ApprovalStatus   string         `json:"approval_status"`
	TenantID         string         `json:"tenant_id,omitempty"`
	Locator          string         `json:"locator"`
	Excerpt          string         `json:"excerpt"`
	ContentChecksum  string         `json:"content_checksum"`
	CorpusSnapshotID string         `json:"corpus_snapshot_id"`
	RetrievalMethods []string       `json:"retrieval_methods"`
	Score            RetrievalScore `json:"score"`
}

type RetrievalSummary struct {
	DocumentsConsidered             int `json:"documents_considered"`
	ChunksConsidered                int `json:"chunks_considered"`
	CitationsReturned               int `json:"citations_returned"`
	ExcludedTenantOrScope           int `json:"excluded_tenant_or_scope"`
	ExcludedUnapprovedOrIneffective int `json:"excluded_unapproved_or_ineffective"`
	ExcludedInstructionLikeChunks   int `json:"excluded_instruction_like_chunks"`
	ExcludedBelowMinimumScore       int `json:"excluded_below_minimum_score"`
}

type CitationPackage struct {
	SchemaVersion     string                   `json:"schema_version"`
	CitationPackageID string                   `json:"citation_package_id"`
	Query             RetrievalQuery           `json:"query"`
	RetrieverVersion  string                   `json:"retriever_version"`
	RetrievalPolicy   RetrievalPolicyReference `json:"retrieval_policy"`
	CorpusSnapshotID  string                   `json:"corpus_snapshot_id"`
	Summary           RetrievalSummary         `json:"summary"`
	Citations         []Citation               `json:"citations"`
}
