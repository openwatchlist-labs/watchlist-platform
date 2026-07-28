package iso20022coverage

// Matrix is the immutable, explicitly bounded ISO 20022 support contract.
type Matrix struct {
	SchemaVersion string          `json:"schema_version"`
	MatrixID      string          `json:"matrix_id"`
	Version       string          `json:"version"`
	Families      []FamilyProfile `json:"families"`
	SHA256        string          `json:"sha256,omitempty"`
}

type FamilyProfile struct {
	ProfileID             string   `json:"profile_id"`
	MessageDefinitionID   string   `json:"message_definition_id"`
	Variant               string   `json:"variant,omitempty"`
	Namespace             string   `json:"namespace"`
	RootElement           string   `json:"root_element"`
	ContainsElement       string   `json:"contains_element,omitempty"`
	TransactionContainers []string `json:"transaction_containers"`
	SupportLevel          string   `json:"support_level"`
	Description           string   `json:"description"`
}

type EvidenceEnvelope struct {
	SchemaVersion       string             `json:"schema_version"`
	SourceRef           string             `json:"source_ref"`
	SourceSHA256        string             `json:"source_sha256"`
	MatrixID            string             `json:"matrix_id"`
	MatrixVersion       string             `json:"matrix_version"`
	MatrixSHA256        string             `json:"matrix_sha256"`
	ProfileID           string             `json:"profile_id"`
	MessageDefinitionID string             `json:"message_definition_id"`
	Variant             string             `json:"variant,omitempty"`
	Namespace           string             `json:"namespace"`
	RootElement         string             `json:"root_element"`
	SupportLevel        string             `json:"support_level"`
	TransactionCount    int                `json:"transaction_count"`
	ElementCount        int                `json:"element_count"`
	ScreenableCount     int                `json:"screenable_count"`
	Elements            []EvidenceElement  `json:"elements"`
	Warnings            []ValidationNotice `json:"warnings"`
	EnvelopeSHA256      string             `json:"envelope_sha256"`
}

type EvidenceElement struct {
	ElementID        string `json:"element_id"`
	TransactionIndex int    `json:"transaction_index"`
	FieldPath        string `json:"field_path"`
	SemanticRole     string `json:"semantic_role"`
	Kind             string `json:"kind"`
	Value            string `json:"value"`
	NormalizedValue  string `json:"normalized_value"`
	Action           string `json:"action"`
	MatchEligible    bool   `json:"match_eligible"`
}

type ValidationNotice struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

type ScreeningProjection struct {
	SchemaVersion       string             `json:"schema_version"`
	SourceRef           string             `json:"source_ref"`
	SourceSHA256        string             `json:"source_sha256"`
	MatrixSHA256        string             `json:"matrix_sha256"`
	ProfileID           string             `json:"profile_id"`
	MessageDefinitionID string             `json:"message_definition_id"`
	Requests            []ScreeningRequest `json:"requests"`
	ProjectionSHA256    string             `json:"projection_sha256"`
}

type ScreeningRequest struct {
	RequestID        string `json:"request_id"`
	ElementID        string `json:"element_id"`
	TransactionIndex int    `json:"transaction_index"`
	FieldPath        string `json:"field_path"`
	SemanticRole     string `json:"semantic_role"`
	QueryKind        string `json:"query_kind"`
	Value            string `json:"value"`
	NormalizedValue  string `json:"normalized_value"`
}

type BatchEnvelope struct {
	SchemaVersion string             `json:"schema_version"`
	Documents     []EvidenceEnvelope `json:"documents"`
	BatchSHA256   string             `json:"batch_sha256"`
}
