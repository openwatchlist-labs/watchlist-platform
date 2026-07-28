package analystnote

import (
	"github.com/openwatchlist-labs/watchlist-platform/internal/policyengine"
	"github.com/openwatchlist-labs/watchlist-platform/internal/rag"
)

const (
	ProfileSchema    = "analyst-note-profile/v1alpha1"
	NoteSchema       = "analyst-note/v1alpha1"
	ClaimSchema      = "analyst-note-claim/v1alpha1"
	InvocationSchema = "analyst-note-invocation/v1alpha1"
	GeneratorVersion = "governed-analyst-note/v0.1.0"
)

type Profile struct {
	SchemaVersion          string   `json:"schema_version"`
	ProfileID              string   `json:"profile_id"`
	ProfileVersion         string   `json:"profile_version"`
	ProfileChecksum        string   `json:"profile_checksum"`
	PromptVersion          string   `json:"prompt_version"`
	DefaultModelID         string   `json:"default_model_id"`
	TemperatureBasisPoints int      `json:"temperature_basis_points"`
	MaximumCitations       int      `json:"maximum_citations"`
	ProhibitedPhrases      []string `json:"prohibited_phrases"`
}

type ProfileReference struct {
	ProfileID       string `json:"profile_id"`
	ProfileVersion  string `json:"profile_version"`
	ProfileChecksum string `json:"profile_checksum"`
	PromptVersion   string `json:"prompt_version"`
}

type ModelReference struct {
	Provider string `json:"provider"`
	ModelID  string `json:"model_id"`
}

type Claim struct {
	SchemaVersion string   `json:"schema_version"`
	ClaimID       string   `json:"claim_id"`
	Text          string   `json:"text"`
	CitationIDs   []string `json:"citation_ids"`
}

type Note struct {
	SchemaVersion            string           `json:"schema_version"`
	NoteID                   string           `json:"note_id"`
	Status                   string           `json:"status"`
	DecisionID               string           `json:"decision_id"`
	DeterministicDisposition string           `json:"deterministic_disposition"`
	ReviewRoute              string           `json:"review_route"`
	Summary                  string           `json:"summary"`
	Claims                   []Claim          `json:"claims"`
	MissingEvidence          []string         `json:"missing_evidence,omitempty"`
	CitationIDs              []string         `json:"citation_ids"`
	Model                    ModelReference   `json:"model"`
	Profile                  ProfileReference `json:"profile"`
	Warnings                 []string         `json:"warnings,omitempty"`
}

type Invocation struct {
	SchemaVersion    string                `json:"schema_version"`
	InvocationID     string                `json:"invocation_id"`
	GeneratorVersion string                `json:"generator_version"`
	Decision         policyengine.Decision `json:"decision"`
	CitationPackage  rag.CitationPackage   `json:"citation_package"`
	Profile          ProfileReference      `json:"profile"`
	Model            ModelReference        `json:"model"`
	PromptChecksum   string                `json:"prompt_checksum"`
	Note             Note                  `json:"note"`
}

type DraftInput struct {
	Decision        policyengine.Decision
	CitationPackage rag.CitationPackage
	Profile         Profile
}

type Provider interface {
	Name() string
	ModelID() string
	Draft(prompt string, schema map[string]any) ([]byte, error)
}
