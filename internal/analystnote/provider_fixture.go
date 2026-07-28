package analystnote

import (
	"encoding/json"
	"fmt"
)

type FixtureProvider struct {
	modelID string
	input   DraftInput
}

func NewFixtureProvider(modelID string, input DraftInput) *FixtureProvider {
	return &FixtureProvider{modelID: modelID, input: input}
}

func (p *FixtureProvider) Name() string    { return "fixture" }
func (p *FixtureProvider) ModelID() string { return p.modelID }

func (p *FixtureProvider) Draft(_ string, _ map[string]any) ([]byte, error) {
	if len(p.input.CitationPackage.Citations) == 0 {
		return nil, fmt.Errorf("fixture provider requires citations")
	}
	decision := p.input.Decision
	first := p.input.CitationPackage.Citations[0].CitationID
	second := first
	if len(p.input.CitationPackage.Citations) > 1 {
		second = p.input.CitationPackage.Citations[1].CitationID
	}
	claims := []Claim{
		{SchemaVersion: ClaimSchema, Text: fmt.Sprintf("The deterministic policy route is %s through %s and remains authoritative.", decision.Disposition, decision.ReviewRoute), CitationIDs: []string{first}},
		{SchemaVersion: ClaimSchema, Text: fmt.Sprintf("The available policy context supports review of reason codes %v and blockers %v.", decision.ReasonCodes, decision.EscalationBlockers), CitationIDs: []string{second}},
	}
	note := Note{
		SchemaVersion:            NoteSchema,
		Status:                   "draft",
		DecisionID:               decision.DecisionID,
		DeterministicDisposition: string(decision.Disposition),
		ReviewRoute:              string(decision.ReviewRoute),
		Summary:                  fmt.Sprintf("Draft analyst context for deterministic %s disposition.", decision.Disposition),
		Claims:                   claims,
		MissingEvidence:          append([]string(nil), decision.RequiredEvidence...),
		CitationIDs:              []string{first, second},
	}
	return json.Marshal(note)
}
