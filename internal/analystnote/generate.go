package analystnote

import (
	"fmt"
	"sort"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/policyengine"
	"github.com/openwatchlist-labs/watchlist-platform/internal/rag"
)

func Generate(input DraftInput, provider Provider) (Invocation, error) {
	if err := policyengine.ValidateDecision(input.Decision); err != nil {
		return Invocation{}, err
	}
	if err := rag.ValidateCitationPackage(input.CitationPackage); err != nil {
		return Invocation{}, err
	}
	if input.CitationPackage.Query.DecisionID != input.Decision.DecisionID {
		return Invocation{}, fmt.Errorf("citation package decision_id does not match decision")
	}
	if err := ValidateProfile(input.Profile); err != nil {
		return Invocation{}, err
	}
	prompt, promptChecksum, err := BuildPrompt(input)
	if err != nil {
		return Invocation{}, err
	}
	raw, err := provider.Draft(prompt, OutputSchema())
	if err != nil {
		return Invocation{}, err
	}
	var note Note
	if err := decodeStrict(raw, &note); err != nil {
		return Invocation{}, fmt.Errorf("decode analyst note: %w", err)
	}
	for index := range note.Claims {
		note.Claims[index].CitationIDs = sortedUnique(note.Claims[index].CitationIDs)
		note.Claims[index].ClaimID = stableClaimID(note.Claims[index])
	}
	note.CitationIDs = sortedUnique(note.CitationIDs)
	note.MissingEvidence = sortedUnique(note.MissingEvidence)
	note.Warnings = sortedUnique(note.Warnings)
	note.Model = ModelReference{Provider: provider.Name(), ModelID: provider.ModelID()}
	note.Profile = ProfileReference{ProfileID: input.Profile.ProfileID, ProfileVersion: input.Profile.ProfileVersion, ProfileChecksum: input.Profile.ProfileChecksum, PromptVersion: input.Profile.PromptVersion}
	note.NoteID = stableNoteID(note)
	if err := ValidateNote(note, input); err != nil {
		return Invocation{}, err
	}
	invocation := Invocation{
		SchemaVersion:    InvocationSchema,
		GeneratorVersion: GeneratorVersion,
		Decision:         input.Decision,
		CitationPackage:  input.CitationPackage,
		Profile:          note.Profile,
		Model:            note.Model,
		PromptChecksum:   promptChecksum,
		Note:             note,
	}
	invocation.InvocationID = stableInvocationID(invocation)
	if err := ValidateInvocation(invocation); err != nil {
		return Invocation{}, err
	}
	return invocation, nil
}

func ValidateProfile(profile Profile) error {
	if profile.SchemaVersion != ProfileSchema || profile.ProfileID == "" || profile.ProfileVersion == "" || profile.ProfileChecksum == "" || profile.PromptVersion == "" || profile.DefaultModelID == "" {
		return fmt.Errorf("invalid analyst-note profile metadata")
	}
	if profile.TemperatureBasisPoints < 0 || profile.TemperatureBasisPoints > 10000 || profile.MaximumCitations < 1 || profile.MaximumCitations > 20 {
		return fmt.Errorf("invalid analyst-note profile limits")
	}
	if len(profile.ProhibitedPhrases) == 0 {
		return fmt.Errorf("prohibited phrases are required")
	}
	if expected := ProfileChecksum(profile); profile.ProfileChecksum != expected {
		return fmt.Errorf("profile_checksum=%q expected %q", profile.ProfileChecksum, expected)
	}
	return nil
}

func ValidateNote(note Note, input DraftInput) error {
	if note.SchemaVersion != NoteSchema || note.NoteID == "" || note.Status != "draft" || note.DecisionID != input.Decision.DecisionID {
		return fmt.Errorf("invalid analyst note metadata")
	}
	if note.DeterministicDisposition != string(input.Decision.Disposition) || note.ReviewRoute != string(input.Decision.ReviewRoute) {
		return fmt.Errorf("analyst note attempted deterministic route override")
	}
	if strings.TrimSpace(note.Summary) == "" || len(note.Claims) == 0 || len(note.CitationIDs) == 0 {
		return fmt.Errorf("analyst note summary, claims, and citations are required")
	}
	allowed := map[string]struct{}{}
	for _, citation := range input.CitationPackage.Citations {
		allowed[citation.CitationID] = struct{}{}
	}
	used := map[string]struct{}{}
	for i, claim := range note.Claims {
		if claim.SchemaVersion != ClaimSchema || claim.ClaimID == "" || strings.TrimSpace(claim.Text) == "" || len(claim.CitationIDs) == 0 {
			return fmt.Errorf("claims[%d] invalid", i)
		}
		for _, citationID := range claim.CitationIDs {
			if _, ok := allowed[citationID]; !ok {
				return fmt.Errorf("claims[%d] uses unknown citation_id %q", i, citationID)
			}
			used[citationID] = struct{}{}
		}
		if expected := stableClaimID(claim); claim.ClaimID != expected {
			return fmt.Errorf("claims[%d] claim ID mismatch", i)
		}
	}
	for _, citationID := range note.CitationIDs {
		if _, ok := allowed[citationID]; !ok {
			return fmt.Errorf("note uses unknown citation_id %q", citationID)
		}
		if _, ok := used[citationID]; !ok {
			return fmt.Errorf("citation_id %q is not used by a claim", citationID)
		}
	}
	text := strings.ToUpper(note.Summary)
	for _, claim := range note.Claims {
		text += " " + strings.ToUpper(claim.Text)
	}
	for _, phrase := range input.Profile.ProhibitedPhrases {
		if strings.Contains(text, strings.ToUpper(phrase)) {
			return fmt.Errorf("analyst note contains prohibited phrase %q", phrase)
		}
	}
	if expected := stableNoteID(note); note.NoteID != expected {
		return fmt.Errorf("note_id=%q expected %q", note.NoteID, expected)
	}
	return nil
}

func ValidateInvocation(invocation Invocation) error {
	if invocation.SchemaVersion != InvocationSchema || invocation.InvocationID == "" || invocation.GeneratorVersion != GeneratorVersion || invocation.PromptChecksum == "" {
		return fmt.Errorf("invalid analyst-note invocation metadata")
	}
	if invocation.Decision.DecisionID != invocation.Note.DecisionID || invocation.CitationPackage.Query.DecisionID != invocation.Decision.DecisionID {
		return fmt.Errorf("invocation lineage mismatch")
	}
	if expected := stableInvocationID(invocation); invocation.InvocationID != expected {
		return fmt.Errorf("invocation_id=%q expected %q", invocation.InvocationID, expected)
	}
	return nil
}

func sortedUnique(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
