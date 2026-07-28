package analystnote

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/policyengine"
	"github.com/openwatchlist-labs/watchlist-platform/internal/rag"
)

func loadFixtureInput(t *testing.T) DraftInput {
	t.Helper()
	root := filepath.Join("..", "..")
	batchData, err := os.ReadFile(filepath.Join(root, "test", "golden", "policy", "pattern-decisions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var batch policyengine.DecisionBatch
	if err := json.Unmarshal(batchData, &batch); err != nil {
		t.Fatal(err)
	}
	var decision policyengine.Decision
	for _, item := range batch.Decisions {
		if item.Classification.Observation.CaseID == "fp-03-entity-type-mismatch" {
			decision = item
		}
	}
	citations, err := rag.LoadCitationPackage(filepath.Join(root, "test", "golden", "rag", "entity-type-citations.json"))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := LoadProfile(filepath.Join(root, "configs", "models", "granite-analyst-note-r1.json"))
	if err != nil {
		t.Fatal(err)
	}
	return DraftInput{Decision: decision, CitationPackage: citations, Profile: profile}
}

func TestFixtureGenerationAndRouteLock(t *testing.T) {
	input := loadFixtureInput(t)
	provider := NewFixtureProvider(input.Profile.DefaultModelID, input)
	first, err := Generate(input, provider)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(input, provider)
	if err != nil {
		t.Fatal(err)
	}
	if first.InvocationID != second.InvocationID || first.Note.NoteID != second.Note.NoteID {
		t.Fatal("fixture generation is not deterministic")
	}
	if first.Note.DeterministicDisposition != string(input.Decision.Disposition) || first.Note.ReviewRoute != string(input.Decision.ReviewRoute) {
		t.Fatal("deterministic route was not preserved")
	}

	bad := first.Note
	bad.NoteID = ""
	bad.DeterministicDisposition = "clear"
	bad.NoteID = stableNoteID(bad)
	if err := ValidateNote(bad, input); err == nil || !strings.Contains(err.Error(), "route override") {
		t.Fatalf("route override was not rejected: %v", err)
	}
}

func TestUnknownCitationRejected(t *testing.T) {
	input := loadFixtureInput(t)
	provider := NewFixtureProvider(input.Profile.DefaultModelID, input)
	invocation, err := Generate(input, provider)
	if err != nil {
		t.Fatal(err)
	}
	bad := invocation.Note
	bad.Claims[0].CitationIDs = []string{"citation_unknown"}
	bad.Claims[0].ClaimID = stableClaimID(bad.Claims[0])
	bad.CitationIDs = append(bad.CitationIDs, "citation_unknown")
	bad.NoteID = stableNoteID(bad)
	if err := ValidateNote(bad, input); err == nil {
		t.Fatal("unknown citation was accepted")
	}
}

func TestOllamaStructuredRequest(t *testing.T) {
	input := loadFixtureInput(t)
	fixture := NewFixtureProvider(input.Profile.DefaultModelID, input)
	prompt, _, err := BuildPrompt(input)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := fixture.Draft(prompt, OutputSchema())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request["stream"] != false || request["format"] == nil {
			t.Fatalf("structured non-streaming request missing: %+v", request)
		}
		message := map[string]any{"message": map[string]string{"content": string(payload)}, "done": true}
		_ = json.NewEncoder(w).Encode(message)
	}))
	defer server.Close()

	provider := NewOllamaProvider(server.URL, input.Profile.DefaultModelID, 5*time.Second)
	raw, err := provider.Draft(prompt, OutputSchema())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, payload) {
		t.Fatal("unexpected Ollama response content")
	}
}
