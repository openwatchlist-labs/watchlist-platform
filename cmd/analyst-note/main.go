package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/analystnote"
	"github.com/openwatchlist-labs/watchlist-platform/internal/policyengine"
	"github.com/openwatchlist-labs/watchlist-platform/internal/rag"
)

func main() {
	decisionBatchPath := flag.String("decision-batch", "", "path to policy decision batch")
	caseID := flag.String("case-id", "", "observation case ID")
	citationPath := flag.String("citations", "", "path to citation package")
	profilePath := flag.String("profile", "", "path to analyst-note profile")
	providerName := flag.String("provider", "fixture", "fixture or ollama")
	modelID := flag.String("model", "", "model ID override")
	ollamaBaseURL := flag.String("ollama-base-url", "http://127.0.0.1:11434", "Ollama base URL")
	timeout := flag.Duration("timeout", 90*time.Second, "model request timeout")
	flag.Parse()
	if *decisionBatchPath == "" || *caseID == "" || *citationPath == "" || *profilePath == "" {
		fatalf("--decision-batch, --case-id, --citations, and --profile are required")
	}
	decision, err := readDecision(*decisionBatchPath, *caseID)
	if err != nil {
		fatalf("read decision: %v", err)
	}
	citations, err := rag.LoadCitationPackage(*citationPath)
	if err != nil {
		fatalf("load citations: %v", err)
	}
	profile, err := analystnote.LoadProfile(*profilePath)
	if err != nil {
		fatalf("load profile: %v", err)
	}
	selectedModel := *modelID
	if selectedModel == "" {
		selectedModel = profile.DefaultModelID
	}
	input := analystnote.DraftInput{Decision: decision, CitationPackage: citations, Profile: profile}
	var provider analystnote.Provider
	switch *providerName {
	case "fixture":
		provider = analystnote.NewFixtureProvider(selectedModel, input)
	case "ollama":
		provider = analystnote.NewOllamaProvider(*ollamaBaseURL, selectedModel, *timeout)
	default:
		fatalf("unknown provider %q", *providerName)
	}
	invocation, err := analystnote.Generate(input, provider)
	if err != nil {
		fatalf("generate analyst note: %v", err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(invocation); err != nil {
		fatalf("encode output: %v", err)
	}
}

func readDecision(path, caseID string) (policyengine.Decision, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return policyengine.Decision{}, err
	}
	var batch policyengine.DecisionBatch
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&batch); err != nil {
		return policyengine.Decision{}, err
	}
	if err := policyengine.ValidateDecisionBatch(batch); err != nil {
		return policyengine.Decision{}, err
	}
	for _, decision := range batch.Decisions {
		if decision.Classification.Observation.CaseID == caseID {
			return decision, nil
		}
	}
	return policyengine.Decision{}, fmt.Errorf("case_id %q not found", caseID)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
