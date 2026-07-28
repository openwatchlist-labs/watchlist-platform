package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/analystnote"
	"github.com/openwatchlist-labs/watchlist-platform/internal/falsepositive"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
	"github.com/openwatchlist-labs/watchlist-platform/internal/policyengine"
	"github.com/openwatchlist-labs/watchlist-platform/internal/rag"
	"github.com/openwatchlist-labs/watchlist-platform/internal/revieworchestrator"
)

func main() {
	patternLibrary := flag.String("pattern-library", "configs/false-positive-patterns/baseline-r1.json", "false-positive pattern library")
	countervailingPolicy := flag.String("countervailing-policy", "configs/false-positive-patterns/countervailing-evidence-r1.json", "countervailing evidence policy")
	policyPath := flag.String("policy", "configs/policies/transaction-screening-r1.yaml", "transaction-screening policy")
	overlayPath := flag.String("overlay", "", "optional tenant policy overlay")
	snapshotPath := flag.String("snapshot", "test/golden/rag/corpus-snapshot.json", "immutable RAG corpus snapshot")
	retrievalPolicyPath := flag.String("retrieval-policy", "configs/rag/retrieval-policy-r1.json", "RAG retrieval policy")
	profilePath := flag.String("analyst-profile", "configs/models/granite-analyst-note-r1.json", "analyst-note profile")
	noteProvider := flag.String("note-provider", "fixture", "analyst-note provider: fixture, ollama, or disabled")
	ollamaBaseURL := flag.String("ollama-base-url", "http://ollama:11434", "Ollama base URL")
	tenantID := flag.String("tenant-id", "tenant-a", "tenant identifier")
	effectiveAt := flag.String("effective-at", "2026-07-14T12:00:00Z", "RFC3339 retrieval effective time")
	sourceReference := flag.String("source-reference", "review-run-cli", "source reference for matcher-result adaptation")
	caseID := flag.String("case-id", "", "optional exact adapted observation case ID")
	flag.Parse()
	if flag.NArg() != 1 {
		fatalf("usage: review-run [flags] <matcher-result-batch.json>")
	}

	var results matcherprovider.ResultBatch
	data, err := os.ReadFile(flag.Arg(0))
	check(err, "read matcher results")
	check(decodeStrict(data, &results), "decode matcher results")
	library, err := falsepositive.LoadPatternLibrary(*patternLibrary)
	check(err, "load pattern library")
	counter, err := falsepositive.LoadCountervailingPolicy(*countervailingPolicy)
	check(err, "load countervailing policy")
	classifier, err := falsepositive.NewClassifier(library, counter)
	check(err, "create classifier")
	policy, err := policyengine.LoadPolicy(*policyPath)
	check(err, "load policy")
	var overlay *policyengine.Overlay
	if *overlayPath != "" {
		value, err := policyengine.LoadOverlay(*overlayPath, policy)
		check(err, "load overlay")
		overlay = &value
	}
	engine, err := policyengine.NewEngine(policy, overlay)
	check(err, "create policy engine")
	snapshot, err := rag.LoadSnapshot(*snapshotPath)
	check(err, "load corpus snapshot")
	retrievalPolicy, err := rag.LoadPolicy(*retrievalPolicyPath)
	check(err, "load retrieval policy")
	retriever, err := rag.NewRetriever(snapshot, retrievalPolicy)
	check(err, "create retriever")
	profile, err := analystnote.LoadProfile(*profilePath)
	check(err, "load analyst profile")

	var factory revieworchestrator.NoteProviderFactory
	switch *noteProvider {
	case "fixture":
		factory = func(input analystnote.DraftInput) analystnote.Provider {
			return analystnote.NewFixtureProvider(profile.DefaultModelID, input)
		}
	case "ollama":
		provider := analystnote.NewOllamaProvider(*ollamaBaseURL, profile.DefaultModelID, 90*time.Second)
		factory = func(analystnote.DraftInput) analystnote.Provider { return provider }
	case "disabled":
		factory = nil
	default:
		fatalf("unsupported --note-provider %q", *noteProvider)
	}
	orchestrator, err := revieworchestrator.New(classifier, engine, retriever, profile, factory)
	check(err, "create orchestrator")
	bundle, err := orchestrator.Run(results, revieworchestrator.RunOptions{TenantID: *tenantID, EffectiveAt: *effectiveAt, SourceReference: *sourceReference, CaseID: *caseID})
	check(err, "run review")
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	check(encoder.Encode(bundle), "encode review bundle")
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	return nil
}
func check(err error, action string) {
	if err != nil {
		fatalf("%s: %v", action, err)
	}
}
func fatalf(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(1) }
