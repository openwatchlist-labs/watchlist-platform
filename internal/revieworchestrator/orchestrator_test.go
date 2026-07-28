package revieworchestrator

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/analystnote"
	"github.com/openwatchlist-labs/watchlist-platform/internal/falsepositive"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
	"github.com/openwatchlist-labs/watchlist-platform/internal/policyengine"
	"github.com/openwatchlist-labs/watchlist-platform/internal/rag"
)

const entityTypeCase = "candidate_result_c75fde262447f82adf98ccb2:diagnostic:entity_type_mismatch:ofac:sdn:3003"

func TestReviewRunDeterministicBundle(t *testing.T) {
	orchestrator, results := testOrchestrator(t, "fixture")
	options := RunOptions{TenantID: "tenant-a", EffectiveAt: "2026-07-14T12:00:00Z", SourceReference: "golden:phase3a-fuzzy-results", CaseID: entityTypeCase}
	first, err := orchestrator.Run(results, options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := orchestrator.Run(results, options)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("review replay differs")
	}
	if first.Summary.TotalCases != 1 || first.Summary.InvestigateCases != 1 || first.Summary.NotesGenerated != 1 {
		t.Fatalf("unexpected summary: %+v", first.Summary)
	}
	c := first.Cases[0]
	if c.Disposition != policyengine.DispositionInvestigate || c.ReviewRoute != policyengine.ReviewRouteStandardReview || c.RetrievalStatus != RetrievalCompleted || c.NoteStatus != NoteGenerated {
		t.Fatalf("unexpected case: %+v", c)
	}
	if c.AnalystInvocation.Note.DeterministicDisposition != string(c.Disposition) || c.AnalystInvocation.Note.ReviewRoute != string(c.ReviewRoute) {
		t.Fatal("analyst note changed deterministic route")
	}
	if err := ValidateRunBundle(first); err != nil {
		t.Fatal(err)
	}
}

func TestReviewRunFailSoftNoteProvider(t *testing.T) {
	orchestrator, results := testOrchestrator(t, "failing")
	bundle, err := orchestrator.Run(results, RunOptions{TenantID: "tenant-a", EffectiveAt: "2026-07-14T12:00:00Z", SourceReference: "failure-test", CaseID: entityTypeCase})
	if err != nil {
		t.Fatal(err)
	}
	c := bundle.Cases[0]
	if c.NoteStatus != NoteGenerationFailed || c.AnalystInvocation != nil || c.Disposition != policyengine.DispositionInvestigate {
		t.Fatalf("unexpected fail-soft case: %+v", c)
	}
	if err := ValidateRunBundle(bundle); err != nil {
		t.Fatal(err)
	}
}

func TestReviewRunAuditTamperRejected(t *testing.T) {
	orchestrator, results := testOrchestrator(t, "disabled")
	bundle, err := orchestrator.Run(results, RunOptions{TenantID: "tenant-a", EffectiveAt: "2026-07-14T12:00:00Z", SourceReference: "tamper-test", CaseID: entityTypeCase})
	if err != nil {
		t.Fatal(err)
	}
	bundle.AuditEvents[2].PayloadDigest = "00" + bundle.AuditEvents[2].PayloadDigest[2:]
	if err := ValidateRunBundle(bundle); err == nil {
		t.Fatal("tampered audit event accepted")
	}
}

func TestReviewRunGolden(t *testing.T) {
	orchestrator, results := testOrchestrator(t, "fixture")
	bundle, err := orchestrator.Run(results, RunOptions{TenantID: "tenant-a", EffectiveAt: "2026-07-14T12:00:00Z", SourceReference: "golden:phase3a-fuzzy-results", CaseID: entityTypeCase})
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(bundle); err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()
	path := root("test/golden/review/entity-type-review-run.json")
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("golden differs; regenerate %s", path)
	}
}

type failingProvider struct{}

func (f failingProvider) Name() string    { return "failing" }
func (f failingProvider) ModelID() string { return "fixture/failing" }
func (f failingProvider) Draft(string, map[string]any) ([]byte, error) {
	return nil, errors.New("synthetic provider failure")
}

func testOrchestrator(t *testing.T, mode string) (*Orchestrator, matcherprovider.ResultBatch) {
	t.Helper()
	var results matcherprovider.ResultBatch
	decodeFile(t, root("test/golden/matcher-baseline/pacs008-fuzzy-names.results.json"), &results)
	library, err := falsepositive.LoadPatternLibrary(root("configs/false-positive-patterns/baseline-r1.json"))
	if err != nil {
		t.Fatal(err)
	}
	counter, err := falsepositive.LoadCountervailingPolicy(root("configs/false-positive-patterns/countervailing-evidence-r1.json"))
	if err != nil {
		t.Fatal(err)
	}
	classifier, err := falsepositive.NewClassifier(library, counter)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := policyengine.LoadPolicy(root("configs/policies/transaction-screening-r1.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := policyengine.NewEngine(policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := rag.LoadSnapshot(root("test/golden/rag/corpus-snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	retrievalPolicy, err := rag.LoadPolicy(root("configs/rag/retrieval-policy-r1.json"))
	if err != nil {
		t.Fatal(err)
	}
	retriever, err := rag.NewRetriever(snapshot, retrievalPolicy)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := analystnote.LoadProfile(root("configs/models/granite-analyst-note-r1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var factory NoteProviderFactory
	switch mode {
	case "fixture":
		factory = func(input analystnote.DraftInput) analystnote.Provider {
			return analystnote.NewFixtureProvider(profile.DefaultModelID, input)
		}
	case "failing":
		factory = func(analystnote.DraftInput) analystnote.Provider { return failingProvider{} }
	case "disabled":
		factory = nil
	}
	o, err := New(classifier, engine, retriever, profile, factory)
	if err != nil {
		t.Fatal(err)
	}
	return o, results
}
func root(path string) string { return filepath.Join("..", "..", path) }
func decodeFile(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		t.Fatal(err)
	}
}
