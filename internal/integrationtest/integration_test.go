// Package integrationtest exercises the real screening -> review chain
// end to end, addressing issue #16: every individual package
// (matcherbaseline, falsepositive, policyengine, rag, analystnote,
// revieworchestrator, alertcase) has its own solid unit tests against
// its own fixtures in isolation, but nothing previously exercised the
// real chain between them together.
//
// Scope and honesty about what this does and doesn't prove: issue #16's
// text describes the chain as
// "screening-api -> matcherbaseline -> candidatescoring -> falsepositive
// -> alertcase -> revieworchestrator." That's not quite the real
// production wiring in either direction this project has actually
// built:
//   - docs/ARCHITECTURE.md documents the real production request
//     lifecycle as vendoradapter -> alertcase -> runtimemmapclient (Rust)
//     -> candidatescoring -> falsepositive -> policyengine ->
//     revieworchestrator -> reviewconsole - alertcase comes BEFORE
//     matching, not after, and candidatescoring is a separate real-time
//     scoring path, not something revieworchestrator.Orchestrator.Run
//     calls internally.
//   - cmd/review-run (this project's own existing CLI) already proves
//     the chain matcherprovider.ResultBatch -> falsepositive ->
//     policyengine -> rag -> analystnote -> revieworchestrator works
//     together, all internally wired by Orchestrator.Run itself - this
//     test does the same wiring via direct Go function calls for the
//     falsepositive/policyengine/rag/revieworchestrator stages instead
//     of the CLI/subprocess layer, which is faster and better at
//     catching the exact class of bug #16 is worried about (a field
//     meaning something slightly different across a package boundary),
//     since intermediate values can be inspected directly in Go.
//   - Current production cmd/screening-api cannot be exercised here at
//     all - it needs the Rust catalog-mmap runtime, unavailable in this
//     environment (see issue #13).
//   - Generating the starting matcherprovider.ResultBatch itself is done
//     by actually running cmd/matcher-run as a real subprocess against
//     real fixtures, rather than hand-constructing a ResultBatch value
//     in Go. ResultBatch turned out to be considerably more deeply
//     nested than a first attempt at hand-constructing it assumed
//     (CandidateSearchResult uses a distinct CandidateMatch type, not
//     the ProviderCandidate type matcherbaseline.Provider.Search
//     returns; there's a RequestLineage and a ResultStatus enum with no
//     obvious "just fill in the request ID" shortcut) - reusing the
//     already-proven, already-tested matcher-run code path eliminates
//     that entire risk surface rather than duplicating and likely
//     getting wrong a decent chunk of matcherprovider's own internal
//     construction logic.
//
// What this DOES prove, concretely: running the real matcher-run binary
// against real OFAC SDN fixture data produces a real, valid
// matcherprovider.ResultBatch; that batch drives a real
// revieworchestrator.Run producing a classification, a policy decision,
// and a generated analyst note, with each stage's real output type
// consumed correctly by the next; and, separately, that
// internal/alertcase.Store accepts a request using the SAME tenant_id as
// the orchestrator run, proving at least that specific identifier
// convention is consistent across that package boundary too.
package integrationtest

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertcase"
	"github.com/openwatchlist-labs/watchlist-platform/internal/analystnote"
	"github.com/openwatchlist-labs/watchlist-platform/internal/falsepositive"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
	"github.com/openwatchlist-labs/watchlist-platform/internal/policyengine"
	"github.com/openwatchlist-labs/watchlist-platform/internal/rag"
	"github.com/openwatchlist-labs/watchlist-platform/internal/revieworchestrator"
)

const tenantID = "tenant-a"

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

// realResultBatch runs cmd/matcher-run - this project's own existing,
// already-tested tool, documented as the quickstart in
// docs/TEST_DATA.md - against real committed fixtures to produce a real,
// guaranteed-structurally-valid matcherprovider.ResultBatch, rather than
// hand-constructing one.
func realResultBatch(t *testing.T) matcherprovider.ResultBatch {
	t.Helper()
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "matcher-run")
	build := exec.Command("go", "build", "-o", binPath, "./cmd/matcher-run")
	build.Dir = repoRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("failed to build cmd/matcher-run (prerequisite): %v\n%s", err, out)
	}

	cmd := exec.Command(binPath,
		"-provider", "ofac-baseline",
		"-catalog", "test/golden/ofac/ofac-sdn-fixture.runtime.owpcat",
		"-matcher-profiles", "configs/matcher-profiles/ofac-name-baseline-r1.json",
		"-input", "requests", "-output", "results",
		"test/golden/iso20022/pacs008/pacs008-basic.matcher-requests.json")
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("cmd/matcher-run failed: %v", err)
	}

	var batch matcherprovider.ResultBatch
	if err := decodeStrict(out, &batch); err != nil {
		t.Fatalf("decode matcher-run output as ResultBatch: %v", err)
	}
	if len(batch.Results) == 0 {
		t.Fatal("expected at least one result in the batch produced by matcher-run")
	}
	return batch
}

// TestScreeningToReviewFlow exercises the real chain: a real matcher-run
// invocation -> revieworchestrator.Run (which internally chains
// falsepositive classification, policyengine decisioning, rag retrieval,
// and analyst-note generation) -> assertions on the real, typed output
// at each stage, not just "no error returned."
func TestScreeningToReviewFlow(t *testing.T) {
	resultBatch := realResultBatch(t)

	library, err := falsepositive.LoadPatternLibrary("../../configs/false-positive-patterns/baseline-r1.json")
	if err != nil {
		t.Fatalf("load false-positive pattern library: %v", err)
	}
	countervailing, err := falsepositive.LoadCountervailingPolicy("../../configs/false-positive-patterns/countervailing-evidence-r1.json")
	if err != nil {
		t.Fatalf("load countervailing evidence policy: %v", err)
	}
	classifier, err := falsepositive.NewClassifier(library, countervailing)
	if err != nil {
		t.Fatalf("construct false-positive classifier: %v", err)
	}

	policy, err := policyengine.LoadPolicy("../../configs/policies/transaction-screening-r1.yaml")
	if err != nil {
		t.Fatalf("load transaction-screening policy: %v", err)
	}
	engine, err := policyengine.NewEngine(policy, nil)
	if err != nil {
		t.Fatalf("construct policy engine: %v", err)
	}

	snapshot, err := rag.LoadSnapshot("../../test/golden/rag/corpus-snapshot.json")
	if err != nil {
		t.Fatalf("load RAG corpus snapshot: %v", err)
	}
	retrievalPolicy, err := rag.LoadPolicy("../../configs/rag/retrieval-policy-r1.json")
	if err != nil {
		t.Fatalf("load RAG retrieval policy: %v", err)
	}
	retriever, err := rag.NewRetriever(snapshot, retrievalPolicy)
	if err != nil {
		t.Fatalf("construct RAG retriever: %v", err)
	}

	profile, err := analystnote.LoadProfile("../../configs/models/granite-analyst-note-r1.json")
	if err != nil {
		t.Fatalf("load analyst-note profile: %v", err)
	}
	// "fixture" provider throughout - no live Ollama instance needed,
	// matching every other analyst-note test in this project.
	factory := func(input analystnote.DraftInput) analystnote.Provider {
		return analystnote.NewFixtureProvider(profile.DefaultModelID, input)
	}

	orchestrator, err := revieworchestrator.New(classifier, engine, retriever, profile, factory)
	if err != nil {
		t.Fatalf("construct review orchestrator: %v", err)
	}

	bundle, err := orchestrator.Run(resultBatch, revieworchestrator.RunOptions{
		TenantID:        tenantID,
		EffectiveAt:     time.Now().UTC().Format(time.RFC3339),
		SourceReference: "integration-test",
	})
	if err != nil {
		t.Fatalf("orchestrator.Run failed: %v", err)
	}

	// Assertions on real, typed output at each boundary - not just "no
	// error." This is the specific class of check issue #16 asked for:
	// does the real end-to-end outcome make sense given a known input,
	// not just "did each stage individually not crash."
	if bundle.TenantID != tenantID {
		t.Errorf("expected bundle.TenantID %q, got %q - tenant_id should propagate unchanged through the whole chain", tenantID, bundle.TenantID)
	}
	if len(bundle.Classifications.Classifications) == 0 {
		t.Fatal("expected at least one false-positive classification in the bundle")
	}
	if len(bundle.Decisions.Decisions) == 0 {
		t.Fatal("expected at least one policy decision in the bundle")
	}
	if len(bundle.Cases) == 0 {
		t.Fatal("expected at least one case bundle - a real registered-alias match should produce a reviewable case, not silently disappear")
	}
	if len(bundle.AuditEvents) == 0 {
		t.Error("expected at least one audit event recorded for this run")
	}

	// Also close the loop with alertcase specifically, per issue #16's
	// own explicit mention of it: a real alertcase.Store accepts a
	// request using the SAME tenant_id this orchestrator run used,
	// proving that identifier convention is consistent across this
	// package boundary too. Uses the real, already-proven
	// test/fixtures/alert-case/create-alert.request.json fixture rather
	// than hand-deriving a ScreeningEvent payload from the bundle above -
	// alertcase is the real production ENTRY POINT before matching, not
	// something fed FROM revieworchestrator's output (see
	// docs/ARCHITECTURE.md), so deriving one from the other here would
	// misrepresent the real wiring rather than clarify it.
	verifyAlertCaseAcceptsSameTenant(t)
}

func verifyAlertCaseAcceptsSameTenant(t *testing.T) {
	t.Helper()
	alertPolicy, err := alertcase.LoadPolicy("../../test/fixtures/alert-case/policy.json")
	if err != nil {
		t.Fatalf("load alert-case policy: %v", err)
	}
	store, err := alertcase.NewStore(t.TempDir(), alertPolicy, "integration-test-stream")
	if err != nil {
		t.Fatalf("construct alert-case store: %v", err)
	}
	requestBytes, err := os.ReadFile("../../test/fixtures/alert-case/create-alert.request.json")
	if err != nil {
		t.Fatalf("read create-alert request fixture: %v", err)
	}
	var req alertcase.CreateAlertRequest
	if err := decodeStrict(requestBytes, &req); err != nil {
		t.Fatalf("decode create-alert request fixture: %v", err)
	}
	if req.TenantID != tenantID {
		t.Fatalf("test fixture assumption violated: expected the alert-case fixture's tenant_id to be %q (matching the orchestrator run above), got %q - if the fixture changed, update this test's tenantID constant to match, don't just relax this check", tenantID, req.TenantID)
	}
	alertRecord, replayed, err := store.CreateAlert(req)
	if err != nil {
		t.Fatalf("alertcase.Store.CreateAlert failed: %v", err)
	}
	if replayed {
		t.Error("expected a fresh alert on the first call against a brand-new store, not a replay")
	}
	if alertRecord.TenantID != tenantID {
		t.Errorf("expected created alert's tenant_id to be %q, got %q", tenantID, alertRecord.TenantID)
	}
}
