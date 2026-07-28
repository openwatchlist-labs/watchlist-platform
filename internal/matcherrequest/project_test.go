package matcherrequest_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/adapters/iso20022"
	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherrequest"
	"github.com/openwatchlist-labs/watchlist-platform/internal/screening"
	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningplan"
)

func TestProjectBuildsDeterministicMatcherRequests(t *testing.T) {
	bundle := evidenceBundle(t, "pacs008-basic.xml")
	projector := matcherrequest.NewProjector()
	batch, err := projector.Project(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if batch.SchemaVersion != matcherrequest.BatchSchemaVersion {
		t.Fatalf("schema version = %q", batch.SchemaVersion)
	}
	if batch.ProjectorVersion != matcherrequest.ProjectorVersion {
		t.Fatalf("projector version = %q", batch.ProjectorVersion)
	}
	if batch.InputEvidenceBundleID != bundle.BundleID {
		t.Fatalf("input bundle = %q want %q", batch.InputEvidenceBundleID, bundle.BundleID)
	}
	if len(batch.Requests) != bundle.Summary.MatchEligibleElements || len(batch.Requests) != 30 {
		t.Fatalf("requests = %d eligible = %d", len(batch.Requests), bundle.Summary.MatchEligibleElements)
	}
	if batch.Summary.CandidateAlertRequests != 14 || batch.Summary.SupportingEvidenceRequests != 16 || batch.Summary.TransactionCount != 1 {
		t.Fatalf("summary = %#v", batch.Summary)
	}
	if err := matcherrequest.ValidateBatch(batch); err != nil {
		t.Fatal(err)
	}
	again, err := projector.Project(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(batch, again) {
		t.Fatal("projection is not deterministic")
	}

	debtor := requestByRole(t, batch, canonical.SemanticRole("debtor.name"))
	if debtor.RequestKind != matcherrequest.RequestCandidateAlert || debtor.TriggerPolicy != canonical.TriggerCandidateAlert {
		t.Fatalf("debtor request kind = %#v", debtor)
	}
	if debtor.Query.NormalizedValue != "ACME IMPORTS LLC" {
		t.Fatalf("debtor query = %q", debtor.Query.NormalizedValue)
	}
	if debtor.SourceLineage.EvidenceBundleID != bundle.BundleID || debtor.SourceLineage.EvidenceID == "" || debtor.SourceLineage.ElementID == "" {
		t.Fatalf("debtor lineage = %#v", debtor.SourceLineage)
	}
	if !reflect.DeepEqual(debtor.SourceLineage.ScreeningPlan, bundle.ScreeningPlan) {
		t.Fatal("debtor plan lineage differs from evidence bundle")
	}
	for _, request := range batch.Requests {
		if request.SemanticRole == canonical.SemanticRole("payment.transaction_id") {
			t.Fatal("retain-only payment transaction ID was projected")
		}
	}
}

func TestProjectionSkipsEmptyAndInvalidEvidence(t *testing.T) {
	projector := matcherrequest.NewProjector()
	emptyBundle := evidenceBundle(t, "pacs008-empty-name.xml")
	emptyBatch, err := projector.Project(emptyBundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range emptyBatch.Requests {
		if request.Query.NormalizedValue == "" {
			t.Fatalf("empty query projected: %#v", request)
		}
	}

	message, executor := messageAndExecutor(t, "pacs008-basic.xml")
	var changed bool
	for index := range message.Elements {
		if message.Elements[index].SemanticRole == canonical.SemanticRole("debtor_agent.bic") {
			message.Elements[index].Presence = canonical.PresenceInvalid
			message.Elements[index].Warnings = []canonical.ParserWarning{{
				Code: "invalid_bic", Severity: canonical.SeverityWarning, Message: "test", Path: message.Elements[index].NativePath,
			}}
			changed = true
			break
		}
	}
	if !changed {
		t.Fatal("debtor-agent BIC not found")
	}
	invalidBundle, err := executor.Execute(message)
	if err != nil {
		t.Fatal(err)
	}
	invalidBatch, err := projector.Project(invalidBundle)
	if err != nil {
		t.Fatal(err)
	}
	if invalidBatch.Summary.TotalRequests != 29 {
		t.Fatalf("invalid-value requests = %d, want 29", invalidBatch.Summary.TotalRequests)
	}
	for _, request := range invalidBatch.Requests {
		if request.SemanticRole == canonical.SemanticRole("debtor_agent.bic") {
			t.Fatal("invalid BIC was projected")
		}
	}
}

func TestProjectRejectsTamperedEvidenceBundle(t *testing.T) {
	bundle := evidenceBundle(t, "pacs008-basic.xml")
	bundle.BundleID = "bundle_tampered"
	_, err := matcherrequest.NewProjector().Project(bundle)
	if !errors.Is(err, matcherrequest.ErrProjection) {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateBatchRejectsRequestDrift(t *testing.T) {
	batch, err := matcherrequest.NewProjector().Project(evidenceBundle(t, "pacs008-basic.xml"))
	if err != nil {
		t.Fatal(err)
	}
	batch.Requests[0].Query.NormalizedValue += " DRIFT"
	if err := matcherrequest.ValidateBatch(batch); !errors.Is(err, matcherrequest.ErrInvalidRequestBatch) {
		t.Fatalf("error = %v", err)
	}
}

func TestReplayEnvelopePreservesProjectionContractAndLineage(t *testing.T) {
	bundle := evidenceBundle(t, "pacs008-basic.xml")
	projector := matcherrequest.NewProjector()
	replay, err := projector.Replay(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if replay.SchemaVersion != matcherrequest.ReplaySchemaVersion || replay.ReplayID == "" {
		t.Fatalf("replay identity = %#v", replay)
	}
	if replay.ProjectionContract.SelectionPolicy != "eligible_for_matching_only" || replay.ProjectionContract.OrderingPolicy != "evidence_order" {
		t.Fatalf("projection contract = %#v", replay.ProjectionContract)
	}
	if replay.Input.EvidenceBundleID != bundle.BundleID || replay.RequestBatch.InputEvidenceBundleID != bundle.BundleID {
		t.Fatalf("replay lineage = %#v", replay.Input)
	}
	if err := matcherrequest.ValidateReplay(replay); err != nil {
		t.Fatal(err)
	}
	again, err := projector.Replay(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(replay, again) {
		t.Fatal("replay envelope is not deterministic")
	}
	replay.Input.ScreeningPlan.PlanChecksum = "drift"
	if err := matcherrequest.ValidateReplay(replay); !errors.Is(err, matcherrequest.ErrInvalidReplayEnvelope) {
		t.Fatalf("error = %v", err)
	}
}

func TestPersistedEvidenceReprojectsIdentically(t *testing.T) {
	path := filepath.Join(repoRoot(t), "test", "golden", "iso20022", "pacs008", "pacs008-basic.evidence.json")
	input, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	var persisted screening.EvidenceBundle
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&persisted); err != nil {
		t.Fatal(err)
	}
	projector := matcherrequest.NewProjector()
	fromPersisted, err := projector.Project(persisted)
	if err != nil {
		t.Fatal(err)
	}
	fromXML, err := projector.Project(evidenceBundle(t, "pacs008-basic.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromPersisted, fromXML) {
		t.Fatal("persisted evidence and XML projection differ")
	}
}

func TestMatcherRequestGoldenFiles(t *testing.T) {
	cases := []struct {
		fixture string
		kind    string
		golden  string
	}{
		{"pacs008-basic.xml", "requests", "pacs008-basic.matcher-requests.json"},
		{"pacs008-basic.xml", "replay", "pacs008-basic.replay.json"},
		{"pacs008-multi-transaction.xml", "requests", "pacs008-multi-transaction.matcher-requests.json"},
	}
	projector := matcherrequest.NewProjector()
	for _, test := range cases {
		t.Run(test.golden, func(t *testing.T) {
			bundle := evidenceBundle(t, test.fixture)
			var value any
			var err error
			if test.kind == "requests" {
				value, err = projector.Project(bundle)
			} else {
				value, err = projector.Replay(bundle)
			}
			if err != nil {
				t.Fatal(err)
			}
			actual, err := json.MarshalIndent(value, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			actual = append(actual, '\n')
			path := filepath.Join(repoRoot(t), "test", "golden", "iso20022", "pacs008", test.golden)
			expected, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(actual) != string(expected) {
				t.Fatalf("golden mismatch for %s; regenerate only after intentional contract review", path)
			}
		})
	}
}

func evidenceBundle(t *testing.T, fixture string) screening.EvidenceBundle {
	t.Helper()
	message, executor := messageAndExecutor(t, fixture)
	bundle, err := executor.Execute(message)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func messageAndExecutor(t *testing.T, fixture string) (canonical.ParsedMessage, *screening.Executor) {
	t.Helper()
	planFile, err := os.Open(filepath.Join(repoRoot(t), "configs", "screening-plans", "iso20022-pacs008-cbprplus-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer planFile.Close()
	plan, err := screeningplan.Load(planFile)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := screeningplan.Compile(plan)
	if err != nil {
		t.Fatal(err)
	}
	parser, err := iso20022.NewParser(compiled)
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(filepath.Join(repoRoot(t), "test", "fixtures", "iso20022", "pacs008", fixture))
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	message, err := parser.Parse("fixture:"+fixture, input)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := screening.NewExecutor(compiled)
	if err != nil {
		t.Fatal(err)
	}
	return message, executor
}

func requestByRole(t *testing.T, batch matcherrequest.RequestBatch, role canonical.SemanticRole) matcherrequest.CandidateSearchRequest {
	t.Helper()
	for _, request := range batch.Requests {
		if request.SemanticRole == role {
			return request
		}
	}
	t.Fatalf("role %q not found", role)
	return matcherrequest.CandidateSearchRequest{}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	current, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			t.Fatal("repository root not found")
		}
		current = parent
	}
}
