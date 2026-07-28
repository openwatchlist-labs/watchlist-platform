package matcherprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherrequest"
)

func TestFixtureProviderExecutionIsDeterministic(t *testing.T) {
	provider := loadTestFixtureProvider(t)
	runner, err := NewRunner(provider)
	if err != nil {
		t.Fatal(err)
	}
	batch := loadRequestBatch(t)
	first, err := runner.Execute(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	second, err := runner.Execute(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("provider execution is not deterministic")
	}
	if first.Summary.TotalRequests != 30 || len(first.Results) != 30 {
		t.Fatalf("unexpected request result count: summary=%d results=%d", first.Summary.TotalRequests, len(first.Results))
	}
	if first.Summary.MatchedRequests == 0 || first.Summary.NoCandidateRequests == 0 || first.Summary.TotalCandidates == 0 {
		t.Fatalf("expected both matched and no-candidate results: %+v", first.Summary)
	}
	if err := ValidateResultBatch(first); err != nil {
		t.Fatal(err)
	}
	for _, result := range first.Results {
		if result.Request.SourceLineage.ScreeningPlan.PlanChecksum == "" {
			t.Fatalf("result %s lost screening-plan lineage", result.ResultID)
		}
		if result.Provider.Catalog.CatalogChecksum != first.Provider.Catalog.CatalogChecksum {
			t.Fatalf("result %s lost catalog lineage", result.ResultID)
		}
	}
}

func TestProviderReplayPreservesInputRequestLineage(t *testing.T) {
	provider := loadTestFixtureProvider(t)
	runner, err := NewRunner(provider)
	if err != nil {
		t.Fatal(err)
	}
	input := loadRequestReplay(t)
	envelope, err := runner.Replay(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateProviderReplay(envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.ResultBatch.InputRequestBatchID != input.RequestBatch.BatchID {
		t.Fatal("provider replay did not preserve input request batch identity")
	}
	for index, request := range input.RequestBatch.Requests {
		if !reflect.DeepEqual(envelope.ResultBatch.Results[index].Request, requestLineage(request)) {
			t.Fatalf("request lineage drift at index %d", index)
		}
	}
}

func TestRunnerCanonicalizesProviderCandidateOrder(t *testing.T) {
	batch := loadRequestBatch(t)
	firstRequestID := batch.Requests[0].RequestID
	provider := stubProvider{
		descriptor: loadTestFixtureProvider(t).Descriptor(),
		search: func(_ context.Context, request matcherrequest.CandidateSearchRequest) ([]ProviderCandidate, error) {
			if request.RequestID != firstRequestID {
				return nil, nil
			}
			return []ProviderCandidate{
				testCandidate("record-b", 9000),
				testCandidate("record-a", 10000),
			}, nil
		},
	}
	runner, err := NewRunner(provider)
	if err != nil {
		t.Fatal(err)
	}
	output, err := runner.Execute(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	candidates := output.Results[0].Candidates
	if candidates[0].ProviderRecordID != "record-a" || candidates[1].ProviderRecordID != "record-b" {
		t.Fatalf("unexpected canonical order: %s, %s", candidates[0].ProviderRecordID, candidates[1].ProviderRecordID)
	}
	if output.Results[0].Request.RequestID != firstRequestID {
		t.Fatal("request identity changed")
	}
}

func TestRunnerRejectsDuplicateProviderCandidates(t *testing.T) {
	batch := loadRequestBatch(t)
	firstRequestID := batch.Requests[0].RequestID
	candidate := testCandidate("record-a", 10000)
	provider := stubProvider{
		descriptor: loadTestFixtureProvider(t).Descriptor(),
		search: func(_ context.Context, request matcherrequest.CandidateSearchRequest) ([]ProviderCandidate, error) {
			if request.RequestID == firstRequestID {
				return []ProviderCandidate{candidate, candidate}, nil
			}
			return nil, nil
		},
	}
	runner, err := NewRunner(provider)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Execute(context.Background(), batch); !errors.Is(err, ErrProviderExecution) {
		t.Fatalf("expected duplicate candidate rejection, got %v", err)
	}
}

func TestRunnerRejectsUnsupportedRequestRoute(t *testing.T) {
	batch := loadRequestBatch(t)
	provider := stubProvider{
		descriptor: testDescriptor([]canonical.MatchRoute{canonical.RouteExactBIC}, []canonical.CandidateType{canonical.CandidateOrganization}),
		search: func(context.Context, matcherrequest.CandidateSearchRequest) ([]ProviderCandidate, error) {
			t.Fatal("search must not be called for an incompatible request")
			return nil, nil
		},
	}
	runner, err := NewRunner(provider)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Execute(context.Background(), batch); !errors.Is(err, ErrProviderExecution) {
		t.Fatalf("expected route compatibility rejection, got %v", err)
	}
}

func TestProviderExecutionIsAtomicOnProviderError(t *testing.T) {
	batch := loadRequestBatch(t)
	provider := stubProvider{
		descriptor: loadTestFixtureProvider(t).Descriptor(),
		search: func(context.Context, matcherrequest.CandidateSearchRequest) ([]ProviderCandidate, error) {
			return nil, errors.New("synthetic provider failure")
		},
	}
	runner, err := NewRunner(provider)
	if err != nil {
		t.Fatal(err)
	}
	output, err := runner.Execute(context.Background(), batch)
	if !errors.Is(err, ErrProviderExecution) {
		t.Fatalf("expected atomic provider error, got %v", err)
	}
	if !reflect.DeepEqual(output, ResultBatch{}) {
		t.Fatal("provider error returned a partial result batch")
	}
}

func TestValidateResultBatchRejectsCandidateDrift(t *testing.T) {
	provider := loadTestFixtureProvider(t)
	runner, err := NewRunner(provider)
	if err != nil {
		t.Fatal(err)
	}
	output, err := runner.Execute(context.Background(), loadRequestBatch(t))
	if err != nil {
		t.Fatal(err)
	}
	for resultIndex := range output.Results {
		if len(output.Results[resultIndex].Candidates) == 0 {
			continue
		}
		output.Results[resultIndex].Candidates[0].PrimaryName += " DRIFT"
		if err := ValidateResultBatch(output); !errors.Is(err, ErrInvalidResultBatch) {
			t.Fatalf("expected candidate drift rejection, got %v", err)
		}
		return
	}
	t.Fatal("fixture produced no candidate to mutate")
}

func TestFixtureCatalogRejectsUnknownFields(t *testing.T) {
	data, err := os.ReadFile("../../test/fixtures/providers/synthetic/synthetic-catalog-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	document["unexpected"] = true
	data, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFixtureProvider(bytes.NewReader(data)); !errors.Is(err, ErrInvalidFixtureCatalog) {
		t.Fatalf("expected strict fixture JSON rejection, got %v", err)
	}
}

func TestProviderEntityCatalogRequiresEntityIDs(t *testing.T) {
	data, err := os.ReadFile("../../test/fixtures/providers/synthetic/synthetic-catalog-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var catalog FixtureCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		t.Fatal(err)
	}
	catalog.Records[0].ProviderEntityID = ""
	data, err = json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFixtureProvider(bytes.NewReader(data)); !errors.Is(err, ErrInvalidFixtureCatalog) {
		t.Fatalf("expected missing provider entity ID rejection, got %v", err)
	}
}

type stubProvider struct {
	descriptor ProviderDescriptor
	search     func(context.Context, matcherrequest.CandidateSearchRequest) ([]ProviderCandidate, error)
}

func (provider stubProvider) Descriptor() ProviderDescriptor { return provider.descriptor }
func (provider stubProvider) Search(ctx context.Context, request matcherrequest.CandidateSearchRequest) ([]ProviderCandidate, error) {
	return provider.search(ctx, request)
}

func testDescriptor(routes []canonical.MatchRoute, types []canonical.CandidateType) ProviderDescriptor {
	return ProviderDescriptor{
		SchemaVersion:   ProviderDescriptorSchemaVersion,
		ProviderID:      "test-provider",
		ProviderVersion: "v1",
		Catalog: CatalogReference{
			CatalogID:       "test-catalog",
			CatalogVersion:  "v1",
			CatalogChecksum: strings.Repeat("a", 64),
			CatalogMode:     CatalogModeProviderEntity,
		},
		Capabilities: ProviderCapabilities{
			SupportedRoutes:          routes,
			SupportedEntityTypes:     types,
			MaxCandidatesPerRequest:  10,
			Deterministic:            true,
			SourceAssertionsIncluded: true,
		},
	}
}

func testCandidate(recordID string, score int) ProviderCandidate {
	return ProviderCandidate{
		ProviderRecordID:       recordID,
		ProviderEntityID:       "entity-" + recordID,
		EntityType:             canonical.CandidateOrganization,
		PrimaryName:            "ACME IMPORTS LLC",
		MatchedValue:           "ACME IMPORTS LLC",
		NormalizedMatchedValue: "ACME IMPORTS LLC",
		MatchRoute:             canonical.RouteNormalizedName,
		ScoreBasisPoints:       score,
		Exact:                  true,
		SourceAssertions: []SourceAssertion{{
			SourceID:       "test-source",
			Authority:      "Test Authority",
			ListID:         "TEST",
			SourceRecordID: "source-" + recordID,
		}},
	}
}

func loadTestFixtureProvider(t *testing.T) *FixtureProvider {
	t.Helper()
	file, err := os.Open("../../test/fixtures/providers/synthetic/synthetic-catalog-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	provider, err := LoadFixtureProvider(file)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func loadRequestBatch(t *testing.T) matcherrequest.RequestBatch {
	t.Helper()
	return decodeJSONFile[matcherrequest.RequestBatch](t, "../../test/golden/iso20022/pacs008/pacs008-basic.matcher-requests.json")
}

func loadRequestReplay(t *testing.T) matcherrequest.ReplayEnvelope {
	t.Helper()
	return decodeJSONFile[matcherrequest.ReplayEnvelope](t, "../../test/golden/iso20022/pacs008/pacs008-basic.replay.json")
}

func decodeJSONFile[T any](t *testing.T, path string) T {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value T
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
