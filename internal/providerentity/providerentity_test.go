package providerentity

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/falsepositive"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherrequest"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
)

func TestProjectCompareAndChecksumGates(t *testing.T) {
	snapshot := loadSnapshotFile(t)
	first, err := Project(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Project(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(first, second) {
		t.Fatal("provider catalog projection is not deterministic")
	}
	golden := loadCatalogFile(t)
	if !jsonEqual(first, golden) {
		t.Fatal("projected provider catalog differs from golden")
	}

	direct := loadDirectFile(t)
	comparison, err := Compare(first, direct)
	if err != nil {
		t.Fatal(err)
	}
	goldenComparison := loadComparisonFile(t)
	if !jsonEqual(comparison, goldenComparison) {
		t.Fatal("catalog comparison differs from golden")
	}
	if comparison.Summary.LinkedRecords != 3 || comparison.Summary.ProviderOnly != 1 || comparison.Summary.DirectOnly != 0 || comparison.Summary.ProgramDifferences != 1 {
		t.Fatalf("unexpected comparison summary: %+v", comparison.Summary)
	}

	tampered := snapshot
	tampered.Entities = append([]SnapshotEntity(nil), snapshot.Entities...)
	tampered.Entities[0].PrimaryName = "tampered"
	if err := ValidateSnapshot(tampered); err == nil {
		t.Fatal("tampered snapshot checksum was accepted")
	}
	tamperedCatalog := golden
	tamperedCatalog.Entities = append([]Entity(nil), golden.Entities...)
	tamperedCatalog.Entities[0].PrimaryName = "tampered"
	if err := ValidateCatalog(tamperedCatalog); err == nil {
		t.Fatal("tampered catalog checksum was accepted")
	}
}

func TestProviderEntityAndHybridResultsPreserveReviewContract(t *testing.T) {
	catalog := loadCatalogFile(t)
	requests := loadRequests(t)
	provider, err := NewProvider(catalog)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := matcherprovider.NewRunner(provider)
	if err != nil {
		t.Fatal(err)
	}
	results, err := runner.Execute(context.Background(), requests)
	if err != nil {
		t.Fatal(err)
	}
	golden := loadResults(t, "provider-entity-results.json")
	if !jsonEqual(results, golden) {
		t.Fatal("provider-entity results differ from golden")
	}
	if results.Provider.Catalog.CatalogMode != matcherprovider.CatalogModeProviderEntity || results.Summary.MatchedRequests != 7 || results.Summary.TotalCandidates != 8 {
		t.Fatalf("unexpected provider results summary: %+v", results.Summary)
	}
	for _, result := range results.Results {
		for _, candidate := range result.Candidates {
			if candidate.ProviderEntityID == "" || len(candidate.SourceAssertions) != 2 {
				t.Fatalf("provider candidate lost entity or source membership: %+v", candidate)
			}
		}
	}
	observations, err := falsepositive.ObservationsFromMatcherResults(results, "provider-entity-regression")
	if err != nil {
		t.Fatalf("review adaptation failed: %v", err)
	}
	if len(observations.Observations) != 8 {
		t.Fatalf("observations=%d", len(observations.Observations))
	}

	direct := loadDirectFile(t)
	hybridProvider, hybridCatalog, err := NewHybridProvider(catalog, direct)
	if err != nil {
		t.Fatal(err)
	}
	if hybridCatalog.CatalogMode != matcherprovider.CatalogModeHybridOverlay {
		t.Fatal("hybrid mode missing")
	}
	hybridRunner, err := matcherprovider.NewRunner(hybridProvider)
	if err != nil {
		t.Fatal(err)
	}
	hybridResults, err := hybridRunner.Execute(context.Background(), requests)
	if err != nil {
		t.Fatal(err)
	}
	hybridGolden := loadResults(t, "hybrid-overlay-results.json")
	if !jsonEqual(hybridResults, hybridGolden) {
		t.Fatal("hybrid results differ from golden")
	}
	for _, result := range hybridResults.Results {
		for _, candidate := range result.Candidates {
			if candidate.ProviderEntityID == "" {
				t.Fatalf("linked hybrid candidate lost provider entity: %+v", candidate)
			}
			if candidate.Attributes["hybrid_origin"] != "provider_plus_official_overlay" {
				t.Fatalf("unexpected hybrid origin: %+v", candidate.Attributes)
			}
			if len(candidate.SourceAssertions) != 2 {
				t.Fatalf("hybrid source assertions=%d", len(candidate.SourceAssertions))
			}
		}
	}
	if _, err := falsepositive.ObservationsFromMatcherResults(hybridResults, "hybrid-overlay-regression"); err != nil {
		t.Fatalf("hybrid review adaptation failed: %v", err)
	}
}

func loadSnapshotFile(t *testing.T) Snapshot {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "test", "fixtures", "provider-entity", "opensanctions-like-snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	value, err := LoadSnapshot(f)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func loadCatalogFile(t *testing.T) Catalog {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "test", "golden", "provider-entity", "provider-catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	value, err := LoadCatalog(f)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func loadDirectFile(t *testing.T) ofaccatalog.Catalog {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "test", "golden", "ofac", "ofac-sdn-fixture.catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	value, err := ofaccatalog.Load(f)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func loadRequests(t *testing.T) matcherrequest.RequestBatch {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "golden", "matcher-baseline", "pacs008-fuzzy-names.matcher-requests.json"))
	if err != nil {
		t.Fatal(err)
	}
	var value matcherrequest.RequestBatch
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}
func loadResults(t *testing.T, name string) matcherprovider.ResultBatch {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "golden", "provider-entity", name))
	if err != nil {
		t.Fatal(err)
	}
	var value matcherprovider.ResultBatch
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	if err := matcherprovider.ValidateResultBatch(value); err != nil {
		t.Fatal(err)
	}
	return value
}
func loadComparisonFile(t *testing.T) Comparison {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "golden", "provider-entity", "catalog-comparison.json"))
	if err != nil {
		t.Fatal(err)
	}
	var value Comparison
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	if err := ValidateComparison(value); err != nil {
		t.Fatal(err)
	}
	return value
}

func jsonEqual(left, right any) bool {
	l, _ := json.Marshal(left)
	r, _ := json.Marshal(right)
	return string(l) == string(r)
}
