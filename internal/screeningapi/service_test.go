package screeningapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertlistmapping"
	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogregistry"
	"github.com/openwatchlist-labs/watchlist-platform/internal/runtimemmapclient"
)

type staticLoader struct{ state State }

func (loader staticLoader) Load() (State, error) { return loader.state, nil }

type fakeRuntime struct {
	lookups int
	info    runtimemmapclient.PackageInfo
	values  []runtimemmapclient.Candidate
}

func (runtime *fakeRuntime) Lookup(_ context.Context, _, _ string, _ runtimemmapclient.Query) (RuntimeResult, error) {
	runtime.lookups++
	return RuntimeResult{Info: runtime.info, Candidates: append([]runtimemmapclient.Candidate(nil), runtime.values...)}, nil
}
func (runtime *fakeRuntime) Ready(catalogregistry.Registry) error { return nil }
func (runtime *fakeRuntime) Close() error                         { return nil }

func TestScreenUsesExactMappingAndActiveRuntime(t *testing.T) {
	state := loadGoldenState(t)
	runtime := &fakeRuntime{
		info:   runtimemmapclient.PackageInfo{ProtocolVersion: "1", ComponentID: "catalog_component_ed835720fdb2b3a505927488", CatalogID: "ofac-sdn-direct", CatalogVersion: "2026-07-13-427847835cb4", CatalogChecksum: "339b64d9a9d8ffa9ea5b9ab243a320faeef1ade6f3dc5a3e8891e437adccc582", CatalogMode: "official_list", PackageSHA256: "8c5e581ad36807c15a2ae00c5cb4e8b7f9154e208b369ff3227617294a473367", RecordCount: 3},
		values: []runtimemmapclient.Candidate{{RecordID: "ofac:sdn:1001", EntityType: "organization", PrimaryName: "Acme Imports LLC", MatchKind: "alias", MatchedValue: "ACME IMPORTS", NormalizedQuery: "acme imports"}},
	}
	service := Service{Loader: staticLoader{state}, Runtime: runtime, MaxCandidates: 20, Clock: func() time.Time { return mustTime(t, "2026-07-14T20:00:00Z") }}
	request := fixtureRequest("screen-1", "fircosoft-prod", "WLS_OFAC_001", "2026-07-20T12:00:00Z")
	response, err := service.Screen(context.Background(), request, "corr-1", "idem-1")
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != StatusMatched || response.CandidateCount != 1 || response.Candidates[0].RecordID != "ofac:sdn:1001" {
		t.Fatalf("unexpected response: %+v", response)
	}
	if response.ListResolution.Status != alertlistmapping.ResolutionResolved || response.Runtime == nil || response.Runtime.CatalogEpoch != 3 {
		t.Fatalf("missing control-plane lineage: %+v", response)
	}
	if runtime.lookups != 1 {
		t.Fatalf("expected one runtime lookup, got %d", runtime.lookups)
	}
}

func TestUnmappedListReturnsBlockerWithoutRuntimeLookup(t *testing.T) {
	state := loadGoldenState(t)
	runtime := &fakeRuntime{}
	service := Service{Loader: staticLoader{state}, Runtime: runtime, MaxCandidates: 20}
	request := fixtureRequest("screen-2", "fircosoft-prod", "WLS_OFAC_UNKNOWN", "2026-07-20T12:00:00Z")
	response, err := service.Screen(context.Background(), request, "corr-2", "idem-2")
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != StatusBlocked || len(response.ReviewBlockers) != 1 || response.ReviewBlockers[0] != alertlistmapping.BlockerMappingRequired {
		t.Fatalf("unexpected blocked response: %+v", response)
	}
	if runtime.lookups != 0 {
		t.Fatalf("runtime should not be called for an unmapped list")
	}
}

func TestHandlerIdempotencyReplayAndConflict(t *testing.T) {
	state := loadGoldenState(t)
	runtime := &fakeRuntime{info: runtimemmapclient.PackageInfo{ProtocolVersion: "1", PackageSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RecordCount: 3}}
	service := &Service{Loader: staticLoader{state}, Runtime: runtime, MaxCandidates: 20, Clock: func() time.Time { return mustTime(t, "2026-07-14T20:00:00Z") }}
	config := Config{MaxBodyBytes: 1 << 20, MaxBatchItems: 100, MaxCandidates: 20, RequestTimeoutMS: 2000}
	handler := &Handler{Config: config, Service: service, Store: IdempotencyStore{Root: t.TempDir()}}
	tokens := loadFixtureTokenService(t)
	token, _, err := tokens.Issue("alice", "tenant-a", time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	guarded, err := NewAuthenticatedHandler(handler, tokens, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(fixtureRequest("screen-3", "unknown", "UNKNOWN", "2026-07-20T12:00:00Z"))

	first := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/screenings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "idem-http-1")
	req.Header.Set("Authorization", "Bearer "+token)
	guarded.ServeHTTP(first, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	second := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/screenings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "idem-http-1")
	req.Header.Set("Authorization", "Bearer "+token)
	guarded.ServeHTTP(second, req)
	var firstJSON, secondJSON any
	if err := json.Unmarshal(first.Body.Bytes(), &firstJSON); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(second.Body.Bytes(), &secondJSON); err != nil {
		t.Fatal(err)
	}
	if second.Code != http.StatusOK || second.Header().Get("X-Idempotent-Replay") != "true" || digest(firstJSON) != digest(secondJSON) {
		t.Fatalf("idempotent replay failed: status=%d header=%q body=%s", second.Code, second.Header().Get("X-Idempotent-Replay"), second.Body.String())
	}
	changed := fixtureRequest("screen-4", "unknown", "UNKNOWN", "2026-07-20T12:00:00Z")
	changedBody, _ := json.Marshal(changed)
	conflict := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/screenings", bytes.NewReader(changedBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "idem-http-1")
	req.Header.Set("Authorization", "Bearer "+token)
	guarded.ServeHTTP(conflict, req)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("expected conflict, got %d body=%s", conflict.Code, conflict.Body.String())
	}
}

func loadGoldenState(t *testing.T) State {
	t.Helper()
	var catalog catalogregistry.Registry
	readJSON(t, filepath.Join("..", "..", "test", "golden", "catalog-registry", "registry.json"), &catalog)
	if err := catalogregistry.ValidateRegistry(catalog); err != nil {
		t.Fatal(err)
	}
	var mapping alertlistmapping.Registry
	readJSON(t, filepath.Join("..", "..", "test", "golden", "alert-list-mapping", "registry.json"), &mapping)
	if err := alertlistmapping.ValidateRegistry(mapping, catalog); err != nil {
		t.Fatal(err)
	}
	return State{Catalog: catalog, Mapping: mapping}
}

func readJSON(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeStrict(data, target); err != nil {
		t.Fatal(err)
	}
}

func fixtureRequest(id, sourceSystem, listName, at string) ScreeningRequest {
	parsed, _ := time.Parse(time.RFC3339, at)
	return ScreeningRequest{SchemaVersion: RequestSchemaVersion, RequestID: id, SourceSystemID: sourceSystem, RawListName: listName, EffectiveAt: parsed, Query: Query{Kind: QueryName, Value: "ACME IMPORTS", TargetEntityTypes: []string{"organization"}, Limit: 20}}
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
