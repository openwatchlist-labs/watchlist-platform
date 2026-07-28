package screeningapiv8d

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type fakeUpstream struct {
	single    []byte
	batch     []byte
	readyErr  error
	singleHit int
	batchHit  int
}

func (f *fakeUpstream) Post(_ context.Context, path string, _ []byte, _, _ string) (int, []byte, error) {
	switch path {
	case "/v1/screenings":
		f.singleHit++
		return http.StatusOK, append([]byte(nil), f.single...), nil
	case "/v1/screenings/batch":
		f.batchHit++
		return http.StatusOK, append([]byte(nil), f.batch...), nil
	default:
		return 0, nil, errors.New("unexpected path")
	}
}

func (f *fakeUpstream) Ready(context.Context) error { return f.readyErr }

func TestScoringIntegratedRealtimeResponse(t *testing.T) {
	upstream := fixtureUpstream(t)
	server := testServer(t, upstream)
	request := fixture(t, "realtime.request.json")

	recorder := httptest.NewRecorder()
	httpRequest := httptest.NewRequest(http.MethodPost, "/v1/screenings", bytes.NewReader(request))
	httpRequest.Header.Set("X-Correlation-ID", "corr-phase8d-test")
	server.Handler().ServeHTTP(recorder, httpRequest)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.SchemaVersion != ResponseSchemaV2 || response.CorrelationID != "corr-phase8d-test" {
		t.Fatalf("unexpected response identity: %+v", response)
	}
	if response.Policy.PolicyID != "candidate-scoring-r1" || len(response.Policy.PolicySHA256) != 64 {
		t.Fatalf("missing policy binding: %+v", response.Policy)
	}
	if got := candidateIDs(response.Candidates); !equalStrings(got, []string{"candidate-exact-lei", "candidate-exact-name", "candidate-weak"}) {
		t.Fatalf("candidate order=%v", got)
	}
	if response.Candidates[0].Score != 930 || response.Candidates[0].SimilarityBand != "high_similarity" {
		t.Fatalf("top candidate=%+v", response.Candidates[0])
	}
	if response.Candidates[1].Score != 500 || response.Candidates[1].SimilarityBand != "possible_similarity" {
		t.Fatalf("second candidate=%+v", response.Candidates[1])
	}
	if response.Candidates[2].Score != 350 || response.Candidates[2].SimilarityBand != "low_similarity" {
		t.Fatalf("weak candidate=%+v", response.Candidates[2])
	}
	assertNoForbiddenKeys(t, recorder.Body.Bytes())
}

func TestRealtimeIdempotencyIsByteExactAndConflicts(t *testing.T) {
	upstream := fixtureUpstream(t)
	server := testServer(t, upstream)
	body := fixture(t, "realtime.request.json")

	call := func(payload []byte) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/v1/screenings", bytes.NewReader(payload))
		request.Header.Set("Idempotency-Key", "idem-phase8d-1")
		server.Handler().ServeHTTP(recorder, request)
		return recorder
	}
	first := call(body)
	second := call(body)
	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("statuses first=%d second=%d", first.Code, second.Code)
	}
	if !bytes.Equal(first.Body.Bytes(), second.Body.Bytes()) {
		t.Fatal("idempotent replay was not byte exact")
	}
	if second.Header().Get("Idempotent-Replay") != "true" {
		t.Fatal("missing replay header")
	}
	if upstream.singleHit != 1 {
		t.Fatalf("upstream calls=%d want 1", upstream.singleHit)
	}
	changed := append([]byte(nil), body...)
	changed = append(changed, ' ')
	conflict := call(changed)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("conflict status=%d body=%s", conflict.Code, conflict.Body.String())
	}
}

func TestBatchPreservesItemOrderAndCanonicalizesTies(t *testing.T) {
	upstream := fixtureUpstream(t)
	server := testServer(t, upstream)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/screenings/batch", bytes.NewReader(fixture(t, "batch.request.json")))
	request.Header.Set("X-Correlation-ID", "corr-phase8d-batch")
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response BatchResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Items) != 2 || response.Items[0].Response.RequestID != "batch-item-tie" || response.Items[1].Response.RequestID != "batch-item-empty" {
		t.Fatalf("batch item order drifted: %+v", response.Items)
	}
	if got := candidateIDs(response.Items[0].Response.Candidates); !equalStrings(got, []string{"a-tie", "z-tie"}) {
		t.Fatalf("tie order=%v", got)
	}
	if len(response.Items[1].Response.Candidates) != 0 || response.Items[1].Response.Status != "no_candidates" {
		t.Fatalf("empty candidate item=%+v", response.Items[1])
	}
	assertNoForbiddenKeys(t, recorder.Body.Bytes())
}

func TestMissingProjectionIsExplicitReadinessStyleBlocker(t *testing.T) {
	upstream := fixtureUpstream(t)
	upstream.single = fixture(t, "unavailable-projection-upstream.response.json")
	server := testServer(t, upstream)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/screenings", bytes.NewReader(fixture(t, "realtime.request.json")))
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "blocked" || len(response.Blockers) != 1 || response.Blockers[0].Code != "candidate_projection_unavailable" {
		t.Fatalf("blockers=%+v", response.Blockers)
	}
}

func TestReadinessRequiresPhase8BAndReturnsPolicyBinding(t *testing.T) {
	upstream := fixtureUpstream(t)
	server := testServer(t, upstream)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var ready ReadyResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &ready); err != nil {
		t.Fatal(err)
	}
	if !ready.Ready || ready.Policy.PolicyID != "candidate-scoring-r1" || len(ready.ProjectionSet) != 64 {
		t.Fatalf("ready=%+v", ready)
	}
	upstream.readyErr = errors.New("not ready")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("not-ready status=%d", recorder.Code)
	}
}

func fixtureUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	return &fakeUpstream{single: fixture(t, "upstream-realtime.response.json"), batch: fixture(t, "upstream-batch.response.json")}
}

func testServer(t *testing.T, upstream *fakeUpstream) *Server {
	t.Helper()
	root := repoRoot(t)
	config := Config{
		ListenAddress:          "127.0.0.1:0",
		UpstreamBaseURL:        "http://phase8b.invalid",
		ScoringPolicyPath:      filepath.Join(root, "configs/scoring/candidate-scoring-r1.json"),
		ProjectionRegistryPath: filepath.Join(root, "test/fixtures/screening-api-v8d/projection-registry.json"),
		IdempotencyDirectory:   t.TempDir(),
		MaxBodyBytes:           1024 * 1024,
		MaxBatchItems:          100,
		RequestTimeoutMillis:   1000,
		DefaultLineage: Lineage{
			Provider: "ofac-direct", CatalogID: "ofac-production", ComponentID: "sdn",
			ComponentVersion: "2026-07-14T00:00:00Z", ActivationID: "activation-phase8d-fixture",
			NormalizationProfile: "unicode-upper-alnum-space-v1",
		},
	}
	server, err := NewServer(config, upstream)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "test/fixtures/screening-api-v8d", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}

func candidateIDs(candidates []Candidate) []string {
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, candidate.CandidateID)
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func assertNoForbiddenKeys(t *testing.T, raw []byte) {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	forbidden := map[string]bool{
		"disposition": true, "regulatory_disposition": true, "clearance": true,
		"analyst_decision": true, "case_decision": true, "full_record": true,
		"catalog_row": true, "source_record": true,
	}
	var walk func(any)
	walk = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				if forbidden[key] {
					t.Fatalf("forbidden key present: %s", key)
				}
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
}
