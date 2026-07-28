package screeningapiv8f

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/activationpromotion"
	"github.com/openwatchlist-labs/watchlist-platform/internal/projectionpackage"
	"github.com/openwatchlist-labs/watchlist-platform/internal/scoringactivation"
)

type apiTestEnvironment struct {
	config          Config
	promotions      *activationpromotion.Manager
	baseID          string
	candidateID     string
	currentCalls    atomic.Int64
	candidateCalls  atomic.Int64
	currentServer   *httptest.Server
	candidateServer *httptest.Server
}

func setupAPI(t *testing.T) *apiTestEnvironment {
	t.Helper()
	root := t.TempDir()
	descriptorSource := filepath.Join("..", "..", "test", "fixtures", "projection-package", "catalog-descriptor.json")
	inputSource := filepath.Join("..", "..", "test", "fixtures", "projection-package", "canonical-input.json")
	catalogSource := filepath.Join("..", "..", "test", "fixtures", "projection-package", "catalog-fixture.mmap")
	policySource := filepath.Join("..", "..", "configs", "scoring", "candidate-scoring-r1.json")
	descriptorPath := filepath.Join(root, "catalog-descriptor.json")
	catalogPath := filepath.Join(root, "catalog-fixture.mmap")
	policyPath := filepath.Join(root, "policy.json")
	copyAPIFile(t, descriptorSource, descriptorPath)
	copyAPIFile(t, catalogSource, catalogPath)
	copyAPIFile(t, policySource, policyPath)
	descriptor, err := projectionpackage.LoadCatalogDescriptor(descriptorPath)
	if err != nil {
		t.Fatal(err)
	}
	input, err := projectionpackage.LoadCanonicalInput(inputSource)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := projectionpackage.Compile(descriptor, input, filepath.Join(root, "packages"))
	if err != nil {
		t.Fatal(err)
	}
	activations, _ := scoringactivation.NewManager(filepath.Join(root, "activations"))
	baseID, candidateID := "activation-current", "activation-candidate"
	if _, err := activations.Activate(scoringactivation.ActivateRequest{ActivationID: baseID, CatalogDescriptorPath: descriptorPath, ProjectionPackagePath: pkg.Directory, ScoringPolicyPath: policyPath}); err != nil {
		t.Fatal(err)
	}
	if _, err := activations.Stage(scoringactivation.ActivateRequest{ActivationID: candidateID, CatalogDescriptorPath: descriptorPath, ProjectionPackagePath: pkg.Directory, ScoringPolicyPath: policyPath}, baseID); err != nil {
		t.Fatal(err)
	}
	promotions, _ := activationpromotion.NewManager(filepath.Join(root, "promotions"), activations)
	if _, err := promotions.Prepare(activationpromotion.PrepareRequest{
		IntentID: "intent-api", CandidateActivationID: candidateID, Operator: "operator", Reason: "api test",
		CanaryBasisPoints: 1000, CanaryCorrelationAllowlist: []string{"corr-canary"}, RequiredReadyAcks: 1,
		Thresholds: activationpromotion.Thresholds{},
	}); err != nil {
		t.Fatal(err)
	}
	environment := &apiTestEnvironment{promotions: promotions, baseID: baseID, candidateID: candidateID}
	environment.currentServer = httptest.NewServer(apiBackend(&environment.currentCalls, baseID, `{"schema_version":"openwatchlist.screening-response.v2","candidates":[{"candidate_id":"current","score":800}],"blockers":[]}`))
	environment.candidateServer = httptest.NewServer(apiBackend(&environment.candidateCalls, candidateID, `{"schema_version":"openwatchlist.screening-response.v2","candidates":[{"candidate_id":"candidate","score":810}],"blockers":[]}`))
	t.Cleanup(environment.currentServer.Close)
	t.Cleanup(environment.candidateServer.Close)
	environment.config = Config{
		ListenAddress: "127.0.0.1:0", CurrentBaseURL: environment.currentServer.URL, CandidateBaseURL: environment.candidateServer.URL,
		ActivationStateDirectory: activations.StateDirectory(), PromotionStateDirectory: promotions.Directory(),
		IdempotencyDirectory: filepath.Join(root, "idempotency"), InstanceID: "instance-test",
		MaxBodyBytes: 1 << 20, RequestTimeoutMillis: 5000,
	}
	return environment
}

func copyAPIFile(t *testing.T, source, destination string) {
	t.Helper()
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func apiBackend(counter *atomic.Int64, activationID, response string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/readyz":
			writeJSON(w, http.StatusOK, map[string]any{"ready": true, "activation_tuple": map[string]any{"activation_id": activationID}})
		case "/v1/screenings", "/v1/screenings/batch":
			counter.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, response)
		default:
			http.NotFound(w, r)
		}
	})
}

func performScreening(t *testing.T, server *Server, correlation, idempotency string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/screenings", io.NopCloser(stringsReader(`{"request_id":"request-api"}`)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Correlation-ID", correlation)
	if idempotency != "" {
		request.Header.Set("Idempotency-Key", idempotency)
	}
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	return recorder
}

func stringsReader(value string) *readerString { return &readerString{value: []byte(value)} }

type readerString struct {
	value  []byte
	offset int
}

func (r *readerString) Read(p []byte) (int, error) {
	if r.offset >= len(r.value) {
		return 0, io.EOF
	}
	n := copy(p, r.value[r.offset:])
	r.offset += n
	return n, nil
}

func TestPreparedValidatedCanaryAndIdempotency(t *testing.T) {
	environment := setupAPI(t)
	server, err := NewServer(environment.config)
	if err != nil {
		t.Fatal(err)
	}
	prepared := performScreening(t, server, "corr-prepared", "idem-prepared")
	if prepared.Code != http.StatusOK || environment.currentCalls.Load() != 1 || environment.candidateCalls.Load() != 0 {
		t.Fatalf("prepared routing failed: code=%d current=%d candidate=%d body=%s", prepared.Code, environment.currentCalls.Load(), environment.candidateCalls.Load(), prepared.Body.String())
	}
	replay := performScreening(t, server, "corr-prepared", "idem-prepared")
	if replay.Code != http.StatusOK || replay.Header().Get("Idempotent-Replay") != "true" || environment.currentCalls.Load() != 1 {
		t.Fatalf("idempotent replay failed: headers=%v calls=%d", replay.Header(), environment.currentCalls.Load())
	}
	status, _ := environment.promotions.Status()
	identical := []byte(`{"candidates":[{"candidate_id":"x","score":1}],"blockers":[]}`)
	observation, _ := activationpromotion.CompareResponses(status.Intent.IntentID, "seed", identical, identical, "2026-07-14T22:00:00Z")
	if err := environment.promotions.RecordObservation(observation); err != nil {
		t.Fatal(err)
	}
	summary, _ := environment.promotions.SummarizeObservations(status.Intent.IntentID)
	status, err = environment.promotions.Evaluate(1, summary, "validator", "passed")
	if err != nil {
		t.Fatal(err)
	}
	validated := performScreening(t, server, "corr-shadow", "")
	if validated.Code != http.StatusOK || environment.currentCalls.Load() != 2 || environment.candidateCalls.Load() != 1 {
		t.Fatalf("validated shadow routing failed: code=%d current=%d candidate=%d body=%s", validated.Code, environment.currentCalls.Load(), environment.candidateCalls.Load(), validated.Body.String())
	}
	var validatedDocument map[string]any
	if err := json.Unmarshal(validated.Body.Bytes(), &validatedDocument); err != nil {
		t.Fatal(err)
	}
	promotion := validatedDocument["promotion"].(map[string]any)
	if promotion["route"] != "current_shadowed" || promotion["shadow_observation_sha256"] == "" {
		t.Fatalf("missing shadow metadata: %#v", promotion)
	}
	status, err = environment.promotions.StartCanary(status.State.Revision, "operator", "start")
	if err != nil {
		t.Fatal(err)
	}
	canary := performScreening(t, server, "corr-canary", "")
	if canary.Code != http.StatusOK || environment.candidateCalls.Load() != 2 || !strings.Contains(canary.Body.String(), `"candidate_id":"candidate"`) {
		t.Fatalf("allowlisted canary failed: code=%d body=%s", canary.Code, canary.Body.String())
	}
}

func TestReadinessRejectsBackendActivationMismatch(t *testing.T) {
	environment := setupAPI(t)
	environment.candidateServer.Close()
	environment.candidateServer = httptest.NewServer(apiBackend(&environment.candidateCalls, "wrong-activation", `{}`))
	t.Cleanup(environment.candidateServer.Close)
	environment.config.CandidateBaseURL = environment.candidateServer.URL
	status, _ := environment.promotions.Status()
	identical := []byte(`{"candidates":[],"blockers":[]}`)
	observation, _ := activationpromotion.CompareResponses(status.Intent.IntentID, "seed", identical, identical, "2026-07-14T22:00:00Z")
	_ = environment.promotions.RecordObservation(observation)
	summary, _ := environment.promotions.SummarizeObservations(status.Intent.IntentID)
	status, _ = environment.promotions.Evaluate(1, summary, "validator", "passed")
	_, _ = environment.promotions.StartCanary(status.State.Revision, "operator", "start")
	server, err := NewServer(environment.config)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "backend activation mismatch") {
		t.Fatalf("mismatched backend was accepted: code=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
