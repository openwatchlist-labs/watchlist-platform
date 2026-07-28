package screeningapiv8e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/projectionpackage"
	"github.com/openwatchlist-labs/watchlist-platform/internal/scoringactivation"
)

func prepareServer(t *testing.T, mutateResponse func([]byte) []byte) (*Server, *scoringactivation.Manager, func()) {
	t.Helper()
	root := filepath.Join("..", "..")
	descriptorPath := filepath.Join(root, "test", "fixtures", "projection-package", "catalog-descriptor.json")
	inputPath := filepath.Join(root, "test", "fixtures", "projection-package", "canonical-input.json")
	policyPath, _ := filepath.Abs(filepath.Join(root, "configs", "scoring", "candidate-scoring-r1.json"))
	descriptor, err := projectionpackage.LoadCatalogDescriptor(descriptorPath)
	if err != nil {
		t.Fatal(err)
	}
	input, err := projectionpackage.LoadCanonicalInput(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	temporary := t.TempDir()
	pkg, err := projectionpackage.Compile(descriptor, input, filepath.Join(temporary, "packages"))
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(temporary, "state")
	manager, _ := scoringactivation.NewManager(state)
	if _, err := manager.Activate(scoringactivation.ActivateRequest{
		ActivationID: "activation-phase8d-fixture", CatalogDescriptorPath: descriptorPath,
		ProjectionPackagePath: pkg.Directory, ScoringPolicyPath: policyPath,
	}); err != nil {
		t.Fatal(err)
	}
	singleRaw, _ := os.ReadFile(filepath.Join(root, "test", "fixtures", "screening-api-v8d", "upstream-realtime.response.json"))
	batchRaw, _ := os.ReadFile(filepath.Join(root, "test", "fixtures", "screening-api-v8d", "upstream-batch.response.json"))
	if mutateResponse != nil {
		singleRaw = mutateResponse(singleRaw)
		batchRaw = mutateResponse(batchRaw)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/readyz":
			_, _ = w.Write([]byte(`{"ready":true}`))
		case r.URL.Path == "/v1/screenings/batch":
			_, _ = w.Write(batchRaw)
		case r.URL.Path == "/v1/screenings":
			_, _ = w.Write(singleRaw)
		default:
			http.NotFound(w, r)
		}
	}))
	server, err := NewServer(Config{
		ListenAddress: "127.0.0.1:0", UpstreamBaseURL: upstream.URL,
		ActivationStateDirectory: state, IdempotencyDirectory: filepath.Join(temporary, "idempotency"),
		MaxBodyBytes: 1048576, MaxBatchItems: 100, RequestTimeoutMillis: 5000,
	})
	if err != nil {
		upstream.Close()
		t.Fatal(err)
	}
	return server, manager, upstream.Close
}

func TestReadyAndScreeningExposeExactActivationTuple(t *testing.T) {
	server, _, cleanup := prepareServer(t, nil)
	defer cleanup()
	ready := httptest.NewRecorder()
	server.Handler().ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusOK {
		t.Fatalf("ready status=%d body=%s", ready.Code, ready.Body.String())
	}
	var readyDocument map[string]any
	_ = json.Unmarshal(ready.Body.Bytes(), &readyDocument)
	activation := readyDocument["activation_tuple"].(map[string]any)
	if activation["activation_id"] != "activation-phase8d-fixture" || activation["projection_package_sha256"] == "" {
		t.Fatalf("invalid activation tuple: %#v", activation)
	}
	requestRaw, _ := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "screening-api-v8d", "realtime.request.json"))
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/screenings", bytes.NewReader(requestRaw))
	request.Header.Set("Content-Type", "application/json")
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("screening status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"activation_tuple"`) || !strings.Contains(response.Body.String(), `"candidate-exact-lei"`) {
		t.Fatalf("screening response missing tuple or candidates: %s", response.Body.String())
	}
}

func TestChangedActiveTupleRequiresRestart(t *testing.T) {
	server, manager, cleanup := prepareServer(t, nil)
	defer cleanup()
	active, err := manager.LoadActive()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Activate(scoringactivation.ActivateRequest{
		ActivationID:          "activation-replacement",
		CatalogDescriptorPath: filepath.Join("..", "..", "test", "fixtures", "projection-package", "catalog-descriptor.json"),
		ProjectionPackagePath: active.ProjectionPackage.Directory,
		ScoringPolicyPath:     active.Activation.Policy.Path,
	}); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/screenings", bytes.NewReader([]byte(`{"request_id":"x"}`))))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "restart required") {
		t.Fatalf("changed tuple response=%d %s", response.Code, response.Body.String())
	}
}

func TestMismatchedUpstreamLineageIsBlocked(t *testing.T) {
	server, _, cleanup := prepareServer(t, func(raw []byte) []byte {
		return bytes.ReplaceAll(raw, []byte("activation-phase8d-fixture"), []byte("inactive-activation"))
	})
	defer cleanup()
	requestRaw, _ := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "screening-api-v8d", "realtime.request.json"))
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/screenings", bytes.NewReader(requestRaw))
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "active_catalog_lineage_mismatch") {
		t.Fatalf("mismatch response=%d %s", response.Code, response.Body.String())
	}
}
