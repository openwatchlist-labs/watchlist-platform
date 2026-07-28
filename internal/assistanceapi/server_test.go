package assistanceapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertcase"
	"github.com/openwatchlist-labs/watchlist-platform/internal/assistancerag"
)

func TestReadinessAndStrictUnknownField(t *testing.T) {
	policy, err := alertcase.LoadPolicy(filepath.Join("..", "..", "test", "fixtures", "alert-case", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	alertStore, err := alertcase.NewStore(filepath.Join(t.TempDir(), "alert"), policy, "api-test")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := assistancerag.LoadManifest(filepath.Join("..", "..", "test", "fixtures", "case-assistance", "corpus", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _ := assistancerag.CompileSnapshot(manifest)
	client := &assistancerag.FixtureModelClient{Models: []string{"granite4.1:8b", "qwen3:14b", "granite4.1-guardian:8b"}, Responses: map[string]assistancerag.ModelResponse{}, Errors: map[string]error{}}
	store, err := assistancerag.NewStore(filepath.Join(t.TempDir(), "assist"), "api-test", alertStore, snapshot, assistancerag.ModelProfile{PrimaryModelID: "granite4.1:8b", ReasoningModelID: "qwen3:14b", GuardianModelID: "granite4.1-guardian:8b", ContextTokens: 16384, KeepAlive: "0"}, client)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Config: Config{ModelMode: "fixture", OllamaRequired: true, Models: store.Models, MaxBodyBytes: 1 << 20}, Store: store, Client: client}
	if err := server.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("readyz=%d %s", rr.Code, rr.Body.String())
	}
	body, _ := json.Marshal(map[string]any{"task": "draft_note", "actor": "analyst", "occurred_at": "2026-07-15T16:00:00Z", "idempotency_key": "x", "unknown": true})
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/cases/missing/assistance", bytes.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("strict decode status=%d body=%s", rr.Code, rr.Body.String())
	}
}
