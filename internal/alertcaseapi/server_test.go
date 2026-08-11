package alertcaseapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertcase"
)

func TestHTTPAlertCaseLifecycle(t *testing.T) {
	root := filepath.Join("..", "..")
	policy, err := alertcase.LoadPolicy(filepath.Join(root, "test", "fixtures", "alert-case", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{StateDirectory: t.TempDir(), StreamID: "api-test", MaxBodyBytes: 1 << 20, TimeoutSeconds: 5}
	server, err := New(cfg, policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	tokens := loadFixtureTokenService(t)
	token, _, err := tokens.Issue("alice", "tenant-a", time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	h, err := server.AuthenticatedHandler(tokens, nil)
	if err != nil {
		t.Fatal(err)
	}
	authed := func(method, path string, body io.Reader) *http.Request {
		req := httptest.NewRequest(method, path, body)
		req.Header.Set("Authorization", "Bearer "+token)
		return req
	}
	raw, _ := os.ReadFile(filepath.Join(root, "test", "fixtures", "alert-case", "create-alert.request.json"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authed(http.MethodPost, "/v1/alerts", bytes.NewReader(raw)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create alert status=%d body=%s", rr.Code, rr.Body.String())
	}
	var alertResp struct {
		Alert alertcase.AlertRecord `json:"alert"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &alertResp); err != nil {
		t.Fatal(err)
	}
	caseReq := alertcase.CreateCaseRequest{TenantID: "tenant-a", AlertIDs: []string{alertResp.Alert.AlertID}, CreatedBy: "analyst-a", Reason: "review", OccurredAt: "2026-07-15T13:00:00Z", IdempotencyKey: "api-case-1"}
	body, _ := json.Marshal(caseReq)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, authed(http.MethodPost, "/v1/cases", bytes.NewReader(body)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create case status=%d body=%s", rr.Code, rr.Body.String())
	}
	var caseResp struct {
		Case alertcase.CaseProjection `json:"case"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &caseResp)
	eventReq := alertcase.CaseEventRequest{ExpectedRevision: 1, Action: "assign", Actor: "supervisor", OccurredAt: "2026-07-15T13:01:00Z", IdempotencyKey: "api-event-1", Payload: json.RawMessage(`{"assignee":"analyst-a"}`)}
	body, _ = json.Marshal(eventReq)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, authed(http.MethodPost, "/v1/cases/"+caseResp.Case.CaseID+"/events", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("case event status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, authed(http.MethodPost, "/v1/cases/"+caseResp.Case.CaseID+"/verify", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestStrictUnknownField(t *testing.T) {
	policy, _ := alertcase.LoadPolicy(filepath.Join("..", "..", "test", "fixtures", "alert-case", "policy.json"))
	server, _ := New(Config{StateDirectory: t.TempDir(), MaxBodyBytes: 1024}, policy)
	tokens := loadFixtureTokenService(t)
	token, _, err := tokens.Issue("alice", "tenant-a", time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	h, err := server.AuthenticatedHandler(tokens, nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/alerts", bytes.NewBufferString(`{"unknown":true}`))
	req.Header.Set("Authorization", "Bearer "+token)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, got %d", rr.Code)
	}
}
