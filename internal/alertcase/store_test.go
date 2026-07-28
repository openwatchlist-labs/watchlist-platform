package alertcase

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixturePath(name string) string {
	return filepath.Join("..", "..", "test", "fixtures", "alert-case", name)
}

func loadFixture[T any](t *testing.T, name string) T {
	t.Helper()
	var out T
	raw, err := os.ReadFile(fixturePath(name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	policy, err := LoadPolicy(fixturePath("policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(t.TempDir(), policy, "phase9ab-test")
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestAlertAndCaseLifecycle(t *testing.T) {
	store := newTestStore(t)
	req := loadFixture[CreateAlertRequest](t, "create-alert.request.json")
	alert, replayed, err := store.CreateAlert(req)
	if err != nil {
		t.Fatal(err)
	}
	if replayed || alert.PolicyDecision.Route != "escalate" || alert.ScreeningLineage == nil {
		t.Fatalf("unexpected alert: replayed=%v route=%s lineage=%v", replayed, alert.PolicyDecision.Route, alert.ScreeningLineage)
	}
	second, replayed, err := store.CreateAlert(req)
	if err != nil || !replayed || second.AlertID != alert.AlertID {
		t.Fatalf("idempotent replay failed: %v %v", replayed, err)
	}
	conflict := req
	conflict.Subject = json.RawMessage(`{"message_id":"changed"}`)
	if _, _, err := store.CreateAlert(conflict); err == nil || !strings.Contains(err.Error(), "idempotency conflict") {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}

	caseReq := CreateCaseRequest{TenantID: "tenant-a", AlertIDs: []string{alert.AlertID}, GroupingKey: "payment:msg-001", CreatedBy: "analyst-a", Reason: "initial investigation", OccurredAt: "2026-07-15T12:02:00Z", IdempotencyKey: "idem-case-001"}
	projection, replayed, err := store.CreateCase(caseReq)
	if err != nil || replayed || projection.State != "open" {
		t.Fatalf("create case: %+v replayed=%v err=%v", projection, replayed, err)
	}
	caseID := projection.CaseID
	steps := []CaseEventRequest{
		{CaseID: caseID, ExpectedRevision: 1, Action: "assign", Actor: "supervisor-a", Reason: "assign", OccurredAt: "2026-07-15T12:03:00Z", IdempotencyKey: "idem-event-1", Payload: json.RawMessage(`{"assignee":"analyst-a"}`)},
		{CaseID: caseID, ExpectedRevision: 2, Action: "start_investigation", Actor: "analyst-a", Reason: "start", OccurredAt: "2026-07-15T12:04:00Z", IdempotencyKey: "idem-event-2"},
		{CaseID: caseID, ExpectedRevision: 3, Action: "request_evidence", Actor: "analyst-a", Reason: "need KYC", OccurredAt: "2026-07-15T12:05:00Z", IdempotencyKey: "idem-event-3", Payload: json.RawMessage(`{"evidence_request_id":"evreq-001","question":"Provide date of birth"}`)},
		{CaseID: caseID, ExpectedRevision: 4, Action: "submit_evidence", Actor: "operations-a", Reason: "KYC supplied", OccurredAt: "2026-07-15T12:06:00Z", IdempotencyKey: "idem-event-4", Payload: json.RawMessage(`{"evidence_submission_id":"evsub-001","evidence_hash":"abc"}`)},
		{CaseID: caseID, ExpectedRevision: 5, Action: "propose_decision", Actor: "analyst-a", Reason: "evidence supports escalation", OccurredAt: "2026-07-15T12:07:00Z", IdempotencyKey: "idem-event-5", Payload: json.RawMessage(`{"decision":{"outcome":"escalate","reason_codes":["identifier_exact"]}}`)},
	}
	for _, step := range steps {
		projection, _, _, err = store.ApplyCaseEvent(step)
		if err != nil {
			t.Fatalf("action %s: %v", step.Action, err)
		}
	}
	selfApprove := CaseEventRequest{CaseID: caseID, ExpectedRevision: 6, Action: "approve_decision", Actor: "analyst-a", Reason: "self approve", OccurredAt: "2026-07-15T12:08:00Z", IdempotencyKey: "idem-self-approve"}
	if _, _, _, err := store.ApplyCaseEvent(selfApprove); err == nil || !strings.Contains(err.Error(), "four-eyes") {
		t.Fatalf("expected four-eyes rejection, got %v", err)
	}
	approve := selfApprove
	approve.Actor = "supervisor-b"
	approve.IdempotencyKey = "idem-event-6"
	projection, _, _, err = store.ApplyCaseEvent(approve)
	if err != nil || projection.State != "resolved" {
		t.Fatalf("approve: %+v %v", projection, err)
	}
	if _, _, _, err := store.ApplyCaseEvent(CaseEventRequest{CaseID: caseID, ExpectedRevision: 5, Action: "reopen", Actor: "supervisor-b", OccurredAt: "2026-07-15T12:09:00Z", IdempotencyKey: "stale"}); err == nil || !strings.Contains(err.Error(), "revision conflict") {
		t.Fatalf("expected revision conflict, got %v", err)
	}
	projection, _, _, err = store.ApplyCaseEvent(CaseEventRequest{CaseID: caseID, ExpectedRevision: 7, Action: "reopen", Actor: "supervisor-b", Reason: "new screening", OccurredAt: "2026-07-15T12:09:00Z", IdempotencyKey: "idem-event-7"})
	if err != nil || projection.State != "reopened" {
		t.Fatalf("reopen: %+v %v", projection, err)
	}
	projection, _, _, err = store.ApplyCaseEvent(CaseEventRequest{CaseID: caseID, ExpectedRevision: 8, Action: "link_rescreen", Actor: "analyst-a", Reason: "new event", OccurredAt: "2026-07-15T12:10:00Z", IdempotencyKey: "idem-event-8", Payload: json.RawMessage(`{"screening_event_id":"screening-event-new"}`)})
	if err != nil || len(projection.RescreenEventIDs) != 1 {
		t.Fatalf("link rescreen: %+v %v", projection, err)
	}
	verified, err := store.VerifyCase(caseID)
	if err != nil || verified.Revision != projection.Revision {
		t.Fatalf("verify case: %+v %v", verified, err)
	}
	count, err := store.VerifyAudit()
	if err != nil || count < 10 {
		t.Fatalf("verify audit count=%d err=%v", count, err)
	}
}

func TestExternalAlertPreservesExactSource(t *testing.T) {
	store := newTestStore(t)
	req := loadFixture[CreateAlertRequest](t, "external-alert.request.json")
	alert, _, err := store.CreateAlert(req)
	if err != nil {
		t.Fatal(err)
	}
	if alert.ExternalAlert == nil || alert.ExternalAlert.RawListName != "WLS_OFAC_001" || alert.PolicyDecision.Route != "escalate" {
		t.Fatalf("unexpected external alert: %+v", alert)
	}
}

func TestPolicyChecksumRejectsTampering(t *testing.T) {
	policy := loadFixture[Policy](t, "policy.json")
	policy.PolicySHA256 = strings.Repeat("0", 64)
	path := filepath.Join(t.TempDir(), "policy.json")
	raw, _ := json.Marshal(policy)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(path); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch, got %v", err)
	}
}
