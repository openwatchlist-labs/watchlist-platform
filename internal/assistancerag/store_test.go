package assistancerag

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertcase"
)

func buildTestStore(t *testing.T, client ModelClient) (*Store, alertcase.CaseProjection) {
	t.Helper()
	policy, err := alertcase.LoadPolicy(filepath.Join("..", "..", "test", "fixtures", "alert-case", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	alertStore, err := alertcase.NewStore(filepath.Join(t.TempDir(), "alert-state"), policy, "phase9c-test-alert")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "alert-case", "create-alert.request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var alertReq alertcase.CreateAlertRequest
	if err := json.Unmarshal(raw, &alertReq); err != nil {
		t.Fatal(err)
	}
	alertReq.IdempotencyKey = "phase9c-test-alert"
	alert, _, err := alertStore.CreateAlert(alertReq)
	if err != nil {
		t.Fatal(err)
	}
	caseProjection, _, err := alertStore.CreateCase(alertcase.CreateCaseRequest{TenantID: "tenant-a", AlertIDs: []string{alert.AlertID}, GroupingKey: "payment:msg-001", CreatedBy: "analyst-a", Reason: "phase9c test", OccurredAt: "2026-07-15T16:00:00Z", IdempotencyKey: "phase9c-test-case"})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := LoadManifest(filepath.Join("..", "..", "test", "fixtures", "case-assistance", "corpus", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := CompileSnapshot(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if client == nil {
		client = goodFixtureClient(snapshot)
	}
	store, err := NewStore(filepath.Join(t.TempDir(), "assistance-state"), "phase9c-test", alertStore, snapshot, ModelProfile{PrimaryModelID: "granite4.1:8b", ReasoningModelID: "qwen3:14b", GuardianModelID: "granite4.1-guardian:8b", ContextTokens: 16384, KeepAlive: "0", MaxOutputBytes: 65536}, client)
	if err != nil {
		t.Fatal(err)
	}
	return store, caseProjection
}

func goodFixtureClient(snapshot CorpusSnapshot) *FixtureModelClient {
	policyID, contradictionID := "", ""
	for _, p := range snapshot.Passages {
		if p.DocumentID == "policy-escalation-r1" && strings.Contains(p.Text, "exact name or typed identifier") {
			policyID = p.PassageID
		}
		if p.DocumentID == "policy-escalation-r1" && strings.Contains(p.Text, "Country or entity-type") {
			contradictionID = p.PassageID
		}
	}
	draft := AssistanceDraft{SchemaVersion: DraftSchemaV1, Summary: "The verified evidence contains an exact name signal and a country contradiction.", EvidenceFindings: []EvidenceFinding{{Statement: "Exact name evidence requires investigation under the cited policy.", CitationIDs: []string{policyID}}, {Statement: "Country contradictions remain countervailing evidence.", CitationIDs: []string{contradictionID}}}, MissingEvidenceQuestions: []string{"Is independently verified identity evidence available?"}, SuggestedNextSteps: []string{"Review the cited evidence."}}
	draftRaw, _ := json.Marshal(draft)
	guardianRaw, _ := json.Marshal(GuardianAssessment{SchemaVersion: GuardianSchemaV1, Grounded: true, Relevant: true, Safe: true, CitationsValid: true, Notes: "bounded"})
	return &FixtureModelClient{Models: []string{"granite4.1:8b", "qwen3:14b", "granite4.1-guardian:8b"}, Responses: map[string]ModelResponse{"granite4.1:8b": {Content: string(draftRaw)}, "qwen3:14b": {Content: string(draftRaw)}, "granite4.1-guardian:8b": {Content: string(guardianRaw)}}, Errors: map[string]error{}}
}

func TestAssistanceCompletedTenantSafeAndCaseImmutable(t *testing.T) {
	store, projection := buildTestStore(t, nil)
	before, _ := CanonicalJSON(projection)
	req := AssistanceRequest{CaseID: projection.CaseID, Task: "draft_note", ModelRole: "primary", Actor: "analyst-a", OccurredAt: "2026-07-15T16:01:00Z", IdempotencyKey: "assist-1"}
	record, replayed, err := store.Assist(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if replayed || record.Status != "completed" {
		t.Fatalf("unexpected result replayed=%v status=%s", replayed, record.Status)
	}
	if record.Generation.ModelID != "granite4.1:8b" || record.GuardianInvocation.ModelID != "granite4.1-guardian:8b" {
		t.Fatalf("unexpected model lineage: %+v", record)
	}
	for _, passage := range record.Retrieval.Passages {
		if strings.Contains(passage.Text, "TENANT_B_SECRET_MARKER") {
			t.Fatal("cross-tenant prior case leaked")
		}
	}
	afterProjection, err := store.AlertStore.VerifyCase(projection.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := CanonicalJSON(afterProjection)
	if string(before) != string(after) {
		t.Fatal("AI assistance mutated deterministic case projection")
	}
	replayedRecord, replayed, err := store.Assist(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed || replayedRecord.RecordSHA256 != record.RecordSHA256 {
		t.Fatal("idempotent replay was not exact")
	}
	changed := req
	changed.Task = "evidence_summary"
	if _, _, err := store.Assist(context.Background(), changed); err == nil || !strings.Contains(err.Error(), "idempotency conflict") {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
	review, replayed, err := store.Review(ReviewRequest{CaseID: projection.CaseID, AssistanceID: record.AssistanceID, Action: "accept", Actor: "analyst-a", Reason: "use as draft", OccurredAt: "2026-07-15T16:02:00Z", IdempotencyKey: "review-1"})
	if err != nil || replayed || review.Action != "accept" {
		t.Fatalf("review failed: %+v %v", review, err)
	}
	if _, err := store.VerifyAudit(); err != nil {
		t.Fatal(err)
	}
}

func TestGuardianRejectionAndModelUnavailableAreFailSoft(t *testing.T) {
	store, projection := buildTestStore(t, nil)
	client := store.Client.(*FixtureModelClient)
	guardianRaw, _ := json.Marshal(GuardianAssessment{SchemaVersion: GuardianSchemaV1, Grounded: false, Relevant: true, Safe: true, CitationsValid: true, UnsupportedClaims: []string{"unsupported"}})
	client.Responses["granite4.1-guardian:8b"] = ModelResponse{Content: string(guardianRaw)}
	record, _, err := store.Assist(context.Background(), AssistanceRequest{CaseID: projection.CaseID, Task: "draft_note", Actor: "analyst-a", OccurredAt: "2026-07-15T16:03:00Z", IdempotencyKey: "assist-reject"})
	if err != nil || record.Status != "rejected_guardrail" {
		t.Fatalf("expected guardrail rejection, got %s %v", record.Status, err)
	}
	if _, _, err := store.Review(ReviewRequest{CaseID: projection.CaseID, AssistanceID: record.AssistanceID, Action: "accept", Actor: "analyst-a", OccurredAt: "2026-07-15T16:04:00Z", IdempotencyKey: "review-reject"}); err == nil {
		t.Fatal("rejected draft was accepted")
	}

	unavailableClient := goodFixtureClient(store.Snapshot)
	unavailableClient.Errors["granite4.1:8b"] = errors.New("ollama unavailable")
	unavailableStore, unavailableCase := buildTestStore(t, unavailableClient)
	unavailable, _, err := unavailableStore.Assist(context.Background(), AssistanceRequest{CaseID: unavailableCase.CaseID, Task: "draft_note", Actor: "analyst-a", OccurredAt: "2026-07-15T16:05:00Z", IdempotencyKey: "assist-unavailable"})
	if err != nil {
		t.Fatal(err)
	}
	if unavailable.Status != "model_unavailable" || unavailable.Draft != nil {
		t.Fatalf("unexpected unavailable record: %+v", unavailable)
	}
	if _, err := unavailableStore.AlertStore.VerifyCase(unavailableCase.CaseID); err != nil {
		t.Fatal("case became unavailable with model failure")
	}
}

func TestCorpusDeterminismAndTenantIsolation(t *testing.T) {
	manifest, err := LoadManifest(filepath.Join("..", "..", "test", "fixtures", "case-assistance", "corpus", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := CompileSnapshot(manifest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CompileSnapshot(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if first.SnapshotSHA256 != second.SnapshotSHA256 {
		t.Fatal("corpus compilation is not deterministic")
	}
	result, err := Query(first, RetrievalQuery{TenantID: "tenant-a", Terms: []string{"secret marker", "exact identifier"}, TopK: 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range result.Passages {
		if strings.Contains(p.Text, "TENANT_B_SECRET_MARKER") {
			t.Fatal("tenant-b passage leaked")
		}
	}
}

func TestSchemaContainsImmutablePostgresContracts(t *testing.T) {
	for _, marker := range []string{"CREATE TABLE IF NOT EXISTS rag_corpus_snapshot", "CREATE TABLE IF NOT EXISTS case_assistance_record", "case_assistance_reject_immutable_mutation"} {
		if !strings.Contains(SchemaSQL, marker) {
			t.Fatalf("schema is missing %s", marker)
		}
	}
}
