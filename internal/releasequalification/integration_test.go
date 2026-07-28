package releasequalification

import (
	"context"
	"encoding/json"
	"github.com/openwatchlist-labs/watchlist-platform/internal/alertcase"
	"github.com/openwatchlist-labs/watchlist-platform/internal/assistancerag"
	"github.com/openwatchlist-labs/watchlist-platform/internal/iso20022coverage"
	"github.com/openwatchlist-labs/watchlist-platform/internal/vendoradapter"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAcceptedProductPath(t *testing.T) {
	m, e := iso20022coverage.LoadMatrix("../../configs/iso20022/family-matrix-r1.json")
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile("../../test/fixtures/iso20022-phase9d/pacs008.xml")
	if e != nil {
		t.Fatal(e)
	}
	env, e := iso20022coverage.Parse(m, "fixture:pacs008", raw)
	if e != nil {
		t.Fatal(e)
	}
	if env.TransactionCount != 2 || len(iso20022coverage.Project(env).Requests) == 0 {
		t.Fatal("canonical evidence/projection failed")
	}
	p, e := vendoradapter.LoadProfile("../../configs/vendor-adapters/generic-json-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	raw, e = os.ReadFile("../../test/fixtures/vendor-adapters/generic-alert.json")
	if e != nil {
		t.Fatal(e)
	}
	ve, e := vendoradapter.Convert(p, "fixture:generic", raw, time.Date(2026, 7, 15, 15, 0, 0, 0, time.UTC))
	if e != nil {
		t.Fatal(e)
	}
	policy, e := alertcase.LoadPolicy("../../test/fixtures/alert-case/policy.json")
	if e != nil {
		t.Fatal(e)
	}
	d := t.TempDir()
	as, e := alertcase.NewStore(filepath.Join(d, "alerts"), policy, "phase10")
	if e != nil {
		t.Fatal(e)
	}
	a, _, e := as.CreateAlert(ve.CreateAlertRequest)
	if e != nil {
		t.Fatal(e)
	}
	c, _, e := as.CreateCase(alertcase.CreateCaseRequest{TenantID: "tenant-a", AlertIDs: []string{a.AlertID}, CreatedBy: "alice", Reason: "phase10", OccurredAt: "2026-07-15T19:00:00Z", IdempotencyKey: "phase10-case"})
	if e != nil {
		t.Fatal(e)
	}
	apply := func(action, actor, key string, payload any) {
		b, _ := json.Marshal(payload)
		var err error
		c, _, _, err = as.ApplyCaseEvent(alertcase.CaseEventRequest{CaseID: c.CaseID, ExpectedRevision: c.Revision, Action: action, Actor: actor, OccurredAt: "2026-07-15T19:01:00Z", IdempotencyKey: key, Payload: b})
		if err != nil {
			t.Fatal(err)
		}
	}
	apply("assign", "alice", "a1", map[string]string{"assignee": "alice"})
	apply("start_investigation", "alice", "a2", nil)
	apply("propose_decision", "alice", "a3", map[string]any{"decision": map[string]string{"outcome": "false_positive"}})
	apply("approve_decision", "rachel", "a4", nil)
	if c.State != "resolved" {
		t.Fatal(c.State)
	}
	snap, e := assistancerag.LoadSnapshot("../../test/fixtures/case-assistance/corpus/snapshot.json")
	if e != nil {
		t.Fatal(e)
	}
	mc, e := assistancerag.LoadFixtureModelClient("../../test/fixtures/case-assistance/models/responses.json")
	if e != nil {
		t.Fatal(e)
	}
	rs, e := assistancerag.NewStore(filepath.Join(d, "rag"), "phase10", as, snap, assistancerag.ModelProfile{PrimaryModelID: "granite4.1:8b", ReasoningModelID: "qwen3:14b", GuardianModelID: "granite4.1-guardian:8b", ContextTokens: 16384, KeepAlive: "0", MaxOutputBytes: 65536}, mc)
	if e != nil {
		t.Fatal(e)
	}
	rec, _, e := rs.Assist(context.Background(), assistancerag.AssistanceRequest{CaseID: c.CaseID, Task: "draft_note", Actor: "alice", OccurredAt: "2026-07-15T19:02:00Z", IdempotencyKey: "phase10-assist"})
	if e != nil {
		t.Fatal(e)
	}
	if rec.Status != "completed" {
		t.Fatal(rec.Status)
	}
	_, _, e = rs.Review(assistancerag.ReviewRequest{CaseID: c.CaseID, AssistanceID: rec.AssistanceID, Action: "accept", Actor: "rachel", Reason: "qualified", OccurredAt: "2026-07-15T19:03:00Z", IdempotencyKey: "phase10-review"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = as.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
	if _, e = rs.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
