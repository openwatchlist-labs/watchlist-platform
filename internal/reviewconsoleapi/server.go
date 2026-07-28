package reviewconsoleapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/openwatchlist-labs/watchlist-platform/internal/alertcase"
	"github.com/openwatchlist-labs/watchlist-platform/internal/assistancerag"
	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewauth"
	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewconsole"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

type Server struct {
	Config          Config
	Registry        reviewauth.Registry
	Tokens          *reviewauth.TokenService
	AlertStore      *alertcase.Store
	AssistanceStore *assistancerag.Store
	ModelClient     assistancerag.ModelClient
	SecurityAudit   *reviewauth.SecurityAuditStore
	counter         atomic.Uint64
}
type ac struct {
	Claims                reviewauth.Claims
	Permissions           []string
	RequestID, Permission string
}
type key struct{}
type sw struct {
	http.ResponseWriter
	status int
}

func (w *sw) WriteHeader(c int) {
	if w.status == 0 {
		w.status = c
	}
	w.ResponseWriter.WriteHeader(c)
}
func (w *sw) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(b)
}
func New(l Loaded) (*Server, error) {
	as, e := alertcase.NewStore(l.Config.AlertCaseStateDirectory, l.Policy, "review-console-alert-case")
	if e != nil {
		return nil, e
	}
	var mc assistancerag.ModelClient
	if l.Config.ModelMode == "fixture" {
		mc, e = assistancerag.LoadFixtureModelClient(l.Config.ModelFixturePath)
	} else {
		mc = assistancerag.NewOllamaClient(l.Config.OllamaBaseURL, l.Config.Timeout())
	}
	if e != nil {
		return nil, e
	}
	rs, e := assistancerag.NewStore(l.Config.AssistanceStateDirectory, "review-console-assistance", as, l.Snapshot, l.Config.Models, mc)
	if e != nil {
		return nil, e
	}
	ts, e := reviewauth.NewTokenService(l.Registry, l.SigningKey, l.Config.MaxTTL())
	if e != nil {
		return nil, e
	}
	au, e := reviewauth.NewSecurityAuditStore(l.Config.SecurityAuditDirectory, l.Config.SecurityAuditStreamID)
	if e != nil {
		return nil, e
	}
	return &Server{Config: l.Config, Registry: l.Registry, Tokens: ts, AlertStore: as, AssistanceStore: rs, ModelClient: mc, SecurityAudit: au}, nil
}
func (s *Server) Check(ctx context.Context) error {
	if e := reviewauth.VerifyRegistry(s.Registry); e != nil {
		return e
	}
	if _, e := s.AlertStore.Status(); e != nil {
		return e
	}
	if _, e := s.AssistanceStore.Status(); e != nil {
		return e
	}
	if _, e := s.SecurityAudit.Verify(); e != nil {
		return e
	}
	if s.Config.OllamaRequired {
		m, e := s.ModelClient.ListModels(ctx)
		if e != nil {
			return e
		}
		set := map[string]bool{}
		for _, x := range m {
			set[x] = true
		}
		for _, x := range []string{s.Config.Models.PrimaryModelID, s.Config.Models.ReasoningModelID, s.Config.Models.GuardianModelID} {
			if !set[x] {
				return fmt.Errorf("required model is not installed: %s", x)
			}
		}
	}
	return nil
}
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { jsonOut(w, 200, map[string]any{"status": "ok"}) })
	m.HandleFunc("GET /readyz", s.ready)
	m.HandleFunc("GET /console", s.console)
	m.HandleFunc("GET /console/", s.console)
	m.HandleFunc("GET /assets/review-console.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		io.WriteString(w, consoleCSS)
	})
	m.HandleFunc("GET /assets/review-console.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, consoleJS)
	})
	m.Handle("GET /v1/me", s.sec(s.me))
	m.Handle("GET /v1/alerts", s.sec(s.alerts))
	m.Handle("GET /v1/alerts/{id}", s.sec(s.alert))
	m.Handle("GET /v1/cases", s.sec(s.cases))
	m.Handle("POST /v1/cases", s.sec(s.createCase))
	m.Handle("GET /v1/cases/{id}", s.sec(s.caseGet))
	m.Handle("POST /v1/cases/{id}/events", s.sec(s.caseEvent))
	m.Handle("GET /v1/cases/{id}/assistance", s.sec(s.assistanceList))
	m.Handle("POST /v1/cases/{id}/assistance", s.sec(s.assist))
	m.Handle("GET /v1/cases/{id}/assistance/{assistance_id}", s.sec(s.assistanceGet))
	m.Handle("POST /v1/cases/{id}/assistance/{assistance_id}/review", s.sec(s.assistanceReview))
	m.Handle("GET /v1/security/audit", s.sec(s.auditList))
	m.Handle("GET /v1/security/audit/verify", s.sec(s.auditVerify))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		m.ServeHTTP(w, r)
	})
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if e := s.Check(r.Context()); e != nil {
		jsonOut(w, 503, map[string]any{"status": "not_ready", "error": e.Error()})
		return
	}
	jsonOut(w, 200, map[string]any{"status": "ok", "registry_sha256": s.Registry.RegistrySHA256, "model_mode": s.Config.ModelMode, "console_enabled": s.Config.ConsoleEnabled})
}
func (s *Server) console(w http.ResponseWriter, r *http.Request) {
	if !s.Config.ConsoleEnabled {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	io.WriteString(w, consoleHTML)
}
func (s *Server) sec(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-ID")
		if rid == "" {
			rid = fmt.Sprintf("req-%d-%d", time.Now().UnixNano(), s.counter.Add(1))
		}
		w.Header().Set("X-Request-ID", rid)
		b := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(b, "Bearer ") {
			s.anon(r, rid, 401, "missing bearer token")
			jsonOut(w, 401, map[string]any{"error": "authentication required", "request_id": rid})
			return
		}
		claims, e := s.Tokens.Parse(strings.TrimSpace(strings.TrimPrefix(b, "Bearer ")), time.Now().UTC())
		if e != nil {
			s.anon(r, rid, 401, e.Error())
			jsonOut(w, 401, map[string]any{"error": "invalid access token", "detail": e.Error(), "request_id": rid})
			return
		}
		x := &ac{Claims: claims, Permissions: s.Registry.Permissions(claims.Roles), RequestID: rid}
		r = r.WithContext(context.WithValue(r.Context(), key{}, x))
		ww := &sw{ResponseWriter: w}
		next(ww, r)
		if ww.status == 0 {
			ww.status = 200
		}
		out := "allowed"
		if ww.status >= 400 {
			out = "denied"
		}
		s.SecurityAudit.Append(reviewauth.SecurityAuditEvent{OccurredAt: time.Now().UTC().Format(time.RFC3339Nano), RequestID: rid, TokenIDHash: reviewauth.HashString(claims.TokenID), Subject: claims.Subject, TenantID: claims.TenantID, Permission: x.Permission, Method: r.Method, Path: r.URL.Path, Outcome: out, StatusCode: ww.status})
	})
}
func (s *Server) anon(r *http.Request, id string, status int, detail string) {
	d, _ := json.Marshal(map[string]string{"detail": detail})
	s.SecurityAudit.Append(reviewauth.SecurityAuditEvent{OccurredAt: time.Now().UTC().Format(time.RFC3339Nano), RequestID: id, Method: r.Method, Path: r.URL.Path, Outcome: "denied", StatusCode: status, Detail: d})
}
func ctx(r *http.Request) *ac { x, _ := r.Context().Value(key{}).(*ac); return x }
func permit(w http.ResponseWriter, r *http.Request, p string) bool {
	x := ctx(r)
	x.Permission = p
	if !reviewauth.PermissionAllowed(x.Permissions, p) {
		jsonOut(w, 403, map[string]any{"error": "permission denied", "permission": p, "request_id": x.RequestID})
		return false
	}
	return true
}
func tenantOK(c reviewauth.Claims, t string) bool { return c.TenantID == t || c.TenantID == "*" }
func tenant(r *http.Request) string {
	x := ctx(r)
	if x.Claims.TenantID != "*" {
		return x.Claims.TenantID
	}
	return strings.TrimSpace(r.URL.Query().Get("tenant_id"))
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	x := ctx(r)
	jsonOut(w, 200, map[string]any{"claims": x.Claims, "permissions": x.Permissions, "registry_sha256": s.Registry.RegistrySHA256})
}
func (s *Server) alerts(w http.ResponseWriter, r *http.Request) {
	if !permit(w, r, "alert.read") {
		return
	}
	t := tenant(r)
	if t == "" {
		jsonOut(w, 400, map[string]any{"error": "tenant_id is required for wildcard tokens"})
		return
	}
	a, e := reviewconsole.ListAlerts(s.Config.AlertCaseStateDirectory, t, reviewconsole.ParseLimit(r.URL.Query().Get("limit"), 100, 500))
	if e != nil {
		errOut(w, e)
		return
	}
	jsonOut(w, 200, map[string]any{"tenant_id": t, "alerts": a})
}
func (s *Server) alert(w http.ResponseWriter, r *http.Request) {
	if !permit(w, r, "alert.read") {
		return
	}
	a, e := s.AlertStore.Alert(r.PathValue("id"))
	if e != nil || !tenantOK(ctx(r).Claims, a.TenantID) {
		jsonOut(w, 404, map[string]any{"error": "alert not found"})
		return
	}
	jsonOut(w, 200, a)
}
func (s *Server) cases(w http.ResponseWriter, r *http.Request) {
	if !permit(w, r, "case.read") {
		return
	}
	t := tenant(r)
	if t == "" {
		jsonOut(w, 400, map[string]any{"error": "tenant_id is required for wildcard tokens"})
		return
	}
	c, e := reviewconsole.ListCases(s.Config.AlertCaseStateDirectory, t, reviewconsole.CaseFilter{State: r.URL.Query().Get("state"), AssignedTo: r.URL.Query().Get("assigned_to"), Limit: reviewconsole.ParseLimit(r.URL.Query().Get("limit"), 100, 500)})
	if e != nil {
		errOut(w, e)
		return
	}
	jsonOut(w, 200, map[string]any{"tenant_id": t, "cases": c})
}
func (s *Server) createCase(w http.ResponseWriter, r *http.Request) {
	if !permit(w, r, "case.create") {
		return
	}
	var q alertcase.CreateCaseRequest
	if !s.decode(w, r, &q) {
		return
	}
	x := ctx(r)
	if x.Claims.TenantID == "*" {
		jsonOut(w, 400, map[string]any{"error": "wildcard tokens must not create cases"})
		return
	}
	q.TenantID = x.Claims.TenantID
	q.CreatedBy = x.Claims.Subject
	if q.IdempotencyKey == "" {
		q.IdempotencyKey = r.Header.Get("Idempotency-Key")
	}
	c, re, e := s.AlertStore.CreateCase(q)
	if e != nil {
		storeErr(w, e)
		return
	}
	status := 201
	if re {
		status = 200
	}
	jsonOut(w, status, map[string]any{"case": c, "replayed": re})
}
func (s *Server) caseGet(w http.ResponseWriter, r *http.Request) {
	if !permit(w, r, "case.read") {
		return
	}
	c, e := s.AlertStore.Case(r.PathValue("id"))
	if e != nil || !tenantOK(ctx(r).Claims, c.TenantID) {
		jsonOut(w, 404, map[string]any{"error": "case not found"})
		return
	}
	jsonOut(w, 200, c)
}
func actionPermission(action string, p json.RawMessage, subject string) (string, error) {
	switch action {
	case "assign":
		var x struct {
			Assignee string `json:"assignee"`
		}
		json.Unmarshal(p, &x)
		if x.Assignee == subject {
			return "case.assign_self", nil
		}
		return "case.assign_any", nil
	case "start_investigation":
		return "case.investigate", nil
	case "request_evidence":
		return "evidence.request", nil
	case "submit_evidence":
		return "evidence.submit", nil
	case "propose_decision":
		return "decision.propose", nil
	case "approve_decision", "reject_decision":
		return "decision.approve", nil
	case "reopen":
		return "case.reopen", nil
	case "link_rescreen":
		return "case.rescreen", nil
	}
	return "", fmt.Errorf("unsupported case action %q", action)
}
func (s *Server) caseEvent(w http.ResponseWriter, r *http.Request) {
	c, e := s.AlertStore.Case(r.PathValue("id"))
	if e != nil || !tenantOK(ctx(r).Claims, c.TenantID) {
		jsonOut(w, 404, map[string]any{"error": "case not found"})
		return
	}
	var q alertcase.CaseEventRequest
	if !s.decode(w, r, &q) {
		return
	}
	q.CaseID = c.CaseID
	q.Actor = ctx(r).Claims.Subject
	if q.IdempotencyKey == "" {
		q.IdempotencyKey = r.Header.Get("Idempotency-Key")
	}
	p, e := actionPermission(q.Action, q.Payload, q.Actor)
	if e != nil {
		jsonOut(w, 400, map[string]any{"error": e.Error()})
		return
	}
	if !permit(w, r, p) {
		return
	}
	c2, ev, re, e := s.AlertStore.ApplyCaseEvent(q)
	if e != nil {
		storeErr(w, e)
		return
	}
	jsonOut(w, 200, map[string]any{"case": c2, "event": ev, "replayed": re})
}
func (s *Server) assistanceList(w http.ResponseWriter, r *http.Request) {
	if !permit(w, r, "assistance.read") {
		return
	}
	c, e := s.AlertStore.Case(r.PathValue("id"))
	if e != nil || !tenantOK(ctx(r).Claims, c.TenantID) {
		jsonOut(w, 404, map[string]any{"error": "case not found"})
		return
	}
	a, e := reviewconsole.ListAssistance(s.Config.AssistanceStateDirectory, c.TenantID, c.CaseID, reviewconsole.ParseLimit(r.URL.Query().Get("limit"), 50, 200))
	if e != nil {
		errOut(w, e)
		return
	}
	jsonOut(w, 200, map[string]any{"assistance": a})
}
func (s *Server) assist(w http.ResponseWriter, r *http.Request) {
	if !permit(w, r, "assistance.request") {
		return
	}
	c, e := s.AlertStore.Case(r.PathValue("id"))
	if e != nil || !tenantOK(ctx(r).Claims, c.TenantID) {
		jsonOut(w, 404, map[string]any{"error": "case not found"})
		return
	}
	var q assistancerag.AssistanceRequest
	if !s.decode(w, r, &q) {
		return
	}
	q.CaseID = c.CaseID
	q.TenantID = c.TenantID
	q.Actor = ctx(r).Claims.Subject
	if q.IdempotencyKey == "" {
		q.IdempotencyKey = r.Header.Get("Idempotency-Key")
	}
	a, re, e := s.AssistanceStore.Assist(r.Context(), q)
	if e != nil {
		storeErr(w, e)
		return
	}
	status := 201
	if re {
		status = 200
	} else if a.Status != "completed" {
		status = 202
	}
	jsonOut(w, status, map[string]any{"assistance": a, "replayed": re})
}
func (s *Server) assistanceGet(w http.ResponseWriter, r *http.Request) {
	if !permit(w, r, "assistance.read") {
		return
	}
	a, e := s.AssistanceStore.Record(r.PathValue("assistance_id"))
	if e != nil || a.CaseID != r.PathValue("id") || !tenantOK(ctx(r).Claims, a.TenantID) {
		jsonOut(w, 404, map[string]any{"error": "assistance not found"})
		return
	}
	jsonOut(w, 200, a)
}
func (s *Server) assistanceReview(w http.ResponseWriter, r *http.Request) {
	if !permit(w, r, "assistance.review") {
		return
	}
	a, e := s.AssistanceStore.Record(r.PathValue("assistance_id"))
	if e != nil || a.CaseID != r.PathValue("id") || !tenantOK(ctx(r).Claims, a.TenantID) {
		jsonOut(w, 404, map[string]any{"error": "assistance not found"})
		return
	}
	if a.Actor == ctx(r).Claims.Subject {
		jsonOut(w, 409, map[string]any{"error": "four-eyes rule: assistance reviewer must differ from requester"})
		return
	}
	var q assistancerag.ReviewRequest
	if !s.decode(w, r, &q) {
		return
	}
	q.CaseID = a.CaseID
	q.AssistanceID = a.AssistanceID
	q.Actor = ctx(r).Claims.Subject
	if q.IdempotencyKey == "" {
		q.IdempotencyKey = r.Header.Get("Idempotency-Key")
	}
	ev, re, e := s.AssistanceStore.Review(q)
	if e != nil {
		storeErr(w, e)
		return
	}
	jsonOut(w, 200, map[string]any{"review": ev, "replayed": re})
}
func (s *Server) auditList(w http.ResponseWriter, r *http.Request) {
	if !permit(w, r, "security.audit.read") {
		return
	}
	x, e := s.SecurityAudit.List(reviewconsole.ParseLimit(r.URL.Query().Get("limit"), 100, 1000))
	if e != nil {
		errOut(w, e)
		return
	}
	jsonOut(w, 200, map[string]any{"events": x})
}
func (s *Server) auditVerify(w http.ResponseWriter, r *http.Request) {
	if !permit(w, r, "security.audit.read") {
		return
	}
	x, e := s.SecurityAudit.Verify()
	if e != nil {
		jsonOut(w, 409, map[string]any{"error": e.Error()})
		return
	}
	jsonOut(w, 200, x)
}
func (s *Server) decode(w http.ResponseWriter, r *http.Request, d any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, s.Config.MaxBodyBytes)
	x := json.NewDecoder(r.Body)
	x.DisallowUnknownFields()
	if e := x.Decode(d); e != nil {
		jsonOut(w, 400, map[string]any{"error": e.Error()})
		return false
	}
	var extra any
	if e := x.Decode(&extra); e != io.EOF {
		if e == nil {
			e = errors.New("multiple JSON values are not allowed")
		}
		jsonOut(w, 400, map[string]any{"error": e.Error()})
		return false
	}
	return true
}
func storeErr(w http.ResponseWriter, e error) {
	c := 400
	m := e.Error()
	if strings.Contains(m, "conflict") || strings.Contains(m, "four-eyes") || strings.Contains(m, "checksum") {
		c = 409
	}
	jsonOut(w, c, map[string]any{"error": m})
}
func errOut(w http.ResponseWriter, e error) { jsonOut(w, 500, map[string]any{"error": e.Error()}) }
func jsonOut(w http.ResponseWriter, c int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	x := json.NewEncoder(w)
	x.SetEscapeHTML(false)
	x.Encode(v)
}

var _ = os.IsNotExist
