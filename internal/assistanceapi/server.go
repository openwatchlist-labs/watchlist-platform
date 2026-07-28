package assistanceapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertcase"
	"github.com/openwatchlist-labs/watchlist-platform/internal/assistancerag"
)

type Server struct {
	Config   Config
	Store    *assistancerag.Store
	Postgres *assistancerag.PostgresSink
	Client   assistancerag.ModelClient
}

func New(cfg Config, policy alertcase.Policy, snapshot assistancerag.CorpusSnapshot) (*Server, error) {
	alertStore, err := alertcase.NewStore(cfg.AlertCaseStateDirectory, policy, "case-assistance-alert-view")
	if err != nil {
		return nil, err
	}
	var client assistancerag.ModelClient
	if cfg.ModelMode == "fixture" {
		client, err = assistancerag.LoadFixtureModelClient(cfg.ModelFixturePath)
	} else {
		client = assistancerag.NewOllamaClient(cfg.OllamaBaseURL, cfg.Timeout())
	}
	if err != nil {
		return nil, err
	}
	store, err := assistancerag.NewStore(cfg.AssistanceStateDirectory, cfg.StreamID, alertStore, snapshot, cfg.Models, client)
	if err != nil {
		return nil, err
	}
	var pg *assistancerag.PostgresSink
	if strings.TrimSpace(cfg.PostgresDSN) != "" {
		pg, err = assistancerag.NewPostgresSink(cfg.PostgresDSN, cfg.PSQLPath, nil, cfg.Timeout())
		if err != nil {
			return nil, err
		}
	}
	return &Server{Config: cfg, Store: store, Postgres: pg, Client: client}, nil
}

func (s *Server) Check(ctx context.Context) error {
	if _, err := s.Store.Status(); err != nil {
		return err
	}
	if err := assistancerag.VerifySnapshot(s.Store.Snapshot); err != nil {
		return err
	}
	if s.Config.OllamaRequired {
		models, err := s.Client.ListModels(ctx)
		if err != nil {
			return err
		}
		required := []string{s.Config.Models.PrimaryModelID, s.Config.Models.ReasoningModelID, s.Config.Models.GuardianModelID}
		set := map[string]struct{}{}
		for _, m := range models {
			set[m] = struct{}{}
		}
		for _, model := range required {
			if _, ok := set[model]; !ok {
				return fmt.Errorf("required Ollama model is not installed: %s", model)
			}
		}
	}
	if s.Config.PostgresRequired {
		if s.Postgres == nil {
			return errors.New("PostgreSQL is required")
		}
		if err := s.Postgres.Ping(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("POST /v1/cases/{id}/assistance", s.assist)
	mux.HandleFunc("GET /v1/cases/{id}/assistance/{assistance_id}", s.getRecord)
	mux.HandleFunc("POST /v1/cases/{id}/assistance/{assistance_id}/review", s.review)
	mux.HandleFunc("POST /v1/corpus/query", s.query)
	mux.HandleFunc("GET /v1/models", s.models)
	return mux
}
func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if err := s.Check(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "model_mode": s.Config.ModelMode, "ollama_required": s.Config.OllamaRequired, "postgres_required": s.Config.PostgresRequired, "snapshot_sha256": s.Store.Snapshot.SnapshotSHA256})
}
func (s *Server) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, s.Config.MaxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return false
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			err = errors.New("multiple JSON values are not allowed")
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return false
	}
	return true
}
func (s *Server) assist(w http.ResponseWriter, r *http.Request) {
	var req assistancerag.AssistanceRequest
	if !s.decode(w, r, &req) {
		return
	}
	req.CaseID = r.PathValue("id")
	if req.IdempotencyKey == "" {
		req.IdempotencyKey = r.Header.Get("Idempotency-Key")
	}
	record, replayed, err := s.Store.Assist(r.Context(), req)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if s.Postgres != nil {
		receipt, e := s.Store.Receipt("assist:"+req.CaseID, req.IdempotencyKey)
		if e == nil {
			e = s.Postgres.PersistSnapshot(r.Context(), s.Store.Snapshot)
		}
		if e == nil {
			e = s.Postgres.PersistRecord(r.Context(), record, receipt)
		}
		if e == nil {
			e = s.Postgres.SyncAudit(r.Context(), s.Config.AssistanceStateDirectory)
		}
		if e != nil && s.Config.PostgresRequired {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "durable PostgreSQL persistence failed", "detail": e.Error(), "assistance_id": record.AssistanceID})
			return
		}
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	} else if record.Status != "completed" {
		status = http.StatusAccepted
	}
	writeJSON(w, status, map[string]any{"assistance": record, "replayed": replayed})
}
func (s *Server) getRecord(w http.ResponseWriter, r *http.Request) {
	record, err := s.Store.Record(r.PathValue("assistance_id"))
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "assistance not found"})
			return
		}
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
		return
	}
	if record.CaseID != r.PathValue("id") {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "assistance not found"})
		return
	}
	writeJSON(w, http.StatusOK, record)
}
func (s *Server) review(w http.ResponseWriter, r *http.Request) {
	var req assistancerag.ReviewRequest
	if !s.decode(w, r, &req) {
		return
	}
	req.CaseID = r.PathValue("id")
	req.AssistanceID = r.PathValue("assistance_id")
	if req.IdempotencyKey == "" {
		req.IdempotencyKey = r.Header.Get("Idempotency-Key")
	}
	event, replayed, err := s.Store.Review(req)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if s.Postgres != nil {
		receipt, e := s.Store.Receipt("review:"+req.AssistanceID, req.IdempotencyKey)
		if e == nil {
			e = s.Postgres.PersistReview(r.Context(), event, receipt)
		}
		if e == nil {
			e = s.Postgres.SyncAudit(r.Context(), s.Config.AssistanceStateDirectory)
		}
		if e != nil && s.Config.PostgresRequired {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "durable PostgreSQL review persistence failed", "detail": e.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"review": event, "replayed": replayed})
}
func (s *Server) query(w http.ResponseWriter, r *http.Request) {
	var query assistancerag.RetrievalQuery
	if !s.decode(w, r, &query) {
		return
	}
	result, err := assistancerag.Query(s.Store.Snapshot, query)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}
func (s *Server) models(w http.ResponseWriter, r *http.Request) {
	models, err := s.Client.ListModels(r.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"models": models, "required": []string{s.Config.Models.PrimaryModelID, s.Config.Models.ReasoningModelID, s.Config.Models.GuardianModelID}})
}
func writeStoreError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	message := err.Error()
	if strings.Contains(message, "idempotency conflict") || strings.Contains(message, "checksum") || strings.Contains(message, "tenant_id does not match") {
		status = http.StatusConflict
	}
	writeJSON(w, status, map[string]any{"error": message})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		_, _ = fmt.Fprintln(w, `{"error":"encoding failure"}`)
	}
}
