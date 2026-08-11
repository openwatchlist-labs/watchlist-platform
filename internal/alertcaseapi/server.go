package alertcaseapi

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
)

type Server struct {
	Config   Config
	Store    *alertcase.Store
	Postgres *alertcase.PostgresSink
}

func New(cfg Config, policy alertcase.Policy) (*Server, error) {
	store, err := alertcase.NewStore(cfg.StateDirectory, policy, cfg.StreamID)
	if err != nil {
		return nil, err
	}
	var pg *alertcase.PostgresSink
	if strings.TrimSpace(cfg.PostgresDSN) != "" {
		pg, err = alertcase.NewPostgresSink(cfg.PostgresDSN, cfg.PSQLPath, nil, cfg.Timeout())
		if err != nil {
			return nil, err
		}
	}
	return &Server{Config: cfg, Store: store, Postgres: pg}, nil
}

func (s *Server) Check(ctx context.Context) error {
	if _, err := s.Store.Status(); err != nil {
		return err
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

func (s *Server) Handler() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("POST /v1/alerts", s.createAlert)
	mux.HandleFunc("POST /v1/alerts/batch", s.createAlertBatch)
	mux.HandleFunc("GET /v1/alerts/{id}", s.getAlert)
	mux.HandleFunc("POST /v1/cases", s.createCase)
	mux.HandleFunc("GET /v1/cases/{id}", s.getCase)
	mux.HandleFunc("POST /v1/cases/{id}/events", s.caseEvent)
	mux.HandleFunc("POST /v1/cases/{id}/verify", s.verifyCase)
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
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "postgres_required": s.Config.PostgresRequired})
}

func (s *Server) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, s.Config.MaxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return false
	}
	if err := ensureEOF(dec); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return false
	}
	return true
}

func ensureEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func (s *Server) createAlert(w http.ResponseWriter, r *http.Request) {
	var req alertcase.CreateAlertRequest
	if !s.decode(w, r, &req) {
		return
	}
	if req.CorrelationID == "" {
		req.CorrelationID = r.Header.Get("X-Correlation-ID")
	}
	if req.IdempotencyKey == "" {
		req.IdempotencyKey = r.Header.Get("Idempotency-Key")
	}
	alert, replayed, err := s.Store.CreateAlert(req)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if s.Postgres != nil {
		receipt, err := s.Store.Receipt("create-alert", req.IdempotencyKey)
		if err == nil {
			err = s.Postgres.PersistAlert(r.Context(), alert, receipt)
		}
		if err == nil {
			err = s.Postgres.SyncAudit(r.Context(), s.Config.StateDirectory)
		}
		if err != nil && s.Config.PostgresRequired {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "durable PostgreSQL persistence failed", "detail": err.Error(), "alert_id": alert.AlertID})
			return
		}
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"alert": alert, "replayed": replayed})
}

func (s *Server) createAlertBatch(w http.ResponseWriter, r *http.Request) {
	var req alertcase.CreateAlertBatchRequest
	if !s.decode(w, r, &req) {
		return
	}
	result, err := s.Store.CreateAlertBatch(req)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if s.Postgres != nil {
		for i, alert := range result.Alerts {
			child := req.Requests[i]
			receipt, persistErr := s.Store.Receipt("create-alert", child.IdempotencyKey)
			if persistErr == nil {
				persistErr = s.Postgres.PersistAlert(r.Context(), alert, receipt)
			}
			if persistErr != nil && s.Config.PostgresRequired {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "durable PostgreSQL batch persistence failed", "detail": persistErr.Error(), "completed": i})
				return
			}
		}
		if err := s.Postgres.SyncAudit(r.Context(), s.Config.StateDirectory); err != nil && s.Config.PostgresRequired {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "durable PostgreSQL audit persistence failed", "detail": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) getAlert(w http.ResponseWriter, r *http.Request) {
	alert, err := s.Store.Alert(r.PathValue("id"))
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "alert not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, alert)
}

func (s *Server) createCase(w http.ResponseWriter, r *http.Request) {
	var req alertcase.CreateCaseRequest
	if !s.decode(w, r, &req) {
		return
	}
	projection, replayed, err := s.Store.CreateCase(req)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if s.Postgres != nil {
		event, e1 := s.Store.LastCaseEvent(projection.CaseID)
		receipt, e2 := s.Store.Receipt("create-case", req.IdempotencyKey)
		if e1 == nil && e2 == nil {
			e1 = s.Postgres.PersistCase(r.Context(), projection, event, receipt)
		}
		if e1 == nil {
			e1 = s.Postgres.SyncAudit(r.Context(), s.Config.StateDirectory)
		}
		if e1 != nil && s.Config.PostgresRequired {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "durable PostgreSQL persistence failed", "detail": e1.Error(), "case_id": projection.CaseID})
			return
		}
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"case": projection, "replayed": replayed})
}

func (s *Server) getCase(w http.ResponseWriter, r *http.Request) {
	projection, err := s.Store.Case(r.PathValue("id"))
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "case not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, projection)
}

func (s *Server) caseEvent(w http.ResponseWriter, r *http.Request) {
	var req alertcase.CaseEventRequest
	if !s.decode(w, r, &req) {
		return
	}
	req.CaseID = r.PathValue("id")
	projection, event, replayed, err := s.Store.ApplyCaseEvent(req)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if s.Postgres != nil {
		scope := "case-event:" + req.CaseID + ":" + req.Action
		receipt, e1 := s.Store.Receipt(scope, req.IdempotencyKey)
		if e1 == nil {
			e1 = s.Postgres.PersistCase(r.Context(), projection, event, receipt)
		}
		if e1 != nil && s.Config.PostgresRequired {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "durable PostgreSQL persistence failed", "detail": e1.Error(), "case_id": req.CaseID})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"case": projection, "event": event, "replayed": replayed})
}

func (s *Server) verifyCase(w http.ResponseWriter, r *http.Request) {
	projection, err := s.Store.VerifyCase(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"status": "invalid", "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "case": projection})
}

func writeStoreError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	msg := err.Error()
	if strings.Contains(msg, "idempotency conflict") || strings.Contains(msg, "revision conflict") || strings.Contains(msg, "four-eyes") {
		status = http.StatusConflict
	}
	writeJSON(w, status, map[string]any{"error": msg})
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
