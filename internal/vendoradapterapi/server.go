package vendoradapterapi

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/openwatchlist-labs/watchlist-platform/internal/tenantctx"
	"github.com/openwatchlist-labs/watchlist-platform/internal/vendoradapter"
	"io"
	"net/http"
	"strings"
	"time"
)

type Server struct {
	Config   Config
	Profiles map[string]vendoradapter.Profile
	Store    *vendoradapter.Store
	Postgres *vendoradapter.PostgresSink
}

func New(c Config) (*Server, error) {
	ps, e := vendoradapter.LoadProfiles(c.ProfilesDirectory)
	if e != nil {
		return nil, e
	}
	s, e := vendoradapter.NewStore(c.StateDirectory, c.StreamID, time.Now)
	if e != nil {
		return nil, e
	}
	var pg *vendoradapter.PostgresSink
	if strings.TrimSpace(c.PostgresDSN) != "" {
		pg, e = vendoradapter.NewPostgresSink(c.PostgresDSN, c.PSQLPath, c.Timeout())
		if e != nil {
			return nil, e
		}
	}
	return &Server{c, ps, s, pg}, nil
}
func (s *Server) Check(ctx context.Context) error {
	if _, e := s.Store.Verify(); e != nil {
		return e
	}
	if s.Config.PostgresRequired {
		if s.Postgres == nil {
			return errors.New("PostgreSQL is required")
		}
		return s.Postgres.Ping(ctx)
	}
	return nil
}
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { write(w, 200, map[string]any{"status": "ok"}) })
	m.HandleFunc("GET /readyz", s.ready)
	m.HandleFunc("GET /v1/vendor-adapters", s.list)
	m.HandleFunc("POST /v1/vendor-alerts/{adapter}", s.ingest)
	return m
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if e := s.Check(r.Context()); e != nil {
		write(w, 503, map[string]any{"status": "not_ready", "error": e.Error()})
		return
	}
	write(w, 200, map[string]any{"status": "ok", "profile_count": len(s.Profiles), "postgres_required": s.Config.PostgresRequired})
}
func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	write(w, 200, map[string]any{"profiles": vendoradapter.ProfileSummary(s.Profiles)})
}
func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	p, ok := s.Profiles[r.PathValue("adapter")]
	if !ok {
		write(w, 404, map[string]any{"error": "adapter profile not found"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, min(s.Config.MaxBodyBytes, p.MaxSourceBytes))
	raw, e := io.ReadAll(r.Body)
	if e != nil {
		write(w, 400, map[string]any{"error": e.Error()})
		return
	}
	source := r.Header.Get("X-Source-Ref")
	if source == "" {
		source = "http:" + p.AdapterID
	}
	env, replay, e := s.Store.Process(p, source, raw)
	if e != nil {
		code := 400
		if strings.Contains(e.Error(), "idempotency conflict") {
			code = 409
		}
		write(w, code, map[string]any{"error": e.Error()})
		return
	}
	if s.Postgres != nil {
		receipt, re := s.Store.Receipt(p.AdapterID, env.CreateAlertRequest.IdempotencyKey)
		if re == nil {
			re = s.Postgres.Persist(r.Context(), env, receipt)
		}
		// Tenant-integrity failures are surfaced regardless of
		// PostgresRequired: they mean the write was scoped to the wrong
		// tenant (or no tenant at all), not that Postgres is unreachable.
		// PostgresRequired=false is meant to tolerate the latter --
		// degrade to the local filesystem write on an outage -- and must
		// not silently swallow the former.
		if errors.Is(re, tenantctx.ErrTenantMismatch) {
			write(w, 403, map[string]any{"error": "tenant mismatch", "detail": re.Error(), "record_id": env.RecordID})
			return
		}
		if errors.Is(re, tenantctx.ErrNoBoundTenant) {
			write(w, 500, map[string]any{"error": "tenant binding integrity failure", "detail": re.Error(), "record_id": env.RecordID})
			return
		}
		if re != nil && s.Config.PostgresRequired {
			write(w, 503, map[string]any{"error": "durable PostgreSQL persistence failed", "detail": re.Error(), "record_id": env.RecordID})
			return
		}
	}
	code := 201
	if replay {
		code = 200
	}
	write(w, code, map[string]any{"envelope": env, "replayed": replay})
}
func write(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
