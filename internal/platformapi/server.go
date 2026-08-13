package platformapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openwatchlist-labs/watchlist-platform/internal/productionops"
	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewconsoleapi"
)

type Server struct {
	Config         productionops.RuntimeConfig
	Quotas         productionops.QuotaRegistry
	Review         *reviewconsoleapi.Server
	Outbox         *productionops.OutboxStore
	Metrics        *productionops.Metrics
	rate           *productionops.RateLimiter
	concurrency    *productionops.ConcurrencyLimiter
	draining       atomic.Bool
	requestCounter atomic.Uint64
	tempFiles      []string

	// pgPool backs the /readyz PostgreSQL probe. platformapi is a
	// separate process from the three sink-holding services and never
	// had a pool of its own to reuse (ADR-0005 §11.2) -- this is that
	// pool, constructed once at startup, nil when PostgreSQL readiness
	// isn't configured.
	pgPool *pgxpool.Pool
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}
func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, e := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, e
}

func New(configPath string) (*Server, error) {
	c, err := productionops.LoadRuntimeConfig(configPath)
	if err != nil {
		return nil, err
	}
	q, err := productionops.LoadQuotaRegistry(c.QuotaRegistryPath)
	if err != nil {
		return nil, err
	}
	if err = productionops.EnsureProductionSecretBoundary(c); err != nil {
		return nil, err
	}
	loaded, temp, err := loadReview(c)
	if err != nil {
		return nil, err
	}
	rs, err := reviewconsoleapi.New(loaded)
	if err != nil {
		if temp != "" {
			os.Remove(temp)
		}
		return nil, err
	}
	outbox, err := productionops.NewOutboxStore(c.OutboxDirectory, "platform-outbox-phase9g")
	if err != nil {
		return nil, err
	}
	pgPool, err := productionops.NewReadinessPool(context.Background(), c)
	if err != nil {
		if temp != "" {
			os.Remove(temp)
		}
		return nil, err
	}
	s := &Server{Config: c, Quotas: q, Review: rs, Outbox: outbox, Metrics: productionops.NewMetrics(), rate: productionops.NewRateLimiter(), concurrency: productionops.NewConcurrencyLimiter(c.GlobalConcurrency, c.DefaultTenantConcurrency), pgPool: pgPool}
	if temp != "" {
		s.tempFiles = append(s.tempFiles, temp)
	}
	return s, nil
}
func loadReview(c productionops.RuntimeConfig) (reviewconsoleapi.Loaded, string, error) {
	if c.Environment != "production" {
		l, e := reviewconsoleapi.LoadConfig(c.ReviewConsoleConfigPath)
		return l, "", e
	}
	raw, err := os.ReadFile(c.ReviewConsoleConfigPath)
	if err != nil {
		return reviewconsoleapi.Loaded{}, "", err
	}
	var rc reviewconsoleapi.Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&rc); err != nil {
		return reviewconsoleapi.Loaded{}, "", err
	}
	if rc.ModelMode == "fixture" {
		return reviewconsoleapi.Loaded{}, "", errors.New("production runtime rejects fixture model mode")
	}
	base := filepath.Dir(c.ReviewConsoleConfigPath)
	resolve := func(v string) string {
		if v == "" || filepath.IsAbs(v) {
			return v
		}
		return filepath.Clean(filepath.Join(base, v))
	}
	rc.AlertCaseStateDirectory = resolve(rc.AlertCaseStateDirectory)
	rc.AssistanceStateDirectory = resolve(rc.AssistanceStateDirectory)
	rc.AlertPolicyPath = resolve(rc.AlertPolicyPath)
	rc.CorpusSnapshotPath = resolve(rc.CorpusSnapshotPath)
	rc.ModelFixturePath = resolve(rc.ModelFixturePath)
	rc.AuthRegistryPath = resolve(rc.AuthRegistryPath)
	rc.SecurityAuditDirectory = resolve(rc.SecurityAuditDirectory)
	key, err := productionops.ResolveSigningKey(c)
	if err != nil {
		return reviewconsoleapi.Loaded{}, "", err
	}
	keyPath := filepath.Join(c.RuntimeStateDirectory, ".runtime-signing-key.hex")
	if err = os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return reviewconsoleapi.Loaded{}, "", err
	}
	if err = os.WriteFile(keyPath, []byte(hex.EncodeToString(key)+"\n"), 0600); err != nil {
		return reviewconsoleapi.Loaded{}, "", err
	}
	rc.SigningKeyPath = keyPath
	rc.ListenAddress = c.ListenAddress
	cfgPath := filepath.Join(c.RuntimeStateDirectory, ".runtime-review-config.json")
	b, _ := json.Marshal(rc)
	if err = os.WriteFile(cfgPath, b, 0600); err != nil {
		return reviewconsoleapi.Loaded{}, "", err
	}
	l, err := reviewconsoleapi.LoadConfig(cfgPath)
	_ = os.Remove(keyPath)
	return l, cfgPath, err
}
func (s *Server) Close() {
	for _, p := range s.tempFiles {
		os.Remove(p)
	}
	if s.Config.Environment == "production" {
		os.Remove(filepath.Join(s.Config.RuntimeStateDirectory, ".runtime-signing-key.hex"))
	}
	if s.pgPool != nil {
		s.pgPool.Close()
	}
}
func (s *Server) StartDraining()  { s.draining.Store(true) }
func (s *Server) InFlight() int64 { return s.Metrics.InFlight() }
func (s *Server) Check(ctx context.Context) productionops.ReadinessReport {
	// s.pgPool is a concrete *pgxpool.Pool; assigning a nil *pgxpool.Pool
	// straight into the productionops.Pinger interface parameter would
	// produce a non-nil interface wrapping a nil pointer, so pg is left
	// as a true nil interface unless the pool actually exists.
	var pg productionops.Pinger
	if s.pgPool != nil {
		pg = s.pgPool
	}
	r := productionops.CheckRuntime(ctx, s.Config, s.Quotas, pg)
	if err := s.Review.Check(ctx); err != nil {
		r.Status = "not_ready"
		r.Checks = append(r.Checks, productionops.CheckResult{Name: "review_console", Status: "failed", Detail: err.Error()})
	} else {
		r.Checks = append(r.Checks, productionops.CheckResult{Name: "review_console", Status: "ok"})
	}
	if s.draining.Load() {
		r.Status = "not_ready"
		r.Checks = append(r.Checks, productionops.CheckResult{Name: "draining", Status: "failed", Detail: "server is draining"})
	}
	return r
}
func (s *Server) Handler() http.Handler {
	inner := s.Review.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/livez":
			jsonOut(w, 200, map[string]any{"status": "ok"})
			return
		case "/healthz":
			jsonOut(w, 200, map[string]any{"status": "ok", "config_sha256": s.Config.ConfigSHA256})
			return
		case "/readyz":
			rep := s.Check(r.Context())
			code := 200
			if rep.Status != "ok" {
				code = 503
			}
			jsonOut(w, code, rep)
			return
		case "/metrics":
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			w.WriteHeader(200)
			_, _ = w.Write([]byte(s.Metrics.Render(s.Config.ConfigSHA256, s.Quotas.RegistrySHA256)))
			return
		}
		s.serve(inner, w, r)
	})
}
func (s *Server) serve(inner http.Handler, w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	s.Metrics.Begin()
	sw := &statusWriter{ResponseWriter: w}
	defer func() {
		if x := recover(); x != nil {
			s.Metrics.Panic()
			jsonOut(sw, 500, map[string]any{"error": "internal server error"})
		}
		if sw.status == 0 {
			sw.status = 200
		}
		s.Metrics.End(sw.status, time.Since(start))
		log.Printf("{\"ts\":%q,\"request_id\":%q,\"method\":%q,\"path\":%q,\"status\":%d,\"bytes\":%d,\"duration_ms\":%d}", time.Now().UTC().Format(time.RFC3339Nano), sw.Header().Get("X-Request-ID"), r.Method, r.URL.Path, sw.status, sw.bytes, time.Since(start).Milliseconds())
	}()
	rid := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if rid == "" {
		rid = fmt.Sprintf("opreq-%d-%d", time.Now().UnixNano(), s.requestCounter.Add(1))
	}
	sw.Header().Set("X-Request-ID", rid)
	if s.draining.Load() {
		jsonOut(sw, 503, map[string]any{"error": "server draining", "request_id": rid})
		return
	}
	if s.Config.TLS.Required && r.TLS == nil {
		secure := false
		if s.Config.TLS.TrustedProxy {
			secure = strings.EqualFold(strings.TrimSpace(r.Header.Get(s.Config.TLS.ForwardedProtoHeader)), "https")
		}
		if !secure {
			jsonOut(sw, 426, map[string]any{"error": "TLS required", "request_id": rid})
			return
		}
	}
	tenant, key := s.rateIdentity(r)
	quota := s.Quotas.ForTenant(tenant)
	if quota.MaxBodyBytes > s.Config.MaxBodyBytes {
		quota.MaxBodyBytes = s.Config.MaxBodyBytes
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(sw, r.Body, quota.MaxBodyBytes)
	}
	if !s.rate.Allow(key, time.Now(), quota.RequestsPerMinute, quota.Burst) {
		s.Metrics.RateLimited()
		sw.Header().Set("Retry-After", "1")
		jsonOut(sw, 429, map[string]any{"error": "rate limit exceeded", "request_id": rid})
		return
	}
	if !s.concurrency.Acquire(tenant, quota.MaxConcurrent) {
		s.Metrics.Overloaded()
		jsonOut(sw, 503, map[string]any{"error": "concurrency limit exceeded", "request_id": rid})
		return
	}
	defer s.concurrency.Release(tenant, quota.MaxConcurrent)
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.Config.RequestTimeoutSeconds)*time.Second)
	defer cancel()
	inner.ServeHTTP(sw, r.WithContext(ctx))
}
func (s *Server) rateIdentity(r *http.Request) (string, string) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(auth, "Bearer ") {
		tok := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if c, err := s.Review.Tokens.Parse(tok, time.Now().UTC()); err == nil {
			return c.TenantID, "tenant:" + c.TenantID + ":subject:" + c.Subject
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if host == "" {
		host = "unknown"
	}
	return "anonymous", "ip:" + host
}
func jsonOut(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
