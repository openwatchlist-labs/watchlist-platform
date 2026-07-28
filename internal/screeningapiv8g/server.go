package screeningapiv8g

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningledger"
	"io"
	"net/http"
	"strings"
	"time"
)

const ShutdownTimeout = 10 * time.Second

type Server struct {
	config      Config
	ledger      *screeningledger.Store
	postgres    *screeningledger.PostgresSink
	client      *http.Client
	idempotency *idempotencyStore
}

func NewServer(config Config) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	key, err := screeningledger.LoadKey(config.SnapshotKeyFile, config.SnapshotKeyEnv)
	if err != nil {
		return nil, err
	}
	ledger, err := screeningledger.NewStore(config.LedgerDirectory, key, config.InstanceID)
	if err != nil {
		return nil, err
	}
	var sink *screeningledger.PostgresSink
	if config.PostgresDSN != "" {
		sink, err = screeningledger.NewPostgresSink(config.PostgresDSN, config.PSQLPath, nil, config.RequestTimeout())
		if err != nil {
			return nil, err
		}
		if config.AutoMigrate {
			if err := sink.Migrate(context.Background()); err != nil {
				return nil, fmt.Errorf("migrate screening ledger: %w", err)
			}
		}
	}
	return &Server{config: config, ledger: ledger, postgres: sink, client: &http.Client{Timeout: config.RequestTimeout()}, idempotency: newIdempotencyStore(config.IdempotencyDirectory)}, nil
}
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serveHTTP) }
func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET is required")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"schema_version": "openwatchlist.health.v1", "status": "ok"})
	case "/readyz":
		s.handleReady(w, r)
	case "/v1/screenings", "/v1/screenings/batch":
		s.handleScreening(w, r)
	default:
		writeError(w, http.StatusNotFound, "not_found", "route not found")
	}
}
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET is required")
		return
	}
	blockers := []map[string]string{}
	if _, err := s.ledger.Verify(); err != nil {
		blockers = append(blockers, map[string]string{"code": "ledger_chain_invalid", "detail": err.Error()})
	}
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, strings.TrimRight(s.config.UpstreamBaseURL, "/")+"/readyz", nil)
	if req != nil {
		resp, err := s.client.Do(req)
		if err != nil {
			blockers = append(blockers, map[string]string{"code": "upstream_not_ready", "detail": err.Error()})
		} else {
			_ = resp.Body.Close()
			if resp.StatusCode/100 != 2 {
				blockers = append(blockers, map[string]string{"code": "upstream_not_ready", "detail": resp.Status})
			}
		}
	}
	if s.config.RequirePostgres {
		if s.postgres == nil {
			blockers = append(blockers, map[string]string{"code": "postgres_not_configured", "detail": "PostgreSQL persistence is required"})
		} else if err := s.postgres.Ping(r.Context()); err != nil {
			blockers = append(blockers, map[string]string{"code": "postgres_not_ready", "detail": err.Error()})
		}
	}
	if len(blockers) > 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"schema_version": "openwatchlist.screening-ready.v4", "ready": false, "blockers": blockers})
		return
	}
	head, _ := s.ledger.Verify()
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": "openwatchlist.screening-ready.v4", "ready": true, "instance_id": s.config.InstanceID, "ledger_head": head, "postgres_required": s.config.RequirePostgres, "postgres_configured": s.postgres != nil})
}
func (s *Server) handleScreening(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST is required")
		return
	}
	body, err := readBoundedBody(w, r, s.config.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request_body", err.Error())
		return
	}
	correlationID := strings.TrimSpace(r.Header.Get("X-Correlation-ID"))
	if correlationID == "" {
		correlationID = correlationFromBody(body)
	}
	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	stored, replayed, err := s.idempotency.execute(r.URL.Path, idempotencyKey, body, func() (storedResponse, error) {
		return s.execute(r.Context(), r.URL.Path, body, correlationID, idempotencyKey)
	})
	if errors.Is(err, ErrIdempotencyConflict) {
		writeError(w, http.StatusConflict, "idempotency_key_reused", err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "screening_ledger_persistence_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Screening-Ledger-Event-ID", stored.EventID)
	w.Header().Set("X-Screening-Ledger-Event-SHA256", stored.EventSHA256)
	if stored.PostgresPersisted {
		w.Header().Set("X-Screening-Ledger-Postgres", "persisted")
	} else {
		w.Header().Set("X-Screening-Ledger-Postgres", "not-configured")
	}
	if replayed {
		w.Header().Set("Idempotent-Replay", "true")
	}
	w.WriteHeader(stored.StatusCode)
	_, _ = w.Write(stored.Body)
}
func (s *Server) execute(ctx context.Context, path string, body []byte, correlationID, idempotencyKey string) (storedResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(s.config.UpstreamBaseURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return storedResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Correlation-ID", correlationID)
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return storedResponse{}, err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, s.config.MaxBodyBytes))
	if err != nil {
		return storedResponse{}, err
	}
	result, err := s.ledger.Append(screeningledger.AppendInput{Route: path, HTTPStatus: resp.StatusCode, CorrelationID: correlationID, IdempotencyKey: idempotencyKey, RequestBytes: body, ResponseBytes: responseBody, OccurredAt: time.Now().UTC().Format(time.RFC3339Nano), Retention: s.config.Retention})
	if err != nil {
		return storedResponse{}, err
	}
	persisted := false
	if s.postgres != nil {
		requestEnvelope, err := s.ledger.LoadSnapshot(result.Event.RequestSnapshotSHA256)
		if err != nil {
			return storedResponse{}, err
		}
		responseEnvelope, err := s.ledger.LoadSnapshot(result.Event.ResponseSnapshotSHA256)
		if err != nil {
			return storedResponse{}, err
		}
		if err := s.postgres.Persist(ctx, result.Event, requestEnvelope, responseEnvelope); err != nil {
			_, _ = s.ledger.AppendAudit("postgres_replication_failed", s.config.InstanceID, err.Error(), result.Event.EventID, nil)
			if s.config.RequirePostgres {
				return storedResponse{}, err
			}
		} else {
			persisted = true
			if err := s.ledger.MarkReplicated(result.Event.EventID, ""); err != nil {
				return storedResponse{}, err
			}
			audit, _ := s.ledger.AppendAudit("postgres_replicated", s.config.InstanceID, "", result.Event.EventID, nil)
			_ = s.postgres.PersistAudit(ctx, audit)
		}
	}
	return storedResponse{StatusCode: resp.StatusCode, Body: json.RawMessage(responseBody), EventID: result.Event.EventID, EventSHA256: result.Event.EventSHA256, PostgresPersisted: persisted}, nil
}
func correlationFromBody(body []byte) string {
	var document map[string]any
	if json.Unmarshal(body, &document) == nil {
		if value, ok := document["request_id"].(string); ok && strings.TrimSpace(value) != "" {
			return value
		}
	}
	return "corr-" + digestHex(body)[:24]
}
func readBoundedBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	reader := http.MaxBytesReader(w, r.Body, limit)
	defer reader.Close()
	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("request body is required")
	}
	return raw, nil
}
func writeError(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, map[string]any{"schema_version": "openwatchlist.error.v1", "error": map[string]string{"code": code, "detail": detail}})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	raw, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}
