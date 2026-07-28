package screeningapiv8f

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/activationpromotion"
	"github.com/openwatchlist-labs/watchlist-platform/internal/scoringactivation"
)

const (
	ReadySchemaV3   = "openwatchlist.screening-ready.v3"
	ShutdownTimeout = 10 * time.Second
)

type Server struct {
	config      Config
	activations *scoringactivation.Manager
	promotions  *activationpromotion.Manager
	current     *upstream
	candidate   *upstream
	idempotency *idempotencyStore
}

func NewServer(config Config) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	activations, err := scoringactivation.NewManager(config.ActivationStateDirectory)
	if err != nil {
		return nil, err
	}
	if _, err := activations.Recover(); err != nil {
		return nil, fmt.Errorf("recover scoring activation: %w", err)
	}
	promotions, err := activationpromotion.NewManager(config.PromotionStateDirectory, activations)
	if err != nil {
		return nil, err
	}
	if _, err := promotions.Recover(); err != nil {
		return nil, fmt.Errorf("recover promotion state: %w", err)
	}
	status, err := promotions.Status()
	if err != nil {
		return nil, fmt.Errorf("load promotion status: %w", err)
	}
	if err := verifyBindings(activations, status); err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: config.RequestTimeout()}
	return &Server{
		config: config, activations: activations, promotions: promotions,
		current: newUpstream(config.CurrentBaseURL, client), candidate: newUpstream(config.CandidateBaseURL, client),
		idempotency: newIdempotencyStore(config.IdempotencyDirectory),
	}, nil
}

func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serveHTTP) }

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET is required")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "schema_version": "openwatchlist.health.v1"})
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
	status, err := s.promotions.Status()
	if err == nil {
		err = verifyBindings(s.activations, status)
	}
	if err == nil {
		err = s.readyForPhase(r.Context(), status)
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"schema_version": ReadySchemaV3, "ready": false,
			"blockers": []map[string]string{{"code": "promotion_not_ready", "detail": err.Error()}},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version":  ReadySchemaV3,
		"ready":           true,
		"instance_id":     s.config.InstanceID,
		"promotion":       promotionMetadata(status, "readiness", ""),
		"audit":           status.AuditHead,
		"ready_ack_count": status.ReadyAckCount,
	})
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
	statusCode, responseBody, replayed, err := s.idempotency.execute(r.URL.Path, idempotencyKey, body, func() (int, []byte, error) {
		return s.executeScreening(r.Context(), r.URL.Path, body, correlationID, idempotencyKey)
	})
	if errors.Is(err, ErrIdempotencyConflict) {
		writeError(w, http.StatusConflict, "idempotency_key_reused", err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "promotion_request_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if replayed {
		w.Header().Set("Idempotent-Replay", "true")
	}
	w.WriteHeader(statusCode)
	_, _ = w.Write(responseBody)
}

func (s *Server) executeScreening(ctx context.Context, path string, body []byte, correlationID, idempotencyKey string) (int, []byte, error) {
	route, status, err := s.promotions.Route(correlationID)
	if err != nil {
		return 0, nil, err
	}
	if err := verifyBindings(s.activations, status); err != nil {
		return 0, nil, err
	}
	if err := s.readyForPhase(ctx, status); err != nil {
		return 0, nil, err
	}
	var statusCode int
	var responseBody []byte
	shadowSHA := ""
	if status.State.Phase == activationpromotion.PhaseValidated {
		currentStatus, currentBody, err := s.current.post(ctx, path, body, correlationID, idempotencyKey)
		if err != nil {
			return 0, nil, err
		}
		_, candidateBody, err := s.candidate.post(ctx, path, body, correlationID, idempotencyKey)
		if err != nil {
			return 0, nil, err
		}
		observation, err := activationpromotion.CompareResponses(status.Intent.IntentID, correlationID, currentBody, candidateBody, time.Now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			return 0, nil, err
		}
		if err := s.promotions.RecordObservation(observation); err != nil {
			return 0, nil, err
		}
		statusCode, responseBody, shadowSHA = currentStatus, currentBody, observation.ObservationSHA256
		route = "current_shadowed"
	} else {
		selected := s.current
		if route == "candidate" {
			selected = s.candidate
		}
		statusCode, responseBody, err = selected.post(ctx, path, body, correlationID, idempotencyKey)
		if err != nil {
			return 0, nil, err
		}
	}
	latest, err := s.promotions.Status()
	if err != nil {
		return 0, nil, err
	}
	if latest.State.IntentID != status.State.IntentID || latest.State.Revision != status.State.Revision || latest.State.Phase != status.State.Phase {
		return 0, nil, errors.New("promotion state changed during request; retry required")
	}
	return statusCode, attachPromotion(responseBody, promotionMetadata(status, route, shadowSHA)), nil
}

func (s *Server) readyForPhase(ctx context.Context, status activationpromotion.Status) error {
	switch status.State.Phase {
	case activationpromotion.PhasePrepared, activationpromotion.PhaseBlocked, activationpromotion.PhaseRolledBack:
		return s.current.ready(ctx, status.Intent.CurrentActivationID)
	case activationpromotion.PhaseValidated, activationpromotion.PhaseCanary:
		if err := s.current.ready(ctx, status.Intent.CurrentActivationID); err != nil {
			return fmt.Errorf("current backend: %w", err)
		}
		if err := s.candidate.ready(ctx, status.Intent.CandidateActivationID); err != nil {
			return fmt.Errorf("candidate backend: %w", err)
		}
		return nil
	case activationpromotion.PhasePromoted:
		return s.candidate.ready(ctx, status.Intent.CandidateActivationID)
	default:
		return fmt.Errorf("unsupported promotion phase %q", status.State.Phase)
	}
}

func verifyBindings(activations *scoringactivation.Manager, status activationpromotion.Status) error {
	current, err := activations.LoadActivation(status.Intent.CurrentActivationID)
	if err != nil {
		return fmt.Errorf("load current activation: %w", err)
	}
	candidate, err := activations.LoadActivation(status.Intent.CandidateActivationID)
	if err != nil {
		return fmt.Errorf("load candidate activation: %w", err)
	}
	currentDigest, err := activations.ActivationDocumentSHA256(current.Activation.ActivationID)
	if err != nil {
		return err
	}
	candidateDigest, err := activations.ActivationDocumentSHA256(candidate.Activation.ActivationID)
	if err != nil {
		return err
	}
	if currentDigest != status.Intent.CurrentActivationSHA256 || candidateDigest != status.Intent.CandidateActivationSHA256 {
		return errors.New("promotion activation checksum binding changed")
	}
	active, err := activations.LoadActive()
	if err != nil {
		return err
	}
	expected := status.Intent.CurrentActivationID
	if status.State.Phase == activationpromotion.PhasePromoted {
		expected = status.Intent.CandidateActivationID
	}
	if active.Activation.ActivationID != expected {
		return fmt.Errorf("active activation mismatch for phase %s: expected %q, found %q", status.State.Phase, expected, active.Activation.ActivationID)
	}
	return nil
}

func promotionMetadata(status activationpromotion.Status, route, shadowSHA string) map[string]any {
	metadata := map[string]any{
		"intent_id": status.Intent.IntentID, "phase": status.State.Phase, "revision": status.State.Revision,
		"route": route, "current_activation_id": status.Intent.CurrentActivationID,
		"candidate_activation_id": status.Intent.CandidateActivationID,
		"canary_basis_points":     status.Intent.CanaryBasisPoints,
	}
	if shadowSHA != "" {
		metadata["shadow_observation_sha256"] = shadowSHA
	}
	return metadata
}

func attachPromotion(raw []byte, metadata map[string]any) []byte {
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		return raw
	}
	document["promotion"] = metadata
	encoded, err := json.Marshal(document)
	if err != nil {
		return raw
	}
	return encoded
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
