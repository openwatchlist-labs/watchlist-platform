package screeningapiv8d

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/candidatescoring"
)

type Server struct {
	config      Config
	engine      *candidatescoring.Engine
	policy      candidatescoring.PolicyReference
	projections *ProjectionRegistry
	upstream    Upstream
	idempotency *IdempotencyStore
}

func NewServer(config Config, upstream Upstream) (*Server, error) {
	loaded, err := candidatescoring.LoadPolicy(config.ScoringPolicyPath)
	if err != nil {
		return nil, fmt.Errorf("load scoring policy: %w", err)
	}
	engine, err := candidatescoring.NewEngine(loaded)
	if err != nil {
		return nil, fmt.Errorf("initialize scoring engine: %w", err)
	}
	policy := engine.PolicyReference()
	if config.DefaultLineage.NormalizationProfile != policy.NormalizationProfile {
		return nil, fmt.Errorf("default lineage normalization_profile %q does not match scoring policy %q", config.DefaultLineage.NormalizationProfile, policy.NormalizationProfile)
	}
	projections, err := LoadProjectionRegistry(config.ProjectionRegistryPath)
	if err != nil {
		return nil, err
	}
	return &Server{
		config:      config,
		engine:      engine,
		policy:      policy,
		projections: projections,
		upstream:    upstream,
		idempotency: NewIdempotencyStore(config.IdempotencyDirectory),
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleReady)
	mux.HandleFunc("/v1/screenings", s.handleSingle)
	mux.HandleFunc("/v1/screenings/batch", s.handleBatch)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "schema_version": "openwatchlist.health.v1"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.config.RequestTimeout())
	defer cancel()
	response := ReadyResponse{
		SchemaVersion: ReadySchemaV1,
		Ready:         true,
		Policy:        s.policy,
		Upstream:      s.config.UpstreamBaseURL,
		ProjectionSet: s.projections.SHA256(),
		Blockers:      []Blocker{},
	}
	if err := s.upstream.Ready(ctx); err != nil {
		response.Ready = false
		response.Blockers = append(response.Blockers, Blocker{Code: "phase8b_upstream_not_ready", Detail: err.Error()})
		writeJSON(w, http.StatusServiceUnavailable, response)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleSingle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	raw, err := readBoundedBody(w, r, s.config.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request_body", err.Error())
		return
	}
	correlationID := correlationID(r, raw)
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	status, body, replay, err := s.idempotency.Execute("POST /v1/screenings", key, raw, func() (int, []byte, error) {
		return s.processSingle(r.Context(), raw, correlationID, key)
	})
	if errors.Is(err, ErrIdempotencyConflict) {
		writeError(w, http.StatusConflict, "idempotency_key_reused_with_different_bytes", err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "screening_execution_failed", err.Error())
		return
	}
	writeRawJSON(w, status, body, replay)
}

func (s *Server) handleBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	raw, err := readBoundedBody(w, r, s.config.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request_body", err.Error())
		return
	}
	correlationID := correlationID(r, raw)
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	status, body, replay, err := s.idempotency.Execute("POST /v1/screenings/batch", key, raw, func() (int, []byte, error) {
		return s.processBatch(r.Context(), raw, correlationID, key)
	})
	if errors.Is(err, ErrIdempotencyConflict) {
		writeError(w, http.StatusConflict, "idempotency_key_reused_with_different_bytes", err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "batch_execution_failed", err.Error())
		return
	}
	writeRawJSON(w, status, body, replay)
}

func (s *Server) processSingle(parent context.Context, raw []byte, correlationID, key string) (int, []byte, error) {
	request, err := extractSingleRequest(raw)
	if err != nil {
		return marshalResponse(http.StatusBadRequest, errorResponse(correlationID, digestHex(raw), "invalid_screening_request", err.Error()))
	}
	if request.RequestID == "" {
		request.RequestID = "screening-" + digestHex(raw)[:24]
	}
	ctx, cancel := context.WithTimeout(parent, s.config.RequestTimeout())
	defer cancel()
	upstreamStatus, upstreamRaw, err := s.upstream.Post(ctx, "/v1/screenings", raw, correlationID, key)
	if err != nil {
		return marshalResponse(http.StatusBadGateway, errorResponse(correlationID, digestHex(raw), "phase8b_upstream_unavailable", err.Error()))
	}
	upstream, err := extractUpstreamSingle(upstreamRaw, s.config.DefaultLineage)
	if err != nil {
		return marshalResponse(http.StatusBadGateway, errorResponse(correlationID, digestHex(raw), "phase8b_response_invalid", err.Error()))
	}
	response, responseStatus := s.buildResponse(request, upstream, correlationID, digestHex(raw), upstreamStatus)
	return marshalResponse(responseStatus, response)
}

func (s *Server) processBatch(parent context.Context, raw []byte, correlationID, key string) (int, []byte, error) {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return marshalResponse(http.StatusBadRequest, errorResponse(correlationID, digestHex(raw), "invalid_batch_request", err.Error()))
	}
	itemValues := arrayValue(root, "items", "screenings", "requests")
	if len(itemValues) == 0 {
		return marshalResponse(http.StatusBadRequest, errorResponse(correlationID, digestHex(raw), "empty_batch", "batch items must not be empty"))
	}
	if len(itemValues) > s.config.MaxBatchItems {
		return marshalResponse(http.StatusRequestEntityTooLarge, errorResponse(correlationID, digestHex(raw), "batch_too_large", fmt.Sprintf("batch exceeds configured maximum of %d", s.config.MaxBatchItems)))
	}
	requests := make([]extractedRequest, 0, len(itemValues))
	itemDigests := make([]string, 0, len(itemValues))
	for index, itemValue := range itemValues {
		object, ok := itemValue.(map[string]any)
		if !ok {
			return marshalResponse(http.StatusBadRequest, errorResponse(correlationID, digestHex(raw), "invalid_batch_item", fmt.Sprintf("batch item %d is not an object", index)))
		}
		itemRaw, err := json.Marshal(object)
		if err != nil {
			return 0, nil, err
		}
		request := extractRequestMap(object)
		if request.RequestID == "" {
			request.RequestID = fmt.Sprintf("screening-%s-%d", digestHex(raw)[:16], index)
		}
		requests = append(requests, request)
		itemDigests = append(itemDigests, digestHex(itemRaw))
	}
	ctx, cancel := context.WithTimeout(parent, s.config.RequestTimeout())
	defer cancel()
	upstreamStatus, upstreamRaw, err := s.upstream.Post(ctx, "/v1/screenings/batch", raw, correlationID, key)
	if err != nil {
		return marshalResponse(http.StatusBadGateway, errorResponse(correlationID, digestHex(raw), "phase8b_upstream_unavailable", err.Error()))
	}
	upstreamItems, err := extractUpstreamBatch(upstreamRaw, s.config.DefaultLineage)
	if err != nil {
		return marshalResponse(http.StatusBadGateway, errorResponse(correlationID, digestHex(raw), "phase8b_response_invalid", err.Error()))
	}
	if len(upstreamItems) != len(requests) {
		return marshalResponse(http.StatusBadGateway, errorResponse(correlationID, digestHex(raw), "phase8b_batch_cardinality_mismatch", fmt.Sprintf("request items=%d response items=%d", len(requests), len(upstreamItems))))
	}
	batchID := firstNonEmpty(stringValue(root, "batch_id", "request_id", "id"), "batch-"+digestHex(raw)[:24])
	response := BatchResponse{
		SchemaVersion: BatchResponseSchemaV2,
		BatchID:       batchID,
		CorrelationID: correlationID,
		RequestSHA256: digestHex(raw),
		Policy:        s.policy,
		Items:         make([]BatchItem, 0, len(requests)),
	}
	status := upstreamStatus
	for index := range requests {
		itemResponse, itemStatus := s.buildResponse(requests[index], upstreamItems[index], correlationID, itemDigests[index], upstreamStatus)
		if itemStatus >= 500 {
			status = itemStatus
		} else if itemStatus >= 400 && status < 400 {
			status = itemStatus
		}
		response.Items = append(response.Items, BatchItem{Index: index, Response: itemResponse})
	}
	if status < 200 || status >= 600 {
		status = http.StatusOK
	}
	return marshalResponse(status, response)
}

func (s *Server) buildResponse(request extractedRequest, upstream extractedUpstream, correlationID, requestDigest string, upstreamStatus int) (Response, int) {
	lineage := upstream.Lineage
	response := Response{
		SchemaVersion: ResponseSchemaV2,
		RequestID:     request.RequestID,
		CorrelationID: correlationID,
		RequestSHA256: requestDigest,
		Status:        upstream.Status,
		Blockers:      append([]Blocker{}, upstream.Blockers...),
		Field: candidatescoring.ScreenedField{
			Path:            request.FieldPath,
			OriginalValue:   request.OriginalValue,
			NormalizedValue: request.NormalizedValue,
		},
		Policy:     s.policy,
		Lineage:    lineage,
		Candidates: []Candidate{},
	}
	if err := validateLineage(lineage); err != nil {
		response.Status = "blocked"
		response.Blockers = append(response.Blockers, Blocker{Code: "incomplete_active_catalog_lineage", Detail: err.Error()})
		return response, http.StatusServiceUnavailable
	}
	if lineage.NormalizationProfile != s.policy.NormalizationProfile {
		response.Status = "blocked"
		response.Blockers = append(response.Blockers, Blocker{Code: "normalization_profile_mismatch", Detail: fmt.Sprintf("lineage=%s policy=%s", lineage.NormalizationProfile, s.policy.NormalizationProfile)})
		return response, http.StatusServiceUnavailable
	}
	if len(upstream.Candidates) == 0 {
		return response, normalizeStatus(upstreamStatus)
	}
	envelopes := make([]candidatescoring.CandidateEnvelope, 0, len(upstream.Candidates))
	for _, retrieved := range upstream.Candidates {
		if strings.TrimSpace(retrieved.CandidateID) == "" {
			response.Blockers = append(response.Blockers, Blocker{Code: "retrieved_candidate_missing_id"})
			continue
		}
		projection, ok := s.projections.Get(retrieved.CandidateID)
		if !ok {
			response.Blockers = append(response.Blockers, Blocker{Code: "candidate_projection_unavailable", Detail: retrieved.CandidateID})
			continue
		}
		envelopes = append(envelopes, candidatescoring.CandidateEnvelope{Candidate: projection, Retrieval: retrieved.Retrieval})
	}
	if len(envelopes) == 0 {
		response.Status = "blocked"
		return response, http.StatusServiceUnavailable
	}
	scored, err := s.engine.Score(candidatescoring.Request{
		SchemaVersion:   candidatescoring.RequestSchemaV1,
		RequestID:       request.RequestID,
		FieldPath:       request.FieldPath,
		OriginalValue:   request.OriginalValue,
		NormalizedValue: request.NormalizedValue,
		Subject:         request.Subject,
		Lineage: candidatescoring.Lineage{
			Provider:             lineage.Provider,
			CatalogID:            lineage.CatalogID,
			ComponentID:          lineage.ComponentID,
			ComponentVersion:     lineage.ComponentVersion,
			ActivationID:         lineage.ActivationID,
			NormalizationProfile: lineage.NormalizationProfile,
		},
		Candidates: envelopes,
	})
	if err != nil {
		response.Status = "blocked"
		response.Blockers = append(response.Blockers, Blocker{Code: "candidate_scoring_failed", Detail: err.Error()})
		return response, http.StatusInternalServerError
	}
	for _, result := range scored.Candidates {
		response.Candidates = append(response.Candidates, Candidate{
			CandidateID:            result.CandidateID,
			Score:                  result.Score,
			SimilarityBand:         similarityBand(result.StrengthBand),
			ExactIdentifierMatched: result.ExactIdentifierMatched,
			ExactNameMatched:       result.ExactNameMatched,
			ReasonCodes:            result.ReasonCodes,
			Components:             result.Components,
			Evidence:               result.Evidence,
			Retrieval:              result.Retrieval,
			Lineage:                lineage,
		})
	}
	if len(response.Blockers) > 0 {
		response.Status = "blocked"
		return response, http.StatusServiceUnavailable
	}
	return response, normalizeStatus(upstreamStatus)
}

func similarityBand(strength string) string {
	switch strength {
	case "strong_candidate":
		return "high_similarity"
	case "review_candidate":
		return "possible_similarity"
	default:
		return "low_similarity"
	}
}

func normalizeStatus(status int) int {
	if status >= 200 && status < 600 {
		return status
	}
	return http.StatusOK
}

func errorResponse(correlationID, requestDigest, code, detail string) Response {
	return Response{
		SchemaVersion: ResponseSchemaV2,
		RequestID:     "screening-" + requestDigest[:24],
		CorrelationID: correlationID,
		RequestSHA256: requestDigest,
		Status:        "blocked",
		Blockers:      []Blocker{{Code: code, Detail: detail}},
		Candidates:    []Candidate{},
	}
}

func correlationID(r *http.Request, body []byte) string {
	if value := strings.TrimSpace(r.Header.Get("X-Correlation-ID")); value != "" {
		return value
	}
	return "corr-" + digestHex(body)[:24]
}

func readBoundedBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("request body is empty")
	}
	return raw, nil
}

func marshalResponse(status int, value any) (int, []byte, error) {
	raw, err := json.Marshal(value)
	return status, raw, err
}

func writeRawJSON(w http.ResponseWriter, status int, raw []byte, replay bool) {
	w.Header().Set("Content-Type", "application/json")
	if replay {
		w.Header().Set("Idempotent-Replay", "true")
	}
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	raw, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "encode response", http.StatusInternalServerError)
		return
	}
	writeRawJSON(w, status, raw, false)
}

func writeError(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, map[string]any{
		"schema_version": "openwatchlist.error.v1",
		"error":          Blocker{Code: code, Detail: detail},
	})
}

func writeMethodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "unsupported HTTP method")
}

// ShutdownTimeout is used by the command for bounded graceful shutdown.
const ShutdownTimeout = 10 * time.Second
