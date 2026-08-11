package screeningapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/tenantctx"
)

type Handler struct {
	Config  Config
	Service *Service
	Store   IdempotencyStore
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	switch request.URL.Path {
	case "/healthz":
		if request.Method != http.MethodGet {
			handler.methodNotAllowed(writer, request)
			return
		}
		handler.writeJSON(writer, http.StatusOK, map[string]any{"status": "ok", "api_version": APIVersion})
	case "/readyz":
		if request.Method != http.MethodGet {
			handler.methodNotAllowed(writer, request)
			return
		}
		if err := handler.Service.Ready(); err != nil {
			handler.writeProblem(writer, Problem{SchemaVersion: ProblemSchemaVersion, Type: "about:blank", Title: "Service unavailable", Status: http.StatusServiceUnavailable, Code: "SCREENING_API_NOT_READY", Detail: err.Error()})
			return
		}
		handler.writeJSON(writer, http.StatusOK, map[string]any{"status": "ready", "api_version": APIVersion})
	case "/v1/screenings":
		if request.Method != http.MethodPost {
			handler.methodNotAllowed(writer, request)
			return
		}
		handler.handleScreening(writer, request, false)
	case "/v1/screenings/batch":
		if request.Method != http.MethodPost {
			handler.methodNotAllowed(writer, request)
			return
		}
		handler.handleScreening(writer, request, true)
	default:
		handler.writeProblem(writer, Problem{SchemaVersion: ProblemSchemaVersion, Type: "about:blank", Title: "Not found", Status: http.StatusNotFound, Code: "NOT_FOUND", Detail: "the requested endpoint does not exist"})
	}
}

func (handler *Handler) handleScreening(writer http.ResponseWriter, request *http.Request, batch bool) {
	correlationID := request.Header.Get("X-Correlation-ID")
	idempotencyKey := request.Header.Get("Idempotency-Key")
	if correlationID != "" {
		if err := validateToken("X-Correlation-ID", correlationID, 128); err != nil {
			handler.writeProblem(writer, Problem{SchemaVersion: ProblemSchemaVersion, Type: "about:blank", Title: "Invalid request", Status: http.StatusBadRequest, Code: "INVALID_CORRELATION_ID", Detail: err.Error()})
			return
		}
	}
	if err := validateToken("Idempotency-Key", idempotencyKey, 128); err != nil {
		handler.writeProblem(writer, Problem{SchemaVersion: ProblemSchemaVersion, Type: "about:blank", Title: "Invalid request", Status: http.StatusBadRequest, Code: "IDEMPOTENCY_KEY_REQUIRED", Detail: err.Error(), CorrelationID: correlationID})
		return
	}
	contentType := request.Header.Get("Content-Type")
	if contentType != "" && !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		handler.writeProblem(writer, Problem{SchemaVersion: ProblemSchemaVersion, Type: "about:blank", Title: "Unsupported media type", Status: http.StatusUnsupportedMediaType, Code: "CONTENT_TYPE_NOT_JSON", Detail: "Content-Type must be application/json", CorrelationID: correlationID})
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, handler.Config.MaxBodyBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		code, status := "INVALID_REQUEST_BODY", http.StatusBadRequest
		var maxError *http.MaxBytesError
		if errors.As(err, &maxError) {
			code, status = "REQUEST_BODY_TOO_LARGE", http.StatusRequestEntityTooLarge
		}
		handler.writeProblem(writer, Problem{SchemaVersion: ProblemSchemaVersion, Type: "about:blank", Title: "Invalid request", Status: status, Code: code, Detail: err.Error(), CorrelationID: correlationID})
		return
	}
	if correlationID == "" {
		correlationID = "corr_" + hashBytes(body)[:24]
	}
	tenant, ok := tenantctx.FromContext(request.Context())
	if !ok {
		handler.writeProblem(writer, Problem{SchemaVersion: ProblemSchemaVersion, Type: "about:blank", Title: "Unauthorized", Status: http.StatusUnauthorized, Code: "TENANT_UNBOUND", Detail: "no tenant bound on this request", CorrelationID: correlationID})
		return
	}
	endpoint := request.URL.Path
	requestSHA := hashBytes(append([]byte(endpoint+"\x1f"), body...))
	replay, lease, err := handler.Store.Begin(endpoint, tenant.String(), idempotencyKey, requestSHA)
	if err != nil {
		status, code := http.StatusInternalServerError, "IDEMPOTENCY_STORE_ERROR"
		if errors.Is(err, ErrIdempotencyConflict) {
			status, code = http.StatusConflict, "IDEMPOTENCY_KEY_REUSE"
		} else if errors.Is(err, ErrIdempotencyBusy) {
			status, code = http.StatusConflict, "IDEMPOTENCY_KEY_IN_PROGRESS"
		}
		handler.writeProblem(writer, Problem{SchemaVersion: ProblemSchemaVersion, Type: "about:blank", Title: "Idempotency error", Status: status, Code: code, Detail: err.Error(), CorrelationID: correlationID})
		return
	}
	if replay != nil {
		writer.Header().Set("X-Correlation-ID", replay.CorrelationID)
		writer.Header().Set("X-Idempotent-Replay", "true")
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(replay.StatusCode)
		_, _ = writer.Write(replay.Response)
		return
	}
	defer lease.Release()

	ctx, cancel := context.WithTimeout(request.Context(), time.Duration(handler.Config.RequestTimeoutMS)*time.Millisecond)
	defer cancel()
	var response any
	if batch {
		var input BatchRequest
		if err := decodeStrict(body, &input); err != nil {
			handler.writeRequestError(writer, correlationID, err)
			return
		}
		if len(input.Requests) > handler.Config.MaxBatchItems {
			handler.writeProblem(writer, Problem{SchemaVersion: ProblemSchemaVersion, Type: "about:blank", Title: "Invalid request", Status: http.StatusBadRequest, Code: "BATCH_LIMIT_EXCEEDED", Detail: fmt.Sprintf("batch contains %d items, maximum is %d", len(input.Requests), handler.Config.MaxBatchItems), CorrelationID: correlationID})
			return
		}
		value, err := handler.Service.ScreenBatch(ctx, input, correlationID, idempotencyKey)
		if err != nil {
			handler.writeServiceError(writer, correlationID, err)
			return
		}
		response = value
	} else {
		var input ScreeningRequest
		if err := decodeStrict(body, &input); err != nil {
			handler.writeRequestError(writer, correlationID, err)
			return
		}
		value, err := handler.Service.Screen(ctx, input, correlationID, idempotencyKey)
		if err != nil {
			handler.writeServiceError(writer, correlationID, err)
			return
		}
		response = value
	}
	encoded, err := jsonBytes(response)
	if err != nil {
		handler.writeServiceError(writer, correlationID, err)
		return
	}
	record := newIdempotencyRecord(endpoint, tenant.String(), idempotencyKey, requestSHA, correlationID, http.StatusOK, encoded, handler.Service.now())
	if err := lease.Commit(record); err != nil {
		handler.writeServiceError(writer, correlationID, err)
		return
	}
	writer.Header().Set("X-Correlation-ID", correlationID)
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(encoded)
}

func (handler *Handler) writeRequestError(writer http.ResponseWriter, correlationID string, err error) {
	handler.writeProblem(writer, Problem{SchemaVersion: ProblemSchemaVersion, Type: "about:blank", Title: "Invalid request", Status: http.StatusBadRequest, Code: "INVALID_REQUEST", Detail: err.Error(), CorrelationID: correlationID})
}

func (handler *Handler) writeServiceError(writer http.ResponseWriter, correlationID string, err error) {
	status, code, title := http.StatusInternalServerError, "SCREENING_FAILED", "Screening failed"
	if errors.Is(err, ErrRuntimeUnavailable) || errors.Is(err, context.DeadlineExceeded) {
		status, code, title = http.StatusServiceUnavailable, "RUNTIME_UNAVAILABLE", "Runtime unavailable"
	}
	handler.writeProblem(writer, Problem{SchemaVersion: ProblemSchemaVersion, Type: "about:blank", Title: title, Status: status, Code: code, Detail: err.Error(), CorrelationID: correlationID})
}

func (handler *Handler) methodNotAllowed(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Allow", allowedMethod(request.URL.Path))
	handler.writeProblem(writer, Problem{SchemaVersion: ProblemSchemaVersion, Type: "about:blank", Title: "Method not allowed", Status: http.StatusMethodNotAllowed, Code: "METHOD_NOT_ALLOWED", Detail: "the HTTP method is not supported for this endpoint"})
}

func allowedMethod(path string) string {
	if path == "/healthz" || path == "/readyz" {
		return http.MethodGet
	}
	return http.MethodPost
}

func (handler *Handler) writeJSON(writer http.ResponseWriter, status int, value any) {
	encoded, err := jsonBytes(value)
	if err != nil {
		http.Error(writer, "JSON encoding failed", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}

func (handler *Handler) writeProblem(writer http.ResponseWriter, problem Problem) {
	handler.writeJSON(writer, problem.Status, problem)
}

func hashBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
