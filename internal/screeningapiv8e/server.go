package screeningapiv8e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/scoringactivation"
	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningapiv8d"
)

const ReadySchemaV2 = "openwatchlist.screening-ready.v2"

type ActivationTuple struct {
	ActivationID            string `json:"activation_id"`
	PreviousActivationID    string `json:"previous_activation_id,omitempty"`
	Provider                string `json:"provider"`
	CatalogID               string `json:"catalog_id"`
	ComponentID             string `json:"component_id"`
	ComponentVersion        string `json:"component_version"`
	CatalogPackageSHA256    string `json:"catalog_package_sha256"`
	ProjectionPackageSHA256 string `json:"projection_package_sha256"`
	ProjectionsSHA256       string `json:"projections_sha256"`
	ScoringPolicySHA256     string `json:"scoring_policy_sha256"`
	NormalizationProfile    string `json:"normalization_profile"`
	RecordCount             int    `json:"record_count"`
	ProjectionCount         int    `json:"projection_count"`
}

type Server struct {
	config   Config
	manager  *scoringactivation.Manager
	snapshot scoringactivation.Snapshot
	tuple    ActivationTuple
	delegate http.Handler
}

func NewServer(config Config) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	manager, err := scoringactivation.NewManager(config.ActivationStateDirectory)
	if err != nil {
		return nil, err
	}
	if _, err := manager.Recover(); err != nil {
		return nil, fmt.Errorf("recover activation state: %w", err)
	}
	snapshot, err := manager.LoadActive()
	if err != nil {
		return nil, fmt.Errorf("load active scoring tuple: %w", err)
	}
	activation := snapshot.Activation
	lineage := screeningapiv8d.Lineage{
		Provider:             activation.Catalog.Provider,
		CatalogID:            activation.Catalog.CatalogID,
		ComponentID:          activation.Catalog.ComponentID,
		ComponentVersion:     activation.Catalog.ComponentVersion,
		ActivationID:         activation.ActivationID,
		NormalizationProfile: activation.Catalog.NormalizationProfile,
	}
	client := &http.Client{Timeout: config.RequestTimeout()}
	upstream := &boundUpstream{delegate: screeningapiv8d.NewHTTPUpstream(config.UpstreamBaseURL, client), expected: lineage}
	delegateConfig := screeningapiv8d.Config{
		ListenAddress:          config.ListenAddress,
		UpstreamBaseURL:        config.UpstreamBaseURL,
		ScoringPolicyPath:      activation.Policy.Path,
		ProjectionRegistryPath: snapshot.ProjectionPackage.ProjectionsPath,
		IdempotencyDirectory:   config.IdempotencyDirectory,
		MaxBodyBytes:           config.MaxBodyBytes,
		MaxBatchItems:          config.MaxBatchItems,
		RequestTimeoutMillis:   config.RequestTimeoutMillis,
		DefaultLineage:         lineage,
	}
	delegate, err := screeningapiv8d.NewServer(delegateConfig, upstream)
	if err != nil {
		return nil, err
	}
	return &Server{
		config: config, manager: manager, snapshot: snapshot,
		tuple: tupleFromSnapshot(snapshot), delegate: delegate.Handler(),
	}, nil
}

func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serveHTTP) }

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/readyz" {
		s.handleReady(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1/screenings") {
		if err := s.verifyBound(); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"schema_version":   "openwatchlist.error.v1",
				"error":            map[string]any{"code": "activation_tuple_not_ready", "detail": err.Error()},
				"activation_tuple": s.tuple,
			})
			return
		}
		s.delegateWithTuple(w, r)
		return
	}
	s.delegate.ServeHTTP(w, r)
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": map[string]any{"code": "method_not_allowed"}})
		return
	}
	if err := s.verifyBound(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"schema_version": ReadySchemaV2, "ready": false,
			"activation_tuple": s.tuple,
			"blockers":         []map[string]string{{"code": "activation_tuple_not_ready", "detail": err.Error()}},
		})
		return
	}
	recorder := httptest.NewRecorder()
	s.delegate.ServeHTTP(recorder, r)
	var document map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": map[string]any{"code": "phase8d_ready_response_invalid", "detail": err.Error()}})
		return
	}
	document["schema_version"] = ReadySchemaV2
	document["activation_tuple"] = s.tuple
	copyHeaders(w.Header(), recorder.Header())
	writeJSON(w, recorder.Code, document)
}

func (s *Server) delegateWithTuple(w http.ResponseWriter, r *http.Request) {
	recorder := httptest.NewRecorder()
	s.delegate.ServeHTTP(recorder, r)
	var document map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		copyHeaders(w.Header(), recorder.Header())
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(recorder.Body.Bytes())
		return
	}
	document["activation_tuple"] = s.tuple
	copyHeaders(w.Header(), recorder.Header())
	writeJSON(w, recorder.Code, document)
}

func (s *Server) verifyBound() error {
	current, err := s.manager.LoadActive()
	if err != nil {
		return err
	}
	currentTuple := tupleFromSnapshot(current)
	if currentTuple != s.tuple {
		return fmt.Errorf("active tuple changed from %s to %s; restart required", s.tuple.ActivationID, currentTuple.ActivationID)
	}
	return nil
}

func tupleFromSnapshot(snapshot scoringactivation.Snapshot) ActivationTuple {
	activation := snapshot.Activation
	return ActivationTuple{
		ActivationID:            activation.ActivationID,
		PreviousActivationID:    activation.PreviousActivationID,
		Provider:                activation.Catalog.Provider,
		CatalogID:               activation.Catalog.CatalogID,
		ComponentID:             activation.Catalog.ComponentID,
		ComponentVersion:        activation.Catalog.ComponentVersion,
		CatalogPackageSHA256:    activation.Catalog.CatalogPackageSHA256,
		ProjectionPackageSHA256: activation.Projection.PackageSHA256,
		ProjectionsSHA256:       activation.Projection.ProjectionsSHA256,
		ScoringPolicySHA256:     activation.Policy.PolicySHA256,
		NormalizationProfile:    activation.Catalog.NormalizationProfile,
		RecordCount:             activation.Catalog.RecordCount,
		ProjectionCount:         activation.Projection.ProjectionCount,
	}
}

func copyHeaders(destination, source http.Header) {
	for key, values := range source {
		destination[key] = append([]string(nil), values...)
	}
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

const ShutdownTimeout = screeningapiv8d.ShutdownTimeout
