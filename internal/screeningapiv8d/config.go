package screeningapiv8d

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config keeps Phase 8B retrieval and Phase 8C policy bindings explicit.
type Config struct {
	ListenAddress          string  `json:"listen_address"`
	UpstreamBaseURL        string  `json:"upstream_base_url"`
	ScoringPolicyPath      string  `json:"scoring_policy_path"`
	ProjectionRegistryPath string  `json:"projection_registry_path"`
	IdempotencyDirectory   string  `json:"idempotency_directory"`
	MaxBodyBytes           int64   `json:"max_body_bytes"`
	MaxBatchItems          int     `json:"max_batch_items"`
	RequestTimeoutMillis   int     `json:"request_timeout_millis"`
	DefaultLineage         Lineage `json:"default_lineage"`
}

func LoadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return Config{}, errors.New("decode config: trailing JSON value")
		}
		return Config{}, fmt.Errorf("decode config trailing content: %w", err)
	}
	base := filepath.Dir(path)
	cfg.ScoringPolicyPath = resolvePath(base, cfg.ScoringPolicyPath)
	cfg.ProjectionRegistryPath = resolvePath(base, cfg.ProjectionRegistryPath)
	cfg.IdempotencyDirectory = resolvePath(base, cfg.IdempotencyDirectory)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func resolvePath(base, value string) string {
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Clean(filepath.Join(base, value))
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.ListenAddress) == "" {
		return errors.New("listen_address is required")
	}
	if strings.TrimSpace(c.UpstreamBaseURL) == "" {
		return errors.New("upstream_base_url is required")
	}
	if strings.TrimSpace(c.ScoringPolicyPath) == "" || strings.TrimSpace(c.ProjectionRegistryPath) == "" {
		return errors.New("scoring_policy_path and projection_registry_path are required")
	}
	if strings.TrimSpace(c.IdempotencyDirectory) == "" {
		return errors.New("idempotency_directory is required")
	}
	if c.MaxBodyBytes < 1024 || c.MaxBodyBytes > 64*1024*1024 {
		return errors.New("max_body_bytes must be between 1024 and 67108864")
	}
	if c.MaxBatchItems < 1 || c.MaxBatchItems > 1000 {
		return errors.New("max_batch_items must be between 1 and 1000")
	}
	if c.RequestTimeoutMillis < 100 || c.RequestTimeoutMillis > 120000 {
		return errors.New("request_timeout_millis must be between 100 and 120000")
	}
	return validateLineage(c.DefaultLineage)
}

func (c Config) RequestTimeout() time.Duration {
	return time.Duration(c.RequestTimeoutMillis) * time.Millisecond
}

func validateLineage(lineage Lineage) error {
	values := []string{lineage.Provider, lineage.CatalogID, lineage.ComponentID, lineage.ComponentVersion, lineage.ActivationID, lineage.NormalizationProfile}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return errors.New("complete default_lineage is required")
		}
	}
	return nil
}
