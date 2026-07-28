package assistanceapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertcase"
	"github.com/openwatchlist-labs/watchlist-platform/internal/assistancerag"
)

type Config struct {
	ListenAddress            string                     `json:"listen_address"`
	AssistanceStateDirectory string                     `json:"assistance_state_directory"`
	AlertCaseStateDirectory  string                     `json:"alert_case_state_directory"`
	AlertPolicyPath          string                     `json:"alert_policy_path"`
	CorpusSnapshotPath       string                     `json:"corpus_snapshot_path"`
	StreamID                 string                     `json:"stream_id"`
	ModelMode                string                     `json:"model_mode"`
	ModelFixturePath         string                     `json:"model_fixture_path,omitempty"`
	OllamaBaseURL            string                     `json:"ollama_base_url,omitempty"`
	OllamaRequired           bool                       `json:"ollama_required"`
	Models                   assistancerag.ModelProfile `json:"models"`
	PostgresDSN              string                     `json:"postgres_dsn,omitempty"`
	PSQLPath                 string                     `json:"psql_path,omitempty"`
	PostgresRequired         bool                       `json:"postgres_required"`
	MaxBodyBytes             int64                      `json:"max_body_bytes"`
	TimeoutSeconds           int                        `json:"timeout_seconds"`
}

func LoadConfig(path string) (Config, alertcase.Policy, assistancerag.CorpusSnapshot, error) {
	var cfg Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, alertcase.Policy{}, assistancerag.CorpusSnapshot{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, alertcase.Policy{}, assistancerag.CorpusSnapshot{}, err
	}
	base := filepath.Dir(path)
	resolve := func(value string) string {
		if value == "" || filepath.IsAbs(value) {
			return value
		}
		return filepath.Clean(filepath.Join(base, value))
	}
	cfg.AssistanceStateDirectory = resolve(cfg.AssistanceStateDirectory)
	cfg.AlertCaseStateDirectory = resolve(cfg.AlertCaseStateDirectory)
	cfg.AlertPolicyPath = resolve(cfg.AlertPolicyPath)
	cfg.CorpusSnapshotPath = resolve(cfg.CorpusSnapshotPath)
	cfg.ModelFixturePath = resolve(cfg.ModelFixturePath)
	cfg.PSQLPath = resolveExecutable(base, cfg.PSQLPath)
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = "127.0.0.1:18092"
	}
	if cfg.StreamID == "" {
		cfg.StreamID = "case-assistance-api-phase9c"
	}
	if cfg.ModelMode == "" {
		cfg.ModelMode = "ollama"
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	if cfg.TimeoutSeconds <= 0 {
		cfg.TimeoutSeconds = 180
	}
	if cfg.OllamaBaseURL == "" {
		cfg.OllamaBaseURL = "http://ollama:11434"
	}
	if cfg.AssistanceStateDirectory == "" || cfg.AlertCaseStateDirectory == "" || cfg.AlertPolicyPath == "" || cfg.CorpusSnapshotPath == "" {
		return cfg, alertcase.Policy{}, assistancerag.CorpusSnapshot{}, errors.New("assistance_state_directory, alert_case_state_directory, alert_policy_path, and corpus_snapshot_path are required")
	}
	if cfg.ModelMode != "fixture" && cfg.ModelMode != "ollama" {
		return cfg, alertcase.Policy{}, assistancerag.CorpusSnapshot{}, fmt.Errorf("unsupported model_mode %q", cfg.ModelMode)
	}
	if cfg.ModelMode == "fixture" && cfg.ModelFixturePath == "" {
		return cfg, alertcase.Policy{}, assistancerag.CorpusSnapshot{}, errors.New("model_fixture_path is required in fixture mode")
	}
	if cfg.PostgresRequired && strings.TrimSpace(cfg.PostgresDSN) == "" {
		return cfg, alertcase.Policy{}, assistancerag.CorpusSnapshot{}, errors.New("postgres_dsn is required when postgres_required is true")
	}
	policy, err := alertcase.LoadPolicy(cfg.AlertPolicyPath)
	if err != nil {
		return cfg, policy, assistancerag.CorpusSnapshot{}, fmt.Errorf("alert policy: %w", err)
	}
	snapshot, err := assistancerag.LoadSnapshot(cfg.CorpusSnapshotPath)
	if err != nil {
		return cfg, policy, snapshot, fmt.Errorf("corpus snapshot: %w", err)
	}
	return cfg, policy, snapshot, nil
}
func resolveExecutable(base, value string) string {
	if value == "" || value == "psql" || filepath.IsAbs(value) {
		return value
	}
	if strings.Contains(value, string(filepath.Separator)) {
		return filepath.Clean(filepath.Join(base, value))
	}
	return value
}
func (c Config) Timeout() time.Duration { return time.Duration(c.TimeoutSeconds) * time.Second }
