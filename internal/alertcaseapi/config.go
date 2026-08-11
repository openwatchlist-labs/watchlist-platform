package alertcaseapi

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
)

type Config struct {
	ListenAddress    string `json:"listen_address"`
	StateDirectory   string `json:"state_directory"`
	PolicyPath       string `json:"policy_path"`
	StreamID         string `json:"stream_id"`
	PostgresDSN      string `json:"postgres_dsn"`
	PSQLPath         string `json:"psql_path"`
	PostgresRequired bool   `json:"postgres_required"`
	MaxBodyBytes     int64  `json:"max_body_bytes"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
	// AuthRegistryPath and SigningKeyPath configure the reviewauth
	// TokenService httpauth authenticates requests with (ADR-0003 §2).
	// Not required by LoadConfig -- "check" needs no auth to validate
	// state/policy wiring -- but required by "serve" (D4: hard cutover,
	// no auth_required flag to make them optional there).
	AuthRegistryPath   string `json:"auth_registry_path,omitempty"`
	SigningKeyPath     string `json:"signing_key_path,omitempty"`
	MaxTokenTTLMinutes int    `json:"max_token_ttl_minutes,omitempty"`
}

func LoadConfig(path string) (Config, alertcase.Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, alertcase.Policy{}, err
	}
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, alertcase.Policy{}, err
	}
	base := filepath.Dir(path)
	resolve := func(v string) string {
		if v == "" || filepath.IsAbs(v) {
			return v
		}
		return filepath.Clean(filepath.Join(base, v))
	}
	cfg.StateDirectory = resolve(cfg.StateDirectory)
	cfg.PolicyPath = resolve(cfg.PolicyPath)
	cfg.PSQLPath = resolveExecutable(base, cfg.PSQLPath)
	cfg.AuthRegistryPath = resolve(cfg.AuthRegistryPath)
	cfg.SigningKeyPath = resolve(cfg.SigningKeyPath)
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = "127.0.0.1:18091"
	}
	if cfg.StreamID == "" {
		cfg.StreamID = "alert-case-api-phase9ab"
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	if cfg.TimeoutSeconds <= 0 {
		cfg.TimeoutSeconds = 20
	}
	if cfg.StateDirectory == "" || cfg.PolicyPath == "" {
		return Config{}, alertcase.Policy{}, errors.New("state_directory and policy_path are required")
	}
	if cfg.PostgresRequired && strings.TrimSpace(cfg.PostgresDSN) == "" {
		return Config{}, alertcase.Policy{}, errors.New("postgres_dsn is required when postgres_required is true")
	}
	policy, err := alertcase.LoadPolicy(cfg.PolicyPath)
	if err != nil {
		return Config{}, alertcase.Policy{}, fmt.Errorf("policy: %w", err)
	}
	return cfg, policy, nil
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
