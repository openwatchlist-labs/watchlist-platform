package screeningapiv8f

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

type Config struct {
	ListenAddress            string `json:"listen_address"`
	CurrentBaseURL           string `json:"current_base_url"`
	CandidateBaseURL         string `json:"candidate_base_url"`
	ActivationStateDirectory string `json:"activation_state_directory"`
	PromotionStateDirectory  string `json:"promotion_state_directory"`
	IdempotencyDirectory     string `json:"idempotency_directory"`
	InstanceID               string `json:"instance_id"`
	MaxBodyBytes             int64  `json:"max_body_bytes"`
	RequestTimeoutMillis     int    `json:"request_timeout_millis"`
}

func LoadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Config{}, errors.New("decode config: trailing JSON value")
		}
		return Config{}, err
	}
	base := filepath.Dir(path)
	config.ActivationStateDirectory = resolvePath(base, config.ActivationStateDirectory)
	config.PromotionStateDirectory = resolvePath(base, config.PromotionStateDirectory)
	config.IdempotencyDirectory = resolvePath(base, config.IdempotencyDirectory)
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func resolvePath(base, value string) string {
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Clean(filepath.Join(base, value))
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.ListenAddress) == "" || strings.TrimSpace(c.CurrentBaseURL) == "" || strings.TrimSpace(c.CandidateBaseURL) == "" {
		return errors.New("listen_address, current_base_url and candidate_base_url are required")
	}
	if strings.TrimSpace(c.ActivationStateDirectory) == "" || strings.TrimSpace(c.PromotionStateDirectory) == "" || strings.TrimSpace(c.IdempotencyDirectory) == "" {
		return errors.New("activation_state_directory, promotion_state_directory and idempotency_directory are required")
	}
	if strings.TrimSpace(c.InstanceID) == "" {
		return errors.New("instance_id is required")
	}
	if c.MaxBodyBytes < 1024 || c.MaxBodyBytes > 64*1024*1024 {
		return errors.New("max_body_bytes must be between 1024 and 67108864")
	}
	if c.RequestTimeoutMillis < 100 || c.RequestTimeoutMillis > 120000 {
		return errors.New("request_timeout_millis must be between 100 and 120000")
	}
	return nil
}

func (c Config) RequestTimeout() time.Duration {
	return time.Duration(c.RequestTimeoutMillis) * time.Millisecond
}
