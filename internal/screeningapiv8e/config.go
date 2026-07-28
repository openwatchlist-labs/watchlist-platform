package screeningapiv8e

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

// Config replaces separate policy/projection settings with one active tuple.
type Config struct {
	ListenAddress            string `json:"listen_address"`
	UpstreamBaseURL          string `json:"upstream_base_url"`
	ActivationStateDirectory string `json:"activation_state_directory"`
	IdempotencyDirectory     string `json:"idempotency_directory"`
	MaxBodyBytes             int64  `json:"max_body_bytes"`
	MaxBatchItems            int    `json:"max_batch_items"`
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
	if strings.TrimSpace(c.ListenAddress) == "" || strings.TrimSpace(c.UpstreamBaseURL) == "" {
		return errors.New("listen_address and upstream_base_url are required")
	}
	if strings.TrimSpace(c.ActivationStateDirectory) == "" || strings.TrimSpace(c.IdempotencyDirectory) == "" {
		return errors.New("activation_state_directory and idempotency_directory are required")
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
	return nil
}

func (c Config) RequestTimeout() time.Duration {
	return time.Duration(c.RequestTimeoutMillis) * time.Millisecond
}
