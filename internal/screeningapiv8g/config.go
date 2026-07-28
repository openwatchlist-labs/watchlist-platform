package screeningapiv8g

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningledger"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	ListenAddress        string                          `json:"listen_address"`
	UpstreamBaseURL      string                          `json:"upstream_base_url"`
	LedgerDirectory      string                          `json:"ledger_directory"`
	IdempotencyDirectory string                          `json:"idempotency_directory"`
	InstanceID           string                          `json:"instance_id"`
	SnapshotKeyFile      string                          `json:"snapshot_key_file"`
	SnapshotKeyEnv       string                          `json:"snapshot_key_env"`
	MaxBodyBytes         int64                           `json:"max_body_bytes"`
	RequestTimeoutMillis int                             `json:"request_timeout_millis"`
	Retention            screeningledger.RetentionPolicy `json:"retention"`
	PostgresDSN          string                          `json:"postgres_dsn"`
	PostgresDSNEnv       string                          `json:"postgres_dsn_env"`
	PSQLPath             string                          `json:"psql_path"`
	RequirePostgres      bool                            `json:"require_postgres"`
	AutoMigrate          bool                            `json:"auto_migrate"`
}

func LoadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var c Config
	if err := d.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		if err == nil {
			return Config{}, errors.New("decode config: trailing JSON value")
		}
		return Config{}, err
	}
	base := filepath.Dir(path)
	c.LedgerDirectory = resolvePath(base, c.LedgerDirectory)
	c.IdempotencyDirectory = resolvePath(base, c.IdempotencyDirectory)
	c.SnapshotKeyFile = resolvePath(base, c.SnapshotKeyFile)
	c.PSQLPath = resolveExecutable(base, c.PSQLPath)
	if c.PostgresDSN == "" && c.PostgresDSNEnv != "" {
		c.PostgresDSN = os.Getenv(c.PostgresDSNEnv)
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}
func resolvePath(base, value string) string {
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Clean(filepath.Join(base, value))
}
func resolveExecutable(base, value string) string {
	if value == "" || value == "psql" || filepath.IsAbs(value) {
		return value
	}
	if strings.Contains(value, "/") {
		return filepath.Clean(filepath.Join(base, value))
	}
	return value
}
func (c Config) Validate() error {
	if strings.TrimSpace(c.ListenAddress) == "" || strings.TrimSpace(c.UpstreamBaseURL) == "" {
		return errors.New("listen_address and upstream_base_url are required")
	}
	if c.LedgerDirectory == "" || c.IdempotencyDirectory == "" || c.InstanceID == "" {
		return errors.New("ledger_directory, idempotency_directory and instance_id are required")
	}
	if c.SnapshotKeyFile == "" && c.SnapshotKeyEnv == "" {
		return errors.New("snapshot_key_file or snapshot_key_env is required")
	}
	if c.MaxBodyBytes < 1024 || c.MaxBodyBytes > 64*1024*1024 {
		return errors.New("max_body_bytes must be between 1024 and 67108864")
	}
	if c.RequestTimeoutMillis < 100 || c.RequestTimeoutMillis > 120000 {
		return errors.New("request_timeout_millis must be between 100 and 120000")
	}
	if c.RequirePostgres && strings.TrimSpace(c.PostgresDSN) == "" {
		return errors.New("PostgreSQL is required but no DSN was configured")
	}
	if c.Retention.RetentionDays <= 0 || c.Retention.MaxSnapshotBytes < 1024 {
		return errors.New("retention_days and max_snapshot_bytes must be positive")
	}
	return nil
}
func (c Config) RequestTimeout() time.Duration {
	return time.Duration(c.RequestTimeoutMillis) * time.Millisecond
}
