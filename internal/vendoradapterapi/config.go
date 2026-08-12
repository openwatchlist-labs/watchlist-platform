package vendoradapterapi

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"
)

type Config struct {
	ListenAddress     string `json:"listen_address"`
	ProfilesDirectory string `json:"profiles_directory"`
	StateDirectory    string `json:"state_directory"`
	StreamID          string `json:"stream_id"`
	PostgresDSN       string `json:"postgres_dsn,omitempty"`
	PostgresRequired  bool   `json:"postgres_required"`
	PSQLPath          string `json:"psql_path"`
	MaxBodyBytes      int64  `json:"max_body_bytes"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
	// AuthRegistryPath and SigningKeyPath configure the reviewauth
	// TokenService httpauth authenticates requests with (ADR-0006 D1).
	// Not required by LoadConfig -- "check" needs no auth to validate
	// profile/state wiring -- but required by "serve" (D5: hard cutover,
	// no auth_required flag to make them optional there).
	AuthRegistryPath   string `json:"auth_registry_path,omitempty"`
	SigningKeyPath     string `json:"signing_key_path,omitempty"`
	MaxTokenTTLMinutes int    `json:"max_token_ttl_minutes,omitempty"`
}

func LoadConfig(path string) (Config, error) {
	var c Config
	b, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	if c.ListenAddress == "" || c.ProfilesDirectory == "" || c.StateDirectory == "" {
		return c, errors.New("listen_address, profiles_directory and state_directory are required")
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 4 << 20
	}
	if c.PSQLPath == "" {
		c.PSQLPath = "psql"
	}
	if c.TimeoutSeconds <= 0 {
		c.TimeoutSeconds = 10
	}
	return c, nil
}
func (c Config) Timeout() time.Duration { return time.Duration(c.TimeoutSeconds) * time.Second }
