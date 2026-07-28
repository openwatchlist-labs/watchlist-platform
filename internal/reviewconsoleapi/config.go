package reviewconsoleapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertcase"
	"github.com/openwatchlist-labs/watchlist-platform/internal/assistancerag"
	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewauth"
)

type Config struct {
	ListenAddress            string                     `json:"listen_address"`
	AlertCaseStateDirectory  string                     `json:"alert_case_state_directory"`
	AssistanceStateDirectory string                     `json:"assistance_state_directory"`
	AlertPolicyPath          string                     `json:"alert_policy_path"`
	CorpusSnapshotPath       string                     `json:"corpus_snapshot_path"`
	ModelMode                string                     `json:"model_mode"`
	ModelFixturePath         string                     `json:"model_fixture_path,omitempty"`
	OllamaBaseURL            string                     `json:"ollama_base_url,omitempty"`
	OllamaRequired           bool                       `json:"ollama_required"`
	Models                   assistancerag.ModelProfile `json:"models"`
	AuthRegistryPath         string                     `json:"auth_registry_path"`
	SigningKeyPath           string                     `json:"signing_key_path"`
	SecurityAuditDirectory   string                     `json:"security_audit_directory"`
	SecurityAuditStreamID    string                     `json:"security_audit_stream_id"`
	MaxTokenTTLMinutes       int                        `json:"max_token_ttl_minutes"`
	MaxBodyBytes             int64                      `json:"max_body_bytes"`
	TimeoutSeconds           int                        `json:"timeout_seconds"`
	ConsoleEnabled           bool                       `json:"console_enabled"`
}
type Loaded struct {
	Config     Config
	Policy     alertcase.Policy
	Snapshot   assistancerag.CorpusSnapshot
	Registry   reviewauth.Registry
	SigningKey []byte
}

func LoadConfig(path string) (Loaded, error) {
	var out Loaded
	raw, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&out.Config); err != nil {
		return out, err
	}
	base := filepath.Dir(path)
	resolve := func(v string) string {
		if v == "" || filepath.IsAbs(v) {
			return v
		}
		return filepath.Clean(filepath.Join(base, v))
	}
	c := &out.Config
	c.AlertCaseStateDirectory = resolve(c.AlertCaseStateDirectory)
	c.AssistanceStateDirectory = resolve(c.AssistanceStateDirectory)
	c.AlertPolicyPath = resolve(c.AlertPolicyPath)
	c.CorpusSnapshotPath = resolve(c.CorpusSnapshotPath)
	c.ModelFixturePath = resolve(c.ModelFixturePath)
	c.AuthRegistryPath = resolve(c.AuthRegistryPath)
	c.SigningKeyPath = resolve(c.SigningKeyPath)
	c.SecurityAuditDirectory = resolve(c.SecurityAuditDirectory)
	if c.ListenAddress == "" {
		c.ListenAddress = "127.0.0.1:18093"
	}
	if c.ModelMode == "" {
		c.ModelMode = "ollama"
	}
	if c.OllamaBaseURL == "" {
		c.OllamaBaseURL = "http://ollama:11434"
	}
	if c.SecurityAuditStreamID == "" {
		c.SecurityAuditStreamID = "review-console-security-phase9f"
	}
	if c.MaxTokenTTLMinutes <= 0 {
		c.MaxTokenTTLMinutes = 480
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 1 << 20
	}
	if c.TimeoutSeconds <= 0 {
		c.TimeoutSeconds = 180
	}
	if c.AlertCaseStateDirectory == "" || c.AssistanceStateDirectory == "" || c.AlertPolicyPath == "" || c.CorpusSnapshotPath == "" || c.AuthRegistryPath == "" || c.SigningKeyPath == "" || c.SecurityAuditDirectory == "" {
		return out, errors.New("alert/assistance state, policy, corpus, auth registry, signing key, and security audit paths are required")
	}
	if c.ModelMode != "fixture" && c.ModelMode != "ollama" {
		return out, fmt.Errorf("unsupported model_mode %q", c.ModelMode)
	}
	if c.ModelMode == "fixture" && c.ModelFixturePath == "" {
		return out, errors.New("model_fixture_path is required in fixture mode")
	}
	out.Policy, err = alertcase.LoadPolicy(c.AlertPolicyPath)
	if err != nil {
		return out, fmt.Errorf("policy: %w", err)
	}
	out.Snapshot, err = assistancerag.LoadSnapshot(c.CorpusSnapshotPath)
	if err != nil {
		return out, fmt.Errorf("corpus: %w", err)
	}
	out.Registry, err = reviewauth.LoadRegistry(c.AuthRegistryPath)
	if err != nil {
		return out, fmt.Errorf("auth registry: %w", err)
	}
	out.SigningKey, err = reviewauth.LoadSigningKey(c.SigningKeyPath)
	if err != nil {
		return out, fmt.Errorf("signing key: %w", err)
	}
	return out, nil
}
func (c Config) Timeout() time.Duration { return time.Duration(c.TimeoutSeconds) * time.Second }
func (c Config) MaxTTL() time.Duration  { return time.Duration(c.MaxTokenTTLMinutes) * time.Minute }
