package productionops

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func LoadRuntimeConfig(path string) (RuntimeConfig, error) {
	var c RuntimeConfig
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&c); err != nil {
		return c, err
	}
	if c.SchemaVersion != ConfigSchemaV1 {
		return c, fmt.Errorf("unsupported schema_version %q", c.SchemaVersion)
	}
	if c.Environment != "fixture" && c.Environment != "production" {
		return c, fmt.Errorf("unsupported environment %q", c.Environment)
	}
	expected := c.ConfigSHA256
	c.ConfigSHA256 = ""
	h, err := objectHash(c)
	if err != nil {
		return c, err
	}
	c.ConfigSHA256 = expected
	if expected == "" || h != expected {
		return c, fmt.Errorf("config checksum mismatch: expected %s calculated %s", expected, h)
	}
	base := filepath.Dir(path)
	resolve := func(v string) string {
		if v == "" || filepath.IsAbs(v) {
			return v
		}
		return filepath.Clean(filepath.Join(base, v))
	}
	c.ReviewConsoleConfigPath = resolve(c.ReviewConsoleConfigPath)
	c.QuotaRegistryPath = resolve(c.QuotaRegistryPath)
	c.RuntimeStateDirectory = resolve(c.RuntimeStateDirectory)
	c.OutboxDirectory = resolve(c.OutboxDirectory)
	c.BackupDirectory = resolve(c.BackupDirectory)
	for i, p := range c.Readiness.RequiredPaths {
		c.Readiness.RequiredPaths[i] = resolve(p)
	}
	if c.ListenAddress == "" {
		c.ListenAddress = "127.0.0.1:18094"
	}
	if c.ShutdownGraceSeconds <= 0 {
		c.ShutdownGraceSeconds = 20
	}
	if c.RequestTimeoutSeconds <= 0 {
		c.RequestTimeoutSeconds = 180
	}
	if c.ReadHeaderTimeoutSeconds <= 0 {
		c.ReadHeaderTimeoutSeconds = 5
	}
	if c.ReadTimeoutSeconds <= 0 {
		c.ReadTimeoutSeconds = 190
	}
	if c.WriteTimeoutSeconds <= 0 {
		c.WriteTimeoutSeconds = 190
	}
	if c.IdleTimeoutSeconds <= 0 {
		c.IdleTimeoutSeconds = 60
	}
	if c.MaxHeaderBytes <= 0 {
		c.MaxHeaderBytes = 1 << 20
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 1 << 20
	}
	if c.GlobalConcurrency <= 0 {
		c.GlobalConcurrency = 64
	}
	if c.DefaultTenantConcurrency <= 0 {
		c.DefaultTenantConcurrency = 8
	}
	if c.DefaultRequestsPerMinute <= 0 {
		c.DefaultRequestsPerMinute = 600
	}
	if c.DefaultBurst <= 0 {
		c.DefaultBurst = 40
	}
	if c.TLS.ForwardedProtoHeader == "" {
		c.TLS.ForwardedProtoHeader = "X-Forwarded-Proto"
	}
	if c.Readiness.PostgreSQLDSNEnv == "" {
		c.Readiness.PostgreSQLDSNEnv = "OPENWATCHLIST_POSTGRES_DSN"
	}
	if c.Readiness.PSQLPath == "" {
		c.Readiness.PSQLPath = "psql"
	}
	if c.ReviewConsoleConfigPath == "" || c.QuotaRegistryPath == "" || c.RuntimeStateDirectory == "" || c.OutboxDirectory == "" || c.BackupDirectory == "" {
		return c, errors.New("review console config, quota registry, runtime state, outbox, and backup paths are required")
	}
	if c.Environment == "production" {
		if strings.TrimSpace(c.SigningKeyEnv) == "" {
			return c, errors.New("signing_key_env is required in production")
		}
		if !c.TLS.Required {
			return c, errors.New("TLS must be required in production")
		}
		if strings.HasPrefix(c.ListenAddress, "127.0.0.1:") && !c.TLS.TrustedProxy {
			return c, errors.New("production loopback listener requires trusted proxy mode")
		}
	}
	return c, nil
}

func ResolveSigningKey(c RuntimeConfig) ([]byte, error) {
	if c.Environment != "production" {
		return nil, nil
	}
	v := strings.TrimSpace(os.Getenv(c.SigningKeyEnv))
	if v == "" {
		return nil, fmt.Errorf("required signing key environment variable %s is empty", c.SigningKeyEnv)
	}
	b, err := hex.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("decode signing key: %w", err)
	}
	if len(b) < 32 {
		return nil, errors.New("production signing key must be at least 32 bytes")
	}
	return b, nil
}

func LoadQuotaRegistry(path string) (QuotaRegistry, error) {
	var q QuotaRegistry
	raw, err := os.ReadFile(path)
	if err != nil {
		return q, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&q); err != nil {
		return q, err
	}
	if q.SchemaVersion != QuotaSchemaV1 {
		return q, fmt.Errorf("unsupported quota schema %q", q.SchemaVersion)
	}
	sort.Slice(q.Tenants, func(i, j int) bool { return q.Tenants[i].TenantID < q.Tenants[j].TenantID })
	if err := validateQuota(q.Default, true); err != nil {
		return q, fmt.Errorf("default quota: %w", err)
	}
	seen := map[string]bool{}
	for _, t := range q.Tenants {
		if seen[t.TenantID] {
			return q, fmt.Errorf("duplicate tenant quota %s", t.TenantID)
		}
		seen[t.TenantID] = true
		if err := validateQuota(t, false); err != nil {
			return q, fmt.Errorf("tenant %s: %w", t.TenantID, err)
		}
	}
	expected := q.RegistrySHA256
	q.RegistrySHA256 = ""
	h, err := objectHash(q)
	if err != nil {
		return q, err
	}
	q.RegistrySHA256 = expected
	if expected == "" || h != expected {
		return q, fmt.Errorf("quota registry checksum mismatch: expected %s calculated %s", expected, h)
	}
	return q, nil
}
func validateQuota(q TenantQuota, allowEmpty bool) error {
	if !allowEmpty && strings.TrimSpace(q.TenantID) == "" {
		return errors.New("tenant_id is required")
	}
	if q.RequestsPerMinute <= 0 || q.Burst <= 0 || q.MaxConcurrent <= 0 || q.MaxBodyBytes <= 0 {
		return errors.New("all quota limits must be positive")
	}
	return nil
}
func (q QuotaRegistry) ForTenant(id string) TenantQuota {
	for _, t := range q.Tenants {
		if t.TenantID == id {
			return t
		}
	}
	d := q.Default
	d.TenantID = id
	return d
}

func SealRuntimeConfig(c RuntimeConfig) (RuntimeConfig, error) {
	c.ConfigSHA256 = ""
	h, err := objectHash(c)
	if err != nil {
		return c, err
	}
	c.ConfigSHA256 = h
	return c, nil
}

func SealQuotaRegistry(q QuotaRegistry) (QuotaRegistry, error) {
	sort.Slice(q.Tenants, func(i, j int) bool { return q.Tenants[i].TenantID < q.Tenants[j].TenantID })
	q.RegistrySHA256 = ""
	h, err := objectHash(q)
	if err != nil {
		return q, err
	}
	q.RegistrySHA256 = h
	return q, nil
}
