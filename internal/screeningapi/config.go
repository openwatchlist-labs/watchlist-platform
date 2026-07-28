package screeningapi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read screening API config: %w", err)
	}
	var config Config
	if err := decodeStrict(data, &config); err != nil {
		return Config{}, fmt.Errorf("decode screening API config: %w", err)
	}
	base := filepath.Dir(path)
	config.CatalogRegistryPath = resolvePath(base, config.CatalogRegistryPath)
	config.MappingRegistryPath = resolvePath(base, config.MappingRegistryPath)
	config.RuntimeBinaryPath = resolvePath(base, config.RuntimeBinaryPath)
	config.IdempotencyRoot = resolvePath(base, config.IdempotencyRoot)
	for index := range config.RuntimeBindings {
		config.RuntimeBindings[index].PackagePath = resolvePath(base, config.RuntimeBindings[index].PackagePath)
	}
	if err := ValidateConfig(config); err != nil {
		return Config{}, err
	}
	return config, nil
}

func ValidateConfig(config Config) error {
	if config.SchemaVersion != ConfigSchemaVersion {
		return fmt.Errorf("schema_version must be %q", ConfigSchemaVersion)
	}
	for field, value := range map[string]string{
		"listen_address":        config.ListenAddress,
		"catalog_registry_path": config.CatalogRegistryPath,
		"mapping_registry_path": config.MappingRegistryPath,
		"runtime_binary_path":   config.RuntimeBinaryPath,
		"idempotency_root":      config.IdempotencyRoot,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}
	if config.MaxBodyBytes < 1024 || config.MaxBodyBytes > 64<<20 {
		return fmt.Errorf("max_body_bytes must be between 1024 and 67108864")
	}
	if config.MaxBatchItems <= 0 || config.MaxBatchItems > 10_000 {
		return fmt.Errorf("max_batch_items must be between 1 and 10000")
	}
	if config.MaxCandidates <= 0 || config.MaxCandidates > 10_000 {
		return fmt.Errorf("max_candidates must be between 1 and 10000")
	}
	if config.RequestTimeoutMS < 100 || config.RequestTimeoutMS > 300_000 {
		return fmt.Errorf("request_timeout_ms must be between 100 and 300000")
	}
	if len(config.RuntimeBindings) == 0 {
		return fmt.Errorf("runtime_bindings must not be empty")
	}
	seen := map[string]struct{}{}
	for index, binding := range config.RuntimeBindings {
		if !strings.HasPrefix(binding.ComponentID, "catalog_component_") {
			return fmt.Errorf("runtime_bindings[%d].component_id is invalid", index)
		}
		if !strings.HasPrefix(binding.VersionID, "catalog_version_") {
			return fmt.Errorf("runtime_bindings[%d].version_id is invalid", index)
		}
		if strings.TrimSpace(binding.PackagePath) == "" {
			return fmt.Errorf("runtime_bindings[%d].package_path is required", index)
		}
		if len(binding.PackageSHA256) != 64 {
			return fmt.Errorf("runtime_bindings[%d].package_sha256 must be a SHA-256 digest", index)
		}
		if _, err := hex.DecodeString(binding.PackageSHA256); err != nil {
			return fmt.Errorf("runtime_bindings[%d].package_sha256 is not hexadecimal", index)
		}
		if binding.WorkerCount <= 0 || binding.WorkerCount > 64 {
			return fmt.Errorf("runtime_bindings[%d].worker_count must be between 1 and 64", index)
		}
		key := binding.ComponentID + "\x1f" + binding.VersionID
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate runtime binding for %s/%s", binding.ComponentID, binding.VersionID)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func resolvePath(base, value string) string {
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Clean(filepath.Join(base, value))
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
