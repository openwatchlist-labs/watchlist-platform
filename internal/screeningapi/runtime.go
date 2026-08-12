package screeningapi

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogregistry"
	"github.com/openwatchlist-labs/watchlist-platform/internal/runtimemmapclient"
)

type RuntimeResult struct {
	Info       runtimemmapclient.PackageInfo
	Candidates []runtimemmapclient.Candidate
}

type RuntimeProvider interface {
	Lookup(context.Context, string, string, runtimemmapclient.Query) (RuntimeResult, error)
	Ready(catalogregistry.Registry) error
	// PackageInfo returns the bound runtime package whose PackageSHA256
	// matches, reading its metadata straight from the package the runtime
	// actually serves (ADR-0004 §2, §9.4) rather than from any
	// config-declared descriptor.
	PackageInfo(packageSHA256 string) (runtimemmapclient.PackageInfo, bool)
	Close() error
}

type boundRuntime struct {
	binding RuntimeBinding
	pool    *runtimemmapclient.Pool
}

type RuntimeManager struct {
	mu       sync.RWMutex
	bindings map[string]*boundRuntime
}

func StartRuntimeManager(ctx context.Context, config Config, catalog catalogregistry.Registry) (*RuntimeManager, error) {
	manager := &RuntimeManager{bindings: map[string]*boundRuntime{}}
	for _, binding := range config.RuntimeBindings {
		version, ok := findCatalogVersion(catalog, binding.VersionID)
		if !ok || version.ComponentID != binding.ComponentID {
			_ = manager.Close()
			return nil, fmt.Errorf("runtime binding references unknown catalog version %s for component %s", binding.VersionID, binding.ComponentID)
		}
		pool, err := runtimemmapclient.StartPool(ctx, config.RuntimeBinaryPath, binding.PackagePath, binding.WorkerCount)
		if err != nil {
			_ = manager.Close()
			return nil, fmt.Errorf("start runtime binding %s/%s: %w", binding.ComponentID, binding.VersionID, err)
		}
		info := pool.Info()
		if err := validateRuntimeInfo(binding, version, info); err != nil {
			_ = pool.Close()
			_ = manager.Close()
			return nil, err
		}
		manager.bindings[runtimeKey(binding.ComponentID, binding.VersionID)] = &boundRuntime{binding: binding, pool: pool}
	}
	if err := manager.Ready(catalog); err != nil {
		_ = manager.Close()
		return nil, err
	}
	return manager, nil
}

func (manager *RuntimeManager) Lookup(ctx context.Context, componentID, versionID string, query runtimemmapclient.Query) (RuntimeResult, error) {
	manager.mu.RLock()
	binding := manager.bindings[runtimeKey(componentID, versionID)]
	manager.mu.RUnlock()
	if binding == nil {
		return RuntimeResult{}, fmt.Errorf("runtime package is not bound for active component %s version %s", componentID, versionID)
	}
	candidates, err := binding.pool.Lookup(ctx, query)
	if err != nil {
		return RuntimeResult{}, err
	}
	return RuntimeResult{Info: binding.pool.Info(), Candidates: candidates}, nil
}

func (manager *RuntimeManager) PackageInfo(packageSHA256 string) (runtimemmapclient.PackageInfo, bool) {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	for _, binding := range manager.bindings {
		info := binding.pool.Info()
		if strings.EqualFold(info.PackageSHA256, packageSHA256) {
			return info, true
		}
	}
	return runtimemmapclient.PackageInfo{}, false
}

func (manager *RuntimeManager) Ready(catalog catalogregistry.Registry) error {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	for _, pointer := range catalog.Active {
		binding := manager.bindings[runtimeKey(pointer.ComponentID, pointer.VersionID)]
		if binding == nil {
			return fmt.Errorf("active catalog component %s version %s has no Rust runtime package binding", pointer.ComponentID, pointer.VersionID)
		}
		version, ok := findCatalogVersion(catalog, pointer.VersionID)
		if !ok {
			return fmt.Errorf("active version %s is not registered", pointer.VersionID)
		}
		if err := validateRuntimeInfo(binding.binding, version, binding.pool.Info()); err != nil {
			return err
		}
	}
	return nil
}

func (manager *RuntimeManager) Close() error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	var first error
	for _, binding := range manager.bindings {
		if err := binding.pool.Close(); err != nil && first == nil {
			first = err
		}
	}
	manager.bindings = map[string]*boundRuntime{}
	return first
}

func validateRuntimeInfo(binding RuntimeBinding, version catalogregistry.CatalogVersion, info runtimemmapclient.PackageInfo) error {
	if info.ProtocolVersion != runtimemmapclient.ProtocolVersion {
		return fmt.Errorf("runtime protocol %q is unsupported", info.ProtocolVersion)
	}
	checks := []struct {
		name, actual, expected string
	}{
		{"component_id", info.ComponentID, binding.ComponentID},
		{"catalog_id", info.CatalogID, version.CatalogID},
		{"catalog_version", info.CatalogVersion, version.CatalogVersion},
		{"catalog_checksum", strings.ToLower(info.CatalogChecksum), strings.ToLower(version.CatalogChecksum)},
		{"catalog_mode", info.CatalogMode, string(versionMode(version))},
		{"package_sha256", strings.ToLower(info.PackageSHA256), strings.ToLower(binding.PackageSHA256)},
	}
	for _, check := range checks {
		if check.actual != check.expected {
			return fmt.Errorf("runtime %s=%q does not match active catalog metadata %q", check.name, check.actual, check.expected)
		}
	}
	if info.RecordCount != uint64(version.RecordCount) {
		return fmt.Errorf("runtime record_count=%d does not match catalog version record_count=%d", info.RecordCount, version.RecordCount)
	}
	return nil
}

func versionMode(version catalogregistry.CatalogVersion) catalogregistry.CatalogMode {
	if version.Source.Kind == catalogregistry.SourceKindProvider {
		return catalogregistry.CatalogModeProvider
	}
	return catalogregistry.CatalogModeOfficial
}

func runtimeKey(componentID, versionID string) string { return componentID + "\x1f" + versionID }
