package screeningapi

import (
	"fmt"
	"os"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertlistmapping"
	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogregistry"
)

type State struct {
	Catalog catalogregistry.Registry
	Mapping alertlistmapping.Registry
}

type StateLoader interface {
	Load() (State, error)
}

type FileStateLoader struct {
	CatalogRegistryPath string
	MappingRegistryPath string
}

func (loader FileStateLoader) Load() (State, error) {
	catalogData, err := os.ReadFile(loader.CatalogRegistryPath)
	if err != nil {
		return State{}, fmt.Errorf("read catalog registry: %w", err)
	}
	var catalog catalogregistry.Registry
	if err := decodeStrict(catalogData, &catalog); err != nil {
		return State{}, fmt.Errorf("decode catalog registry: %w", err)
	}
	if err := catalogregistry.ValidateRegistry(catalog); err != nil {
		return State{}, fmt.Errorf("validate catalog registry: %w", err)
	}
	mappingData, err := os.ReadFile(loader.MappingRegistryPath)
	if err != nil {
		return State{}, fmt.Errorf("read alert-list mapping registry: %w", err)
	}
	var mapping alertlistmapping.Registry
	if err := decodeStrict(mappingData, &mapping); err != nil {
		return State{}, fmt.Errorf("decode alert-list mapping registry: %w", err)
	}
	if err := alertlistmapping.ValidateRegistry(mapping, catalog); err != nil {
		return State{}, fmt.Errorf("validate alert-list mapping registry: %w", err)
	}
	return State{Catalog: catalog, Mapping: mapping}, nil
}

func findActivePointer(registry catalogregistry.Registry, componentID string) (catalogregistry.ActivePointer, bool) {
	for _, pointer := range registry.Active {
		if pointer.ComponentID == componentID {
			return pointer, true
		}
	}
	return catalogregistry.ActivePointer{}, false
}

func findCatalogVersion(registry catalogregistry.Registry, versionID string) (catalogregistry.CatalogVersion, bool) {
	for _, version := range registry.Versions {
		if version.VersionID == versionID {
			return version, true
		}
	}
	return catalogregistry.CatalogVersion{}, false
}
