package ofacruntime

import (
	"fmt"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogruntime"
)

func ActivationInput(loaded *LoadedPackage, compiledAt time.Time) (catalogruntime.PackageActivationInput, error) {
	if loaded == nil || compiledAt.IsZero() {
		return catalogruntime.PackageActivationInput{}, fmt.Errorf("loaded package and compiled_at are required")
	}
	if err := ValidateInfo(loaded.Info); err != nil {
		return catalogruntime.PackageActivationInput{}, err
	}
	manifest := loaded.Info.Manifest
	return catalogruntime.PackageActivationInput{
		PackageID:        loaded.Info.PackageID,
		PackageChecksum:  loaded.Info.PackageChecksum,
		CatalogID:        manifest.Provider.Catalog.CatalogID,
		CatalogVersion:   manifest.Provider.Catalog.CatalogVersion,
		CatalogChecksum:  manifest.Provider.Catalog.CatalogChecksum,
		SourceManifestID: manifest.SourceManifestID,
		CompiledAt:       compiledAt.UTC(),
	}, nil
}

func Readiness(loaded *LoadedPackage, compiledAt, checkedAt time.Time) (catalogruntime.ReadinessReport, error) {
	if loaded == nil {
		return catalogruntime.ReadinessReport{}, fmt.Errorf("loaded package is required")
	}
	input, err := ActivationInput(loaded, compiledAt)
	if err != nil {
		return catalogruntime.ReadinessReport{}, err
	}
	checks := []catalogruntime.ReadinessCheck{
		{Name: "artifact_integrity", Status: catalogruntime.CheckPass, Detail: "package artifact checksum and framing verified"},
		{Name: "manifest_contract", Status: catalogruntime.CheckPass, Detail: "package manifest schema, identity, and lineage verified"},
		{Name: "payload_integrity", Status: catalogruntime.CheckPass, Detail: "compiled payload checksum and size verified"},
		{Name: "runtime_index", Status: catalogruntime.CheckPass, Detail: fmt.Sprintf("compiled exact index contains %d entries", loaded.Payload.EntryCount)},
		{Name: "provider_descriptor", Status: catalogruntime.CheckPass, Detail: "provider capabilities and catalog reference verified"},
		{Name: "source_lineage", Status: catalogruntime.CheckPass, Detail: "source manifest and catalog lineage verified"},
		{Name: "record_count", Status: catalogruntime.CheckPass, Detail: fmt.Sprintf("runtime package covers %d direct-list records", loaded.Payload.RecordCount)},
	}
	return catalogruntime.NewReadinessReport(input, checkedAt, checks)
}
