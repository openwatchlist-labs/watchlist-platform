package alertlistmapping

import (
	"fmt"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogregistry"
)

func Resolve(registry Registry, catalog catalogregistry.Registry, request ResolveRequest) (Resolution, error) {
	if err := ValidateRegistry(registry, catalog); err != nil {
		return Resolution{}, err
	}
	if !sourceSystemPattern.MatchString(request.SourceSystemID) {
		return Resolution{}, fmt.Errorf("source_system_id must match %s", sourceSystemPattern.String())
	}
	if err := validateRawListName(request.RawListName); err != nil {
		return Resolution{}, err
	}
	if request.At.IsZero() {
		return Resolution{}, fmt.Errorf("resolution time is required")
	}
	at := request.At.UTC()
	result := Resolution{
		SchemaVersion:     ResolutionSchemaVersion,
		MappingRegistryID: registry.RegistryID,
		Namespace:         registry.Namespace,
		SourceSystemID:    request.SourceSystemID,
		RawListName:       request.RawListName,
		ResolvedAt:        at,
	}
	id := mappingID(registry.Namespace, request.SourceSystemID, request.RawListName)
	keyExists := false
	for _, key := range registry.Keys {
		if key.MappingID == id && key.SourceSystemID == request.SourceSystemID && key.RawListName == request.RawListName {
			keyExists = true
			break
		}
	}
	if !keyExists {
		return blocked(result, ResolutionUnmapped, BlockerMappingRequired, false), nil
	}
	result.ExactMatch = true
	result.MappingID = id
	var selected *MappingVersion
	for index := range registry.Versions {
		candidate := &registry.Versions[index]
		if candidate.MappingID != id || candidate.EffectiveFrom.After(at) {
			continue
		}
		if selected == nil || candidate.EffectiveFrom.After(selected.EffectiveFrom) {
			selected = candidate
		}
	}
	if selected == nil {
		return blocked(result, ResolutionNotEffective, BlockerMappingNotEffective, true), nil
	}
	result.MappingVersionID = selected.MappingVersionID
	from := selected.EffectiveFrom
	result.MappingEffectiveFrom = &from
	if selected.EffectiveTo != nil {
		to := selected.EffectiveTo.UTC()
		result.MappingEffectiveTo = &to
		if !at.Before(to) {
			return blocked(result, ResolutionExpired, BlockerMappingExpired, true), nil
		}
	}
	if selected.Action == MappingActionRetire {
		return blocked(result, ResolutionRetired, BlockerMappingRetired, true), nil
	}
	result.ComponentID = selected.ComponentID
	component, ok := catalogComponent(catalog, selected.ComponentID)
	if !ok {
		return blocked(result, ResolutionComponentMissing, BlockerComponentMissing, true), nil
	}
	result.ComponentKey = component.ComponentKey
	result.ComponentDisplayName = component.DisplayName
	result.CatalogMode = string(component.CatalogMode)
	if component.Status != catalogregistry.ComponentStatusActive {
		return blocked(result, ResolutionComponentRetired, BlockerComponentRetired, true), nil
	}
	pointer, ok := activePointer(catalog, component.ComponentID)
	if !ok {
		return blocked(result, ResolutionCatalogNotActive, BlockerCatalogNotActive, true), nil
	}
	version, ok := catalogVersion(catalog, pointer.VersionID)
	if !ok {
		return blocked(result, ResolutionCatalogNotActive, BlockerCatalogNotActive, true), nil
	}
	result.Status = ResolutionResolved
	result.Available = true
	result.ActiveCatalogVersionID = version.VersionID
	result.ActiveCatalogID = version.CatalogID
	result.ActiveCatalogVersion = version.CatalogVersion
	result.ActiveCatalogChecksum = version.CatalogChecksum
	result.ActiveArtifactURI = version.ArtifactURI
	return result, nil
}

func ResolveBatch(registry Registry, catalog catalogregistry.Registry, input BatchInput) (BatchResult, error) {
	if input.At.IsZero() {
		return BatchResult{}, fmt.Errorf("batch resolution time is required")
	}
	result := BatchResult{
		SchemaVersion: BatchResolutionSchemaVersion,
		ResolvedAt:    input.At.UTC(),
		Results:       make([]BatchResultItem, 0, len(input.Alerts)),
	}
	seen := map[string]struct{}{}
	for _, alert := range input.Alerts {
		if alert.AlertID == "" {
			return BatchResult{}, fmt.Errorf("alert_id is required")
		}
		if _, exists := seen[alert.AlertID]; exists {
			return BatchResult{}, fmt.Errorf("duplicate alert_id %q", alert.AlertID)
		}
		seen[alert.AlertID] = struct{}{}
		resolution, err := Resolve(registry, catalog, ResolveRequest{
			SourceSystemID: alert.SourceSystemID,
			RawListName:    alert.RawListName,
			At:             input.At,
		})
		if err != nil {
			return BatchResult{}, fmt.Errorf("resolve alert %s: %w", alert.AlertID, err)
		}
		result.Results = append(result.Results, BatchResultItem{AlertID: alert.AlertID, Resolution: resolution})
		incrementSummary(&result.Summary, resolution.Status)
	}
	result.Summary.Total = len(result.Results)
	return result, nil
}

func blocked(result Resolution, status ResolutionStatus, blocker string, exact bool) Resolution {
	result.Status = status
	result.Available = false
	result.ExactMatch = exact
	result.ReviewBlocker = blocker
	return result
}

func incrementSummary(summary *BatchSummary, status ResolutionStatus) {
	switch status {
	case ResolutionResolved:
		summary.Resolved++
	case ResolutionUnmapped:
		summary.Unmapped++
	case ResolutionNotEffective:
		summary.NotEffective++
	case ResolutionExpired:
		summary.Expired++
	case ResolutionRetired:
		summary.Retired++
	case ResolutionComponentMissing:
		summary.ComponentMissing++
	case ResolutionComponentRetired:
		summary.ComponentRetired++
	case ResolutionCatalogNotActive:
		summary.CatalogNotActive++
	}
}

func ParseTime(value string) (time.Time, error) {
	return time.Parse(time.RFC3339, value)
}
