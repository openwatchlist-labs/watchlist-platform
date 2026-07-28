package providerrefresh

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertlistmapping"
	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogregistry"
)

const (
	ViolationProviderChanged   = "PROVIDER_ID_CHANGED"
	ViolationAddedExceeded     = "ADDED_COMPONENT_THRESHOLD_EXCEEDED"
	ViolationRemovedExceeded   = "REMOVED_COMPONENT_THRESHOLD_EXCEEDED"
	ViolationRenamedExceeded   = "RENAMED_COMPONENT_THRESHOLD_EXCEEDED"
	ViolationMappedUnavailable = "MAPPED_COMPONENT_UNAVAILABLE"
	ViolationTargetUnavailable = "TARGET_COMPONENT_UNAVAILABLE"
	ViolationRecordDelta       = "RECORD_COUNT_DELTA_EXCEEDED"
)

func NormalizeInventory(input ProviderInventory) (ProviderInventory, error) {
	input.SchemaVersion = InventorySchemaVersion
	input.ProviderID = strings.TrimSpace(input.ProviderID)
	input.ProviderVersion = strings.TrimSpace(input.ProviderVersion)
	input.GeneratedAt = input.GeneratedAt.UTC()
	components := make([]ProviderComponent, len(input.Components))
	for i, component := range input.Components {
		component.ProviderComponentRef = strings.TrimSpace(component.ProviderComponentRef)
		component.ProviderTitle = strings.TrimSpace(component.ProviderTitle)
		component.CatalogID = strings.TrimSpace(component.CatalogID)
		component.CatalogVersion = strings.TrimSpace(component.CatalogVersion)
		component.CatalogChecksum = strings.ToLower(strings.TrimSpace(component.CatalogChecksum))
		component.CatalogSchema = strings.TrimSpace(component.CatalogSchema)
		component.ArtifactURI = strings.TrimSpace(component.ArtifactURI)
		component.ArtifactSHA256 = strings.ToLower(strings.TrimSpace(component.ArtifactSHA256))
		component.SourceManifestID = strings.TrimSpace(component.SourceManifestID)
		component.SourceManifestHash = strings.ToLower(strings.TrimSpace(component.SourceManifestHash))
		component.ProducerVersion = strings.TrimSpace(component.ProducerVersion)
		component.Metadata = normalizeMap(component.Metadata)
		components[i] = component
	}
	sort.Slice(components, func(i, j int) bool { return components[i].ProviderComponentRef < components[j].ProviderComponentRef })
	input.Components = components
	input.InventoryChecksum = inventoryChecksum(input)
	if err := ValidateInventory(input); err != nil {
		return ProviderInventory{}, err
	}
	return input, nil
}

func DefaultPolicy() RefreshPolicy {
	return RefreshPolicy{
		SchemaVersion:                       PolicySchemaVersion,
		MaxAddedComponents:                  10,
		MaxRemovedComponents:                0,
		MaxRenamedComponents:                10,
		MaxRecordCountDeltaPercent:          20,
		RequireAllMappedComponentsAvailable: true,
		RequireTargetComponentAvailable:     true,
		RequireProviderIDUnchanged:          true,
	}
}

func NewRegistry(namespace string) (Registry, error) {
	registry := Registry{SchemaVersion: RegistrySchemaVersion, RegistryID: registryID(namespace), Namespace: strings.TrimSpace(namespace), EngineVersion: EngineVersion, Candidates: []RefreshCandidate{}, Decisions: []PromotionDecision{}, Executions: []PromotionExecution{}}
	registry.RegistryChecksum = registryChecksum(registry)
	if err := ValidateRegistry(registry, catalogregistry.Registry{}); err != nil && !strings.Contains(err.Error(), "candidate") { // empty catalog is valid for empty registry
		return Registry{}, err
	}
	return registry, nil
}

func Analyze(input AnalyzeInput, catalog catalogregistry.Registry, mappings alertlistmapping.Registry) (RefreshCandidate, error) {
	if strings.TrimSpace(input.Namespace) == "" || input.Namespace != catalog.Namespace || input.Namespace != mappings.Namespace {
		return RefreshCandidate{}, fmt.Errorf("namespace must match catalog and mapping registries")
	}
	if input.AnalyzedAt.IsZero() || strings.TrimSpace(input.AnalyzedBy) == "" || strings.TrimSpace(input.Reason) == "" {
		return RefreshCandidate{}, fmt.Errorf("analyzed_at, analyzed_by, and reason are required")
	}
	if err := ValidatePolicy(input.Policy); err != nil {
		return RefreshCandidate{}, err
	}
	previous, err := NormalizeInventory(input.Previous)
	if err != nil {
		return RefreshCandidate{}, fmt.Errorf("previous inventory: %w", err)
	}
	candidateInventory, err := NormalizeInventory(input.Candidate)
	if err != nil {
		return RefreshCandidate{}, fmt.Errorf("candidate inventory: %w", err)
	}
	target, ok := findComponent(catalog, strings.TrimSpace(input.TargetComponentID))
	if !ok || target.CatalogMode != catalogregistry.CatalogModeProvider {
		return RefreshCandidate{}, fmt.Errorf("target component must be a registered provider component")
	}
	currentPointer, ok := findActive(catalog, target.ComponentID)
	if !ok {
		return RefreshCandidate{}, fmt.Errorf("target component has no active catalog version")
	}
	currentVersion, ok := findVersion(catalog, currentPointer.VersionID)
	if !ok || currentVersion.Source.Provider == nil {
		return RefreshCandidate{}, fmt.Errorf("target active version is not a provider version")
	}

	previousByRef := componentMap(previous)
	candidateByRef := componentMap(candidateInventory)
	renameMap := map[string]string{}
	renameReason := map[string]string{}
	toSeen := map[string]struct{}{}
	for _, rename := range input.Renames {
		from := strings.TrimSpace(rename.FromProviderComponentRef)
		to := strings.TrimSpace(rename.ToProviderComponentRef)
		if from == "" || to == "" || from == to {
			return RefreshCandidate{}, fmt.Errorf("rename directive must contain distinct references")
		}
		if _, ok := previousByRef[from]; !ok {
			return RefreshCandidate{}, fmt.Errorf("rename source %q is not in previous inventory", from)
		}
		if _, ok := candidateByRef[to]; !ok {
			return RefreshCandidate{}, fmt.Errorf("rename target %q is not in candidate inventory", to)
		}
		if _, ok := renameMap[from]; ok {
			return RefreshCandidate{}, fmt.Errorf("duplicate rename source %q", from)
		}
		if _, ok := toSeen[to]; ok {
			return RefreshCandidate{}, fmt.Errorf("duplicate rename target %q", to)
		}
		renameMap[from] = to
		renameReason[from] = strings.TrimSpace(rename.Reason)
		toSeen[to] = struct{}{}
	}

	changes := make([]ComponentChange, 0)
	consumedCandidate := map[string]struct{}{}
	for _, old := range previous.Components {
		if _, ok := candidateByRef[old.ProviderComponentRef]; ok {
			changes = append(changes, ComponentChange{ChangeType: ChangeUnchanged, FromProviderComponentRef: old.ProviderComponentRef, ToProviderComponentRef: old.ProviderComponentRef})
			consumedCandidate[old.ProviderComponentRef] = struct{}{}
			continue
		}
		if to, ok := renameMap[old.ProviderComponentRef]; ok {
			changes = append(changes, ComponentChange{ChangeType: ChangeRenamed, FromProviderComponentRef: old.ProviderComponentRef, ToProviderComponentRef: to, Reason: renameReason[old.ProviderComponentRef]})
			consumedCandidate[to] = struct{}{}
			continue
		}
		changes = append(changes, ComponentChange{ChangeType: ChangeRemoved, FromProviderComponentRef: old.ProviderComponentRef})
	}
	for _, next := range candidateInventory.Components {
		if _, ok := consumedCandidate[next.ProviderComponentRef]; !ok {
			changes = append(changes, ComponentChange{ChangeType: ChangeAdded, ToProviderComponentRef: next.ProviderComponentRef})
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		ai := string(changes[i].ChangeType) + changes[i].FromProviderComponentRef + changes[i].ToProviderComponentRef
		aj := string(changes[j].ChangeType) + changes[j].FromProviderComponentRef + changes[j].ToProviderComponentRef
		return ai < aj
	})

	impacts := make([]MappingImpact, 0)
	for _, component := range catalog.Components {
		if component.CatalogMode != catalogregistry.CatalogModeProvider || component.Status != catalogregistry.ComponentStatusActive {
			continue
		}
		pointer, ok := findActive(catalog, component.ComponentID)
		if !ok {
			continue
		}
		version, ok := findVersion(catalog, pointer.VersionID)
		if !ok || version.Source.Provider == nil || version.Source.Provider.ProviderID != previous.ProviderID {
			continue
		}
		currentRef := version.Source.Provider.ProviderComponentRef
		candidateRef := currentRef
		status := ImpactAvailable
		next, exists := candidateByRef[currentRef]
		if !exists {
			if renamed, ok := renameMap[currentRef]; ok {
				candidateRef = renamed
				next = candidateByRef[renamed]
				status = ImpactRenamed
				exists = true
			} else {
				status = ImpactMissing
			}
		}
		impact := MappingImpact{ComponentID: component.ComponentID, ComponentKey: component.ComponentKey, CurrentVersionID: version.VersionID, CurrentProviderComponentRef: currentRef, CandidateProviderComponentRef: candidateRef, Status: status, ActiveMappingCount: activeMappingCount(mappings, component.ComponentID, input.AnalyzedAt), CurrentRecordCount: version.RecordCount}
		if exists {
			impact.CandidateRecordCount = next.RecordCount
			impact.RecordCountDeltaPercent = deltaPercent(version.RecordCount, next.RecordCount)
		}
		if status == ImpactMissing && impact.ActiveMappingCount > 0 {
			impact.Blockers = append(impact.Blockers, ViolationMappedUnavailable)
		}
		if exists && impact.RecordCountDeltaPercent > input.Policy.MaxRecordCountDeltaPercent {
			impact.Blockers = append(impact.Blockers, ViolationRecordDelta)
		}
		impacts = append(impacts, impact)
	}
	sort.Slice(impacts, func(i, j int) bool { return impacts[i].ComponentID < impacts[j].ComponentID })

	violations := make([]string, 0)
	if input.Policy.RequireProviderIDUnchanged && previous.ProviderID != candidateInventory.ProviderID {
		violations = append(violations, ViolationProviderChanged)
	}
	added, removed, renamed := countChanges(changes)
	if added > input.Policy.MaxAddedComponents {
		violations = append(violations, ViolationAddedExceeded)
	}
	if removed > input.Policy.MaxRemovedComponents {
		violations = append(violations, ViolationRemovedExceeded)
	}
	if renamed > input.Policy.MaxRenamedComponents {
		violations = append(violations, ViolationRenamedExceeded)
	}
	for _, impact := range impacts {
		if input.Policy.RequireAllMappedComponentsAvailable && impact.Status == ImpactMissing && impact.ActiveMappingCount > 0 {
			violations = appendUnique(violations, ViolationMappedUnavailable)
		}
		if impact.RecordCountDeltaPercent > input.Policy.MaxRecordCountDeltaPercent {
			violations = appendUnique(violations, ViolationRecordDelta)
		}
	}

	targetRef := currentVersion.Source.Provider.ProviderComponentRef
	if to, ok := renameMap[targetRef]; ok {
		targetRef = to
	}
	targetCandidate, available := candidateByRef[targetRef]
	if !available && input.Policy.RequireTargetComponentAvailable {
		violations = appendUnique(violations, ViolationTargetUnavailable)
	}
	candidateVersion := CandidateVersion{ComponentID: target.ComponentID, ExpectedCurrentVersionID: currentVersion.VersionID, ProviderID: candidateInventory.ProviderID, ProviderComponentRef: targetRef, ProviderVersion: candidateInventory.ProviderVersion}
	if available {
		candidateVersion.CatalogID = targetCandidate.CatalogID
		candidateVersion.CatalogVersion = targetCandidate.CatalogVersion
		candidateVersion.CatalogChecksum = targetCandidate.CatalogChecksum
		candidateVersion.CatalogSchema = targetCandidate.CatalogSchema
		candidateVersion.ArtifactURI = targetCandidate.ArtifactURI
		candidateVersion.ArtifactSHA256 = targetCandidate.ArtifactSHA256
		candidateVersion.SourceManifestID = targetCandidate.SourceManifestID
		candidateVersion.SourceManifestHash = targetCandidate.SourceManifestHash
		candidateVersion.RecordCount = targetCandidate.RecordCount
		candidateVersion.ProducerVersion = targetCandidate.ProducerVersion
		candidateVersion.ProviderTitle = targetCandidate.ProviderTitle
		candidateVersion.Metadata = normalizeMap(targetCandidate.Metadata)
	}
	status := CandidateReady
	if len(violations) > 0 {
		status = CandidateBlocked
	}
	result := RefreshCandidate{SchemaVersion: CandidateSchemaVersion, RegistryID: registryID(input.Namespace), Namespace: input.Namespace, Status: status, TargetComponentID: target.ComponentID, PreviousInventoryID: previous.InventoryChecksum, CandidateInventoryID: candidateInventory.InventoryChecksum, Policy: input.Policy, Changes: changes, MappingImpacts: impacts, PolicyViolations: violations, CandidateVersion: candidateVersion, AnalyzedAt: input.AnalyzedAt.UTC(), AnalyzedBy: strings.TrimSpace(input.AnalyzedBy), Reason: strings.TrimSpace(input.Reason)}
	result.CandidateID = candidateID(result)
	result.CandidateChecksum = candidateChecksum(result)
	if err := ValidateCandidate(result, catalog); err != nil {
		return RefreshCandidate{}, err
	}
	return result, nil
}

func componentMap(in ProviderInventory) map[string]ProviderComponent {
	out := make(map[string]ProviderComponent, len(in.Components))
	for _, v := range in.Components {
		out[v.ProviderComponentRef] = v
	}
	return out
}
func normalizeMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range values {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k != "" && v != "" {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
func deltaPercent(old, next int) float64 {
	if old == 0 {
		if next == 0 {
			return 0
		}
		return 100
	}
	return math.Round(math.Abs(float64(next-old))/float64(old)*1000000) / 10000
}
func countChanges(changes []ComponentChange) (int, int, int) {
	a, r, n := 0, 0, 0
	for _, c := range changes {
		switch c.ChangeType {
		case ChangeAdded:
			a++
		case ChangeRemoved:
			r++
		case ChangeRenamed:
			n++
		}
	}
	return a, r, n
}
func appendUnique(values []string, value string) []string {
	for _, v := range values {
		if v == value {
			return values
		}
	}
	return append(values, value)
}

func activeMappingCount(registry alertlistmapping.Registry, componentID string, at time.Time) int {
	latest := map[string]alertlistmapping.MappingVersion{}
	for _, version := range registry.Versions {
		if version.EffectiveFrom.After(at) {
			continue
		}
		current, ok := latest[version.MappingID]
		if !ok || version.EffectiveFrom.After(current.EffectiveFrom) {
			latest[version.MappingID] = version
		}
	}
	count := 0
	for _, version := range latest {
		if version.Action != alertlistmapping.MappingActionBind || version.ComponentID != componentID {
			continue
		}
		if version.EffectiveTo != nil && !at.Before(*version.EffectiveTo) {
			continue
		}
		count++
	}
	return count
}
