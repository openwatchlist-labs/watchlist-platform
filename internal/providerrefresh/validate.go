package providerrefresh

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogregistry"
)

var ErrInvalidRegistry = errors.New("invalid provider refresh registry")
var simpleID = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,255}$`)

func ValidateInventory(inventory ProviderInventory) error {
	if inventory.SchemaVersion != InventorySchemaVersion {
		return fmt.Errorf("inventory schema_version must be %q", InventorySchemaVersion)
	}
	if !simpleID.MatchString(inventory.ProviderID) {
		return fmt.Errorf("provider_id is invalid")
	}
	if strings.TrimSpace(inventory.ProviderVersion) == "" || inventory.GeneratedAt.IsZero() {
		return fmt.Errorf("provider_version and generated_at are required")
	}
	seen := map[string]struct{}{}
	for _, component := range inventory.Components {
		if !simpleID.MatchString(component.ProviderComponentRef) {
			return fmt.Errorf("provider_component_ref %q is invalid", component.ProviderComponentRef)
		}
		if _, exists := seen[component.ProviderComponentRef]; exists {
			return fmt.Errorf("duplicate provider_component_ref %q", component.ProviderComponentRef)
		}
		seen[component.ProviderComponentRef] = struct{}{}
		if component.RecordCount < 0 || !isSHA256(component.CatalogChecksum) || !isSHA256(component.ArtifactSHA256) {
			return fmt.Errorf("component %q has invalid record count or checksum", component.ProviderComponentRef)
		}
		if strings.TrimSpace(component.CatalogID) == "" || strings.TrimSpace(component.CatalogVersion) == "" || strings.TrimSpace(component.CatalogSchema) == "" || strings.TrimSpace(component.ArtifactURI) == "" || strings.TrimSpace(component.SourceManifestID) == "" || strings.TrimSpace(component.ProducerVersion) == "" {
			return fmt.Errorf("component %q is missing catalog metadata", component.ProviderComponentRef)
		}
	}
	if !sort.SliceIsSorted(inventory.Components, func(i, j int) bool {
		return inventory.Components[i].ProviderComponentRef < inventory.Components[j].ProviderComponentRef
	}) {
		return fmt.Errorf("inventory components must be sorted by provider_component_ref")
	}
	if !isSHA256(inventory.InventoryChecksum) || inventory.InventoryChecksum != inventoryChecksum(inventory) {
		return fmt.Errorf("inventory checksum mismatch")
	}
	return nil
}

func ValidatePolicy(policy RefreshPolicy) error {
	if policy.SchemaVersion != PolicySchemaVersion {
		return fmt.Errorf("policy schema_version must be %q", PolicySchemaVersion)
	}
	if policy.MaxAddedComponents < 0 || policy.MaxRemovedComponents < 0 || policy.MaxRenamedComponents < 0 {
		return fmt.Errorf("component thresholds cannot be negative")
	}
	if math.IsNaN(policy.MaxRecordCountDeltaPercent) || math.IsInf(policy.MaxRecordCountDeltaPercent, 0) || policy.MaxRecordCountDeltaPercent < 0 {
		return fmt.Errorf("record-count threshold is invalid")
	}
	return nil
}

func ValidateCandidate(candidate RefreshCandidate, catalog catalogregistry.Registry) error {
	if candidate.SchemaVersion != CandidateSchemaVersion {
		return fmt.Errorf("candidate schema_version must be %q", CandidateSchemaVersion)
	}
	if candidate.RegistryID == "" || candidate.Namespace == "" || candidate.TargetComponentID == "" || candidate.AnalyzedAt.IsZero() || strings.TrimSpace(candidate.AnalyzedBy) == "" || strings.TrimSpace(candidate.Reason) == "" {
		return fmt.Errorf("candidate identity and audit fields are required")
	}
	if candidate.Namespace != catalog.Namespace {
		return fmt.Errorf("candidate namespace does not match catalog registry")
	}
	component, ok := findComponent(catalog, candidate.TargetComponentID)
	if !ok || component.CatalogMode != catalogregistry.CatalogModeProvider {
		return fmt.Errorf("target component must be a registered provider component")
	}
	if candidate.CandidateVersion.ComponentID != candidate.TargetComponentID || candidate.CandidateVersion.ProviderID == "" || candidate.CandidateVersion.ProviderComponentRef == "" {
		return fmt.Errorf("candidate version target is invalid")
	}
	if !isSHA256(candidate.PreviousInventoryID) || !isSHA256(candidate.CandidateInventoryID) {
		return fmt.Errorf("candidate inventory checksums are invalid")
	}
	if err := ValidatePolicy(candidate.Policy); err != nil {
		return err
	}
	if candidate.Status == CandidateReady && len(candidate.PolicyViolations) != 0 {
		return fmt.Errorf("ready candidate has policy violations")
	}
	if candidate.Status == CandidateBlocked && len(candidate.PolicyViolations) == 0 {
		return fmt.Errorf("blocked candidate has no policy violations")
	}
	if candidate.Status != CandidateReady && candidate.Status != CandidateBlocked {
		return fmt.Errorf("unsupported candidate status")
	}
	if candidate.CandidateID != candidateID(candidate) || !isSHA256(candidate.CandidateChecksum) || candidate.CandidateChecksum != candidateChecksum(candidate) {
		return fmt.Errorf("candidate identity or checksum mismatch")
	}
	return nil
}

func ValidateRegistry(registry Registry, catalog catalogregistry.Registry) error {
	if registry.SchemaVersion != RegistrySchemaVersion || registry.EngineVersion != EngineVersion || registry.RegistryID != registryID(registry.Namespace) {
		return fmt.Errorf("%w: registry identity mismatch", ErrInvalidRegistry)
	}
	seenCandidates := map[string]struct{}{}
	for _, candidate := range registry.Candidates {
		if _, ok := seenCandidates[candidate.CandidateID]; ok {
			return fmt.Errorf("%w: duplicate candidate", ErrInvalidRegistry)
		}
		if err := ValidateCandidate(candidate, catalog); err != nil {
			return err
		}
		seenCandidates[candidate.CandidateID] = struct{}{}
	}
	previousHash := ""
	type auditEvent struct {
		sequence uint64
		previous string
		hash     string
		kind     string
	}
	events := make([]auditEvent, 0, len(registry.Decisions)+len(registry.Executions))
	for _, decision := range registry.Decisions {
		if decision.RegistryID != registry.RegistryID {
			return fmt.Errorf("%w: decision registry mismatch", ErrInvalidRegistry)
		}
		if _, ok := seenCandidates[decision.CandidateID]; !ok {
			return fmt.Errorf("%w: decision references unknown candidate", ErrInvalidRegistry)
		}
		if decision.Action != DecisionApprove && decision.Action != DecisionReject {
			return fmt.Errorf("%w: invalid decision action", ErrInvalidRegistry)
		}
		if decision.DecisionID != decisionID(decision) || decision.EventHash != decisionEventHash(decision) || decision.DecisionChecksum != decisionChecksum(decision) {
			return fmt.Errorf("%w: decision checksum mismatch", ErrInvalidRegistry)
		}
		events = append(events, auditEvent{decision.Sequence, decision.PreviousEventHash, decision.EventHash, "decision"})
	}
	for _, execution := range registry.Executions {
		if execution.RegistryID != registry.RegistryID {
			return fmt.Errorf("%w: execution registry mismatch", ErrInvalidRegistry)
		}
		if execution.Action != ExecutionPromote && execution.Action != ExecutionRollback {
			return fmt.Errorf("%w: invalid execution action", ErrInvalidRegistry)
		}
		if execution.Action == ExecutionPromote {
			if _, ok := seenCandidates[execution.CandidateID]; !ok {
				return fmt.Errorf("%w: promotion references unknown candidate", ErrInvalidRegistry)
			}
		}
		if execution.ExecutionID != executionID(execution) || execution.EventHash != executionEventHash(execution) || execution.ExecutionChecksum != executionChecksum(execution) {
			return fmt.Errorf("%w: execution checksum mismatch", ErrInvalidRegistry)
		}
		events = append(events, auditEvent{execution.Sequence, execution.PreviousEventHash, execution.EventHash, "execution"})
	}
	sort.Slice(events, func(i, j int) bool { return events[i].sequence < events[j].sequence })
	expectedSequence := uint64(0)
	for _, event := range events {
		expectedSequence++
		if event.sequence != expectedSequence || event.previous != previousHash {
			return fmt.Errorf("%w: %s audit chain discontinuity", ErrInvalidRegistry, event.kind)
		}
		previousHash = event.hash
	}
	if registry.LastSequence != expectedSequence || registry.AuditHead != previousHash {
		return fmt.Errorf("%w: registry sequence or audit head mismatch", ErrInvalidRegistry)
	}
	if !sort.SliceIsSorted(registry.Candidates, func(i, j int) bool { return registry.Candidates[i].CandidateID < registry.Candidates[j].CandidateID }) {
		return fmt.Errorf("%w: candidates must be sorted", ErrInvalidRegistry)
	}
	if !isSHA256(registry.RegistryChecksum) || registry.RegistryChecksum != registryChecksum(registry) {
		return fmt.Errorf("%w: registry checksum mismatch", ErrInvalidRegistry)
	}
	return nil
}

func decisionEventHash(decision PromotionDecision) string {
	copy := decision
	copy.EventHash = ""
	copy.DecisionChecksum = ""
	return eventHash(copy)
}
func decisionChecksum(decision PromotionDecision) string {
	copy := decision
	copy.DecisionChecksum = ""
	return digest(copy)
}
func executionEventHash(execution PromotionExecution) string {
	copy := execution
	copy.EventHash = ""
	copy.ExecutionChecksum = ""
	return eventHash(copy)
}
func executionChecksum(execution PromotionExecution) string {
	copy := execution
	copy.ExecutionChecksum = ""
	return digest(copy)
}

func isSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
func findComponent(registry catalogregistry.Registry, id string) (catalogregistry.Component, bool) {
	for _, v := range registry.Components {
		if v.ComponentID == id {
			return v, true
		}
	}
	return catalogregistry.Component{}, false
}
func findVersion(registry catalogregistry.Registry, id string) (catalogregistry.CatalogVersion, bool) {
	for _, v := range registry.Versions {
		if v.VersionID == id {
			return v, true
		}
	}
	return catalogregistry.CatalogVersion{}, false
}
func findActive(registry catalogregistry.Registry, componentID string) (catalogregistry.ActivePointer, bool) {
	for _, v := range registry.Active {
		if v.ComponentID == componentID {
			return v, true
		}
	}
	return catalogregistry.ActivePointer{}, false
}
