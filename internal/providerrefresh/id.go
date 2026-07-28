package providerrefresh

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

func digest(value any) string {
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func stableID(prefix string, value any) string { return prefix + digest(value)[:24] }

func registryID(namespace string) string {
	return stableID("provider_refresh_registry_", struct {
		Namespace string `json:"namespace"`
	}{strings.TrimSpace(namespace)})
}

func inventoryChecksum(inventory ProviderInventory) string {
	copy := inventory
	copy.InventoryChecksum = ""
	return digest(copy)
}

func candidateID(candidate RefreshCandidate) string {
	copy := candidate
	copy.CandidateID = ""
	copy.CandidateChecksum = ""
	return stableID("provider_refresh_candidate_", copy)
}

func candidateChecksum(candidate RefreshCandidate) string {
	copy := candidate
	copy.CandidateChecksum = ""
	return digest(copy)
}

func decisionID(decision PromotionDecision) string {
	copy := decision
	copy.DecisionID = ""
	copy.EventHash = ""
	copy.DecisionChecksum = ""
	return stableID("provider_refresh_decision_", copy)
}

func executionID(execution PromotionExecution) string {
	copy := execution
	copy.ExecutionID = ""
	copy.EventHash = ""
	copy.ExecutionChecksum = ""
	return stableID("provider_refresh_execution_", copy)
}

func eventHash(value any) string { return digest(value) }

func registryChecksum(registry Registry) string {
	copy := registry
	copy.RegistryChecksum = ""
	return digest(copy)
}
