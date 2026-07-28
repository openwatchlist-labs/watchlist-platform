package policyengine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

func digestID(prefix string, values ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, "\x1f")))
	return prefix + hex.EncodeToString(sum[:12])
}

func stableDecisionID(decision Decision) string {
	copy := decision
	copy.DecisionID = ""
	data, _ := json.Marshal(copy)
	return digestID("policy_decision_", DecisionSchemaVersion, string(data))
}

func stableBatchID(batch DecisionBatch) string {
	parts := []string{DecisionBatchSchema, batch.InputClassificationBatchID, batch.EngineVersion, batch.Policy.PolicyChecksum}
	if batch.Overlay != nil {
		parts = append(parts, batch.Overlay.OverlayChecksum)
	}
	for _, decision := range batch.Decisions {
		parts = append(parts, decision.DecisionID)
	}
	return digestID("policy_decision_batch_", parts...)
}
