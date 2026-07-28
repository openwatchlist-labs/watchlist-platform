package revieworchestrator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func digest(value any) string {
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hashID(prefix string, value any) string { return prefix + digest(value)[:24] }

func correlationID(resultBatchID, caseID string) string {
	return hashID("review_corr_", struct{ ResultBatchID, CaseID string }{resultBatchID, caseID})
}

func stableCaseBundleID(bundle CaseBundle) string {
	copy := bundle
	copy.CaseBundleID = ""
	return hashID("review_case_", copy)
}

func stableRunID(bundle RunBundle) string {
	copy := bundle
	copy.RunID = ""
	copy.AuditEvents = nil
	copy.AuditHead = ""
	return hashID("review_run_", copy)
}
