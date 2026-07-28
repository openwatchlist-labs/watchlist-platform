package falsepositive

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

func stableObservationID(observation Observation) string {
	copy := observation
	copy.ObservationID = ""
	data, _ := json.Marshal(copy)
	return digestID("fp_observation_", ObservationSchemaVersion, string(data))
}

func stableObservationBatchID(batch ObservationBatch) string {
	parts := []string{ObservationBatchSchema, batch.SourceReference}
	for _, observation := range batch.Observations {
		parts = append(parts, observation.ObservationID)
	}
	return digestID("fp_observation_batch_", parts...)
}

func stableClassificationID(classification Classification) string {
	copy := classification
	copy.ClassificationID = ""
	data, _ := json.Marshal(copy)
	return digestID("fp_classification_", ClassificationSchemaVersion, string(data))
}

func stableClassificationBatchID(batch ClassificationBatch) string {
	parts := []string{ClassificationBatchSchema, batch.InputObservationBatchID, batch.ClassifierVersion, batch.PatternLibrary.LibraryChecksum, batch.CountervailingPolicy.PolicyChecksum}
	for _, classification := range batch.Classifications {
		parts = append(parts, classification.ClassificationID)
	}
	return digestID("fp_classification_batch_", parts...)
}
