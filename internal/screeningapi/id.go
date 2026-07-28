package screeningapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

func digest(value any) string {
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func stableID(prefix string, value any) string { return prefix + digest(value)[:24] }

func screeningID(response ScreeningResponse) string {
	copy := response
	copy.ScreeningID = ""
	copy.CorrelationID = ""
	copy.IdempotencyKey = ""
	copy.ProcessedAt = copy.Request.EffectiveAt.UTC()
	return stableID("screening_", copy)
}

func batchID(response BatchResponse) string {
	copy := response
	copy.BatchID = ""
	copy.CorrelationID = ""
	copy.IdempotencyKey = ""
	copy.ProcessedAt = time.Time{}
	for index := range copy.Results {
		copy.Results[index].CorrelationID = ""
		copy.Results[index].IdempotencyKey = ""
		copy.Results[index].ProcessedAt = copy.Results[index].Request.EffectiveAt.UTC()
	}
	return stableID("screening_batch_", copy)
}
