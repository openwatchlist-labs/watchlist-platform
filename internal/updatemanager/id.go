package updatemanager

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

func stableID(prefix string, value any) string {
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return prefix + "_" + hex.EncodeToString(sum[:12])
}

func sha256JSON(value any) string {
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func normalizedIDs(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
