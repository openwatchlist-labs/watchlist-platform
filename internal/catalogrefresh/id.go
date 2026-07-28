package catalogrefresh

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func stableID(prefix string, value any) string {
	b, _ := json.Marshal(value)
	sum := sha256.Sum256(b)
	return prefix + "_" + hex.EncodeToString(sum[:12])
}

func sha256JSON(value any) (string, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
