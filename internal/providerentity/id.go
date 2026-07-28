package providerentity

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
