package productionops

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func canonicalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func objectHash(v any) (string, error) {
	b, err := canonicalJSON(v)
	if err != nil {
		return "", err
	}
	return sha256Hex(b), nil
}
