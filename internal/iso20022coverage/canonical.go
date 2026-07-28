package iso20022coverage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

func MarshalCanonical(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func shortHash(parts ...string) string {
	s := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(s[:12])
}

func hashStruct[T any](value T, clear func(*T)) string {
	copyValue := value
	clear(&copyValue)
	b, _ := json.Marshal(copyValue)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
