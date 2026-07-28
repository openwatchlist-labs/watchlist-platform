package reviewauth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

func CanonicalJSON(v any) ([]byte, error) { return json.Marshal(v) }
func SHA256Bytes(b []byte) string         { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func HashObject(v any) (string, error) {
	b, e := CanonicalJSON(v)
	if e != nil {
		return "", e
	}
	return SHA256Bytes(b), nil
}
func HashString(v string) string { return SHA256Bytes([]byte(v)) }
func NormalizeTime(v string) (string, error) {
	t, e := time.Parse(time.RFC3339Nano, v)
	if e != nil {
		return "", e
	}
	return t.UTC().Format(time.RFC3339Nano), nil
}
