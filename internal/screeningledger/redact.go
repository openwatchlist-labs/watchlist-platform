package screeningledger

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

func RedactJSON(raw []byte, policy RetentionPolicy, key []byte) ([]byte, error) {
	var value any
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	if err := d.Decode(&value); err != nil {
		return nil, err
	}
	value = redactValue(value, lowerSet(policy.RedactKeys), lowerSet(policy.HashKeys), key)
	return json.Marshal(value)
}
func redactValue(value any, redact, hash map[string]struct{}, secret []byte) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for field, child := range typed {
			lower := strings.ToLower(field)
			if _, ok := redact[lower]; ok {
				out[field] = "[REDACTED]"
				continue
			}
			if _, ok := hash[lower]; ok {
				out[field] = "hmac-sha256:" + hmacHex(secret, child)
				continue
			}
			out[field] = redactValue(child, redact, hash, secret)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i := range typed {
			out[i] = redactValue(typed[i], redact, hash, secret)
		}
		return out
	default:
		return value
	}
}
func lowerSet(values []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, v := range values {
		out[strings.ToLower(strings.TrimSpace(v))] = struct{}{}
	}
	return out
}
func hmacHex(key []byte, value any) string {
	raw, _ := json.Marshal(value)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil))
}
