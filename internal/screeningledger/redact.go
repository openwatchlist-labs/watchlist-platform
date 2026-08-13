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
	redacted, err := redactValue(value, lowerSet(policy.RedactKeys), lowerSet(policy.HashKeys), key)
	if err != nil {
		return nil, err
	}
	return json.Marshal(redacted)
}
func redactValue(value any, redact, hash map[string]struct{}, secret []byte) (any, error) {
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
				hashed, err := hmacHex(secret, child)
				if err != nil {
					return nil, err
				}
				out[field] = "hmac-sha256:" + hashed
				continue
			}
			redactedChild, err := redactValue(child, redact, hash, secret)
			if err != nil {
				return nil, err
			}
			out[field] = redactedChild
		}
		return out, nil
	case []any:
		out := make([]any, len(typed))
		for i := range typed {
			redactedItem, err := redactValue(typed[i], redact, hash, secret)
			if err != nil {
				return nil, err
			}
			out[i] = redactedItem
		}
		return out, nil
	default:
		return value, nil
	}
}
func lowerSet(values []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, v := range values {
		out[strings.ToLower(strings.TrimSpace(v))] = struct{}{}
	}
	return out
}
func hmacHex(key []byte, value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}
