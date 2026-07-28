package vendoradapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func SHA256Bytes(b []byte) string  { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func SHA256String(s string) string { return SHA256Bytes([]byte(s)) }

func canonicalJSON(v any) ([]byte, error) { return json.Marshal(v) }

func profileHash(p Profile) (string, error) {
	p.ProfileSHA256 = ""
	b, err := canonicalJSON(p)
	if err != nil {
		return "", err
	}
	return SHA256Bytes(b), nil
}

func envelopeHash(e Envelope) (string, error) {
	e.EnvelopeSHA256 = ""
	b, err := canonicalJSON(e)
	if err != nil {
		return "", err
	}
	return SHA256Bytes(b), nil
}

func batchHash(b Batch) (string, error) {
	b.BatchSHA256 = ""
	raw, err := canonicalJSON(b)
	if err != nil {
		return "", err
	}
	return SHA256Bytes(raw), nil
}

func auditHash(a AuditEvent) (string, error) {
	a.AuditSHA256 = ""
	raw, err := canonicalJSON(a)
	if err != nil {
		return "", err
	}
	return SHA256Bytes(raw), nil
}
