package screeningledger

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func LoadKey(file, envName string) ([]byte, error) {
	var raw string
	if strings.TrimSpace(file) != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read snapshot key: %w", err)
		}
		raw = strings.TrimSpace(string(data))
	} else if strings.TrimSpace(envName) != "" {
		raw = strings.TrimSpace(os.Getenv(envName))
	}
	if raw == "" {
		return nil, errors.New("snapshot encryption key is required")
	}
	if d, err := hex.DecodeString(raw); err == nil && len(d) == 32 {
		return d, nil
	}
	if d, err := base64.StdEncoding.DecodeString(raw); err == nil && len(d) == 32 {
		return d, nil
	}
	return nil, errors.New("snapshot encryption key must be 32 bytes encoded as hex or base64")
}
func encryptSnapshot(key []byte, kind string, plaintext []byte, createdAt, expiresAt, retentionClass string) (SnapshotEnvelope, error) {
	if len(key) != 32 {
		return SnapshotEnvelope{}, errors.New("AES-256 key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return SnapshotEnvelope{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return SnapshotEnvelope{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return SnapshotEnvelope{}, err
	}
	plainSHA := digestHex(plaintext)
	snapSHA := digestHex(append([]byte(kind+"\n"), plaintext...))
	aad := kind + ":" + snapSHA
	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(aad))
	return SnapshotEnvelope{SchemaVersion: SnapshotSchemaV1, SnapshotSHA256: snapSHA, PlaintextSHA256: plainSHA, Kind: kind, Cipher: "AES-256-GCM", NonceBase64: base64.StdEncoding.EncodeToString(nonce), CiphertextBase64: base64.StdEncoding.EncodeToString(ciphertext), AAD: aad, PlaintextBytes: len(plaintext), CreatedAt: createdAt, ExpiresAt: expiresAt, RetentionClass: retentionClass}, nil
}
func decryptSnapshot(key []byte, e SnapshotEnvelope) ([]byte, error) {
	if e.PurgedAt != "" || e.CiphertextBase64 == "" {
		return nil, errors.New("snapshot ciphertext has been purged")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(e.NonceBase64)
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(e.CiphertextBase64)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ct, []byte(e.AAD))
	if err != nil {
		return nil, err
	}
	if digestHex(plain) != e.PlaintextSHA256 {
		return nil, errors.New("snapshot plaintext checksum mismatch")
	}
	return plain, nil
}
func digestHex(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

// macHex is HMAC-SHA256(key, raw), hex-encoded. hash.Hash.Write never
// returns an error, so the discard matches the existing pattern at
// redact.go's hmacHex.
func macHex(key, raw []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil))
}
func canonicalJSON(raw []byte) ([]byte, error) {
	var value any
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	if err := d.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}
