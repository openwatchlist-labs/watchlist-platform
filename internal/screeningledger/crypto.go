package screeningledger

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
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
	raw, err := readKeyMaterial(file, envName)
	if err != nil {
		return nil, err
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

// LoadEd25519PublicKey loads a 32-byte Ed25519 public key from file or
// envName, the same file-or-env-var idiom as LoadKey. This is the policy
// trust root (ADR-0007 D10/EA5) -- distinct from LoadKey, which loads the
// symmetric root secret R or, when pointed at anchor-key material, K_anchor.
func LoadEd25519PublicKey(file, envName string) (ed25519.PublicKey, error) {
	raw, err := readKeyMaterial(file, envName)
	if err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, errors.New("verification policy trust-root public key is required")
	}
	if d, err := hex.DecodeString(raw); err == nil && len(d) == ed25519.PublicKeySize {
		return ed25519.PublicKey(d), nil
	}
	if d, err := base64.StdEncoding.DecodeString(raw); err == nil && len(d) == ed25519.PublicKeySize {
		return ed25519.PublicKey(d), nil
	}
	return nil, fmt.Errorf("verification policy public key must be %d bytes encoded as hex or base64", ed25519.PublicKeySize)
}

// LoadEd25519PrivateKey loads a 64-byte Ed25519 private key (seed||public,
// the standard library's encoding) from file or envName. Used only by
// operator-run, out-of-band signing tooling (SignVerificationPolicy) --
// never by the appending or verifying process.
func LoadEd25519PrivateKey(file, envName string) (ed25519.PrivateKey, error) {
	raw, err := readKeyMaterial(file, envName)
	if err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, errors.New("verification policy signing key is required")
	}
	if d, err := hex.DecodeString(raw); err == nil && len(d) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(d), nil
	}
	if d, err := base64.StdEncoding.DecodeString(raw); err == nil && len(d) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(d), nil
	}
	return nil, fmt.Errorf("verification policy signing key must be %d bytes encoded as hex or base64", ed25519.PrivateKeySize)
}

func readKeyMaterial(file, envName string) (string, error) {
	if strings.TrimSpace(file) != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("read key material: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	if strings.TrimSpace(envName) != "" {
		return strings.TrimSpace(os.Getenv(envName)), nil
	}
	return "", nil
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
