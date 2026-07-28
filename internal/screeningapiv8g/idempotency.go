package screeningapiv8g

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var ErrIdempotencyConflict = errors.New("idempotency key was reused with different request bytes")

type storedResponse struct {
	RequestSHA256     string          `json:"request_sha256"`
	StatusCode        int             `json:"status_code"`
	Body              json.RawMessage `json:"body"`
	EventID           string          `json:"event_id"`
	EventSHA256       string          `json:"event_sha256"`
	PostgresPersisted bool            `json:"postgres_persisted"`
}
type idempotencyStore struct {
	directory string
	mu        sync.Mutex
}

func newIdempotencyStore(directory string) *idempotencyStore {
	return &idempotencyStore{directory: directory}
}
func (s *idempotencyStore) execute(scope, key string, request []byte, fn func() (storedResponse, error)) (storedResponse, bool, error) {
	if key == "" {
		value, err := fn()
		return value, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.directory, 0o750); err != nil {
		return storedResponse{}, false, err
	}
	requestDigest := digestHex(request)
	path := filepath.Join(s.directory, digestHex([]byte(scope+"\n"+key))+".json")
	if raw, err := os.ReadFile(path); err == nil {
		var stored storedResponse
		if err := json.Unmarshal(raw, &stored); err != nil {
			return storedResponse{}, false, err
		}
		if stored.RequestSHA256 != requestDigest {
			return storedResponse{}, false, ErrIdempotencyConflict
		}
		return stored, true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return storedResponse{}, false, err
	}
	stored, err := fn()
	if err != nil {
		return storedResponse{}, false, err
	}
	stored.RequestSHA256 = requestDigest
	raw, err := json.Marshal(stored)
	if err != nil {
		return storedResponse{}, false, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return storedResponse{}, false, fmt.Errorf("write idempotency state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return storedResponse{}, false, err
	}
	return stored, false, nil
}
func digestHex(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
