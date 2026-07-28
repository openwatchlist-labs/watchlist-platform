package screeningapiv8d

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
	RequestSHA256 string          `json:"request_sha256"`
	StatusCode    int             `json:"status_code"`
	Body          json.RawMessage `json:"body"`
}

type IdempotencyStore struct {
	directory string
	mu        sync.Mutex
}

func NewIdempotencyStore(directory string) *IdempotencyStore {
	return &IdempotencyStore{directory: directory}
}

func (s *IdempotencyStore) Execute(scope, key string, request []byte, fn func() (int, []byte, error)) (int, []byte, bool, error) {
	if key == "" {
		status, body, err := fn()
		return status, body, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.directory, 0o750); err != nil {
		return 0, nil, false, fmt.Errorf("create idempotency directory: %w", err)
	}
	requestDigest := digestHex(request)
	path := filepath.Join(s.directory, digestHex([]byte(scope+"\n"+key))+".json")
	if raw, err := os.ReadFile(path); err == nil {
		var stored storedResponse
		if err := json.Unmarshal(raw, &stored); err != nil {
			return 0, nil, false, fmt.Errorf("decode idempotency state: %w", err)
		}
		if stored.RequestSHA256 != requestDigest {
			return 0, nil, false, ErrIdempotencyConflict
		}
		return stored.StatusCode, append([]byte(nil), stored.Body...), true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, nil, false, fmt.Errorf("read idempotency state: %w", err)
	}
	status, body, err := fn()
	if err != nil {
		return 0, nil, false, err
	}
	encoded, err := json.Marshal(storedResponse{RequestSHA256: requestDigest, StatusCode: status, Body: json.RawMessage(append([]byte(nil), body...))})
	if err != nil {
		return 0, nil, false, fmt.Errorf("encode idempotency state: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, encoded, 0o640); err != nil {
		return 0, nil, false, fmt.Errorf("write idempotency state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return 0, nil, false, fmt.Errorf("commit idempotency state: %w", err)
	}
	return status, body, false, nil
}

func digestHex(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
