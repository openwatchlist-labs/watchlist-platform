package screeningapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrIdempotencyConflict = errors.New("idempotency key was reused with a different request")
	ErrIdempotencyBusy     = errors.New("idempotency key is currently being processed")
)

type IdempotencyStore struct {
	Root string
}

type IdempotencyLease struct {
	store    IdempotencyStore
	lockPath string
	released bool
}

func (store IdempotencyStore) Begin(endpoint, key, requestSHA string) (*idempotencyRecord, *IdempotencyLease, error) {
	if strings.TrimSpace(store.Root) == "" {
		return nil, nil, fmt.Errorf("idempotency root is required")
	}
	path := store.recordPath(endpoint, key)
	if record, err := store.read(path); err == nil {
		if record.RequestSHA256 != requestSHA {
			return nil, nil, ErrIdempotencyConflict
		}
		return &record, nil, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, nil, err
	}
	lockPath := path + ".lock"
	if err := os.Mkdir(lockPath, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			if record, readErr := store.read(path); readErr == nil {
				if record.RequestSHA256 != requestSHA {
					return nil, nil, ErrIdempotencyConflict
				}
				return &record, nil, nil
			}
			return nil, nil, ErrIdempotencyBusy
		}
		return nil, nil, err
	}
	return nil, &IdempotencyLease{store: store, lockPath: lockPath}, nil
}

func (lease *IdempotencyLease) Commit(record idempotencyRecord) error {
	if lease == nil || lease.released {
		return fmt.Errorf("idempotency lease is not active")
	}
	path := lease.store.recordPath(record.Endpoint, record.Key)
	data, err := jsonBytes(record)
	if err != nil {
		lease.Release()
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".screening-idempotency-*.tmp")
	if err != nil {
		lease.Release()
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		lease.Release()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		lease.Release()
		return err
	}
	if err := file.Close(); err != nil {
		lease.Release()
		return err
	}
	if err := os.Rename(name, path); err != nil {
		lease.Release()
		return err
	}
	lease.Release()
	return nil
}

func (lease *IdempotencyLease) Release() {
	if lease == nil || lease.released {
		return
	}
	lease.released = true
	_ = os.Remove(lease.lockPath)
}

func (store IdempotencyStore) recordPath(endpoint, key string) string {
	return filepath.Join(store.Root, digest(struct {
		Endpoint string `json:"endpoint"`
		Key      string `json:"key"`
	}{Endpoint: endpoint, Key: key})+".json")
}

func (store IdempotencyStore) read(path string) (idempotencyRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return idempotencyRecord{}, err
	}
	var record idempotencyRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return idempotencyRecord{}, err
	}
	if record.SchemaVersion != IdempotencySchemaVersion || record.Endpoint == "" || record.Key == "" || len(record.RequestSHA256) != 64 || len(record.Response) == 0 || record.CreatedAt.IsZero() {
		return idempotencyRecord{}, fmt.Errorf("invalid idempotency record")
	}
	return record, nil
}

func jsonBytes(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func newIdempotencyRecord(endpoint, key, requestSHA, correlationID string, status int, response []byte, createdAt time.Time) idempotencyRecord {
	return idempotencyRecord{SchemaVersion: IdempotencySchemaVersion, Endpoint: endpoint, Key: key, RequestSHA256: requestSHA, StatusCode: status, CorrelationID: correlationID, Response: append([]byte(nil), response...), CreatedAt: createdAt.UTC()}
}
