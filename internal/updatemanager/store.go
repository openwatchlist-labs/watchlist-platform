package updatemanager

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Store struct{ Root string }

func (s Store) PersistUpdate(record UpdateRecord) error {
	return s.writeExclusive(filepath.Join("updates", record.UpdateID+".json"), record)
}
func (s Store) PersistReadiness(updateID string, ack WorkerReadinessAck) error {
	return s.writeExclusive(filepath.Join("worker-readiness", updateID, ack.Worker.WorkerID+"-"+ack.AckID+".json"), ack)
}
func (s Store) PersistActivation(record FleetActivationRecord) error {
	return s.writeExclusive(filepath.Join("fleet-activations", record.ActivationID+".json"), record)
}
func (s Store) PersistRollback(record FleetRollbackRecord) error {
	return s.writeExclusive(filepath.Join("fleet-rollbacks", record.RollbackID+".json"), record)
}
func (s Store) PersistAudit(event AuditEvent) error {
	return s.writeExclusive(filepath.Join("audit", fmt.Sprintf("%020d-%s.json", event.Sequence, event.EventID)), event)
}
func (s Store) SetActive(pointer FleetPointer) error { return s.writeAtomic("active.json", pointer) }
func (s Store) Active() (*FleetPointer, error) {
	var p FleetPointer
	err := s.read("active.json", &p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}
func (s Store) writeExclusive(relative string, value any) error {
	path := filepath.Join(s.Root, relative)
	data, err := jsonBytes(value)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if old, readErr := os.ReadFile(path); readErr == nil {
		if !bytes.Equal(old, data) {
			return fmt.Errorf("immutable state collision at %s", path)
		}
		return nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
func (s Store) writeAtomic(relative string, value any) error {
	path := filepath.Join(s.Root, relative)
	data, err := jsonBytes(value)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".fleet-*.tmp")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
func (s Store) read(relative string, target any) error {
	f, err := os.Open(filepath.Join(s.Root, relative))
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err = dec.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err = dec.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}
func jsonBytes(value any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	err := enc.Encode(value)
	return b.Bytes(), err
}

func persistImmutablePackage(root, packageID, packageChecksum string, data []byte) (string, error) {
	if packageID == "" || packageChecksum == "" || len(data) == 0 {
		return "", fmt.Errorf("package identity and data are required")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != packageChecksum {
		return "", fmt.Errorf("package checksum mismatch")
	}
	path := filepath.Join(root, "packages", packageID+".owpcat")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if existing, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(existing, data) {
			return "", fmt.Errorf("immutable package collision at %s", path)
		}
		return path, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	return path, nil
}
