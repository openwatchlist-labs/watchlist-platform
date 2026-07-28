package catalogruntime

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
	"time"
)

var ErrStateLocked = errors.New("catalog runtime state is locked")

type StateStore struct {
	Root string
}

type RollbackEnvelope struct {
	Activation ActivationRecord `json:"activation"`
	Rollback   RollbackRecord   `json:"rollback"`
}

func (s StateStore) Active() (*ActivePointer, error) {
	path := filepath.Join(s.Root, "active.json")
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var pointer ActivePointer
	if err := decodeStrict(file, &pointer); err != nil {
		return nil, err
	}
	if pointer.SchemaVersion != ActivePointerSchemaVersion {
		return nil, fmt.Errorf("invalid active pointer schema")
	}
	if err := ValidateGenerationStamp(pointer.Generation); err != nil {
		return nil, err
	}
	return &pointer, nil
}

func (s StateStore) Activate(input PackageActivationInput, readiness ReadinessReport, at time.Time) (ActivationRecord, error) {
	if err := ValidateReadinessReport(readiness); err != nil {
		return ActivationRecord{}, err
	}
	if !readiness.Ready || !readinessMatches(input, readiness) {
		return ActivationRecord{}, fmt.Errorf("%w: readiness report is not ready for package", ErrInvalidActivation)
	}
	unlock, err := s.lock()
	if err != nil {
		return ActivationRecord{}, err
	}
	defer unlock()
	previous, err := s.activeUnlocked()
	if err != nil {
		return ActivationRecord{}, err
	}
	var previousStamp *GenerationStamp
	if previous != nil {
		previousStamp = &previous.Generation
	}
	record, _, err := BuildActivation(previousStamp, input, readiness.ReportID, ActivationActionActivate, "", at)
	if err != nil {
		return ActivationRecord{}, err
	}
	if err := s.persistActivation(record, nil); err != nil {
		return ActivationRecord{}, err
	}
	return record, nil
}

func (s StateStore) Rollback(input PackageActivationInput, readiness ReadinessReport, reason string, at time.Time) (RollbackEnvelope, error) {
	if err := ValidateReadinessReport(readiness); err != nil {
		return RollbackEnvelope{}, err
	}
	if !readiness.Ready || !readinessMatches(input, readiness) {
		return RollbackEnvelope{}, fmt.Errorf("%w: readiness report is not ready for package", ErrInvalidRollback)
	}
	unlock, err := s.lock()
	if err != nil {
		return RollbackEnvelope{}, err
	}
	defer unlock()
	previous, err := s.activeUnlocked()
	if err != nil {
		return RollbackEnvelope{}, err
	}
	if previous == nil {
		return RollbackEnvelope{}, fmt.Errorf("%w: no active generation", ErrInvalidRollback)
	}
	record, rollback, err := BuildActivation(&previous.Generation, input, readiness.ReportID, ActivationActionRollback, reason, at)
	if err != nil {
		return RollbackEnvelope{}, err
	}
	if err := s.persistActivation(record, rollback); err != nil {
		return RollbackEnvelope{}, err
	}
	return RollbackEnvelope{Activation: record, Rollback: *rollback}, nil
}

func (s StateStore) persistActivation(record ActivationRecord, rollback *RollbackRecord) error {
	if err := os.MkdirAll(filepath.Join(s.Root, "activations"), 0o755); err != nil {
		return err
	}
	if err := writeJSONExclusive(filepath.Join(s.Root, "activations", record.ActivationID+".json"), record); err != nil {
		return err
	}
	if rollback != nil {
		if err := os.MkdirAll(filepath.Join(s.Root, "rollbacks"), 0o755); err != nil {
			return err
		}
		if err := writeJSONExclusive(filepath.Join(s.Root, "rollbacks", rollback.RollbackID+".json"), rollback); err != nil {
			return err
		}
	}
	pointer := ActivePointer{SchemaVersion: ActivePointerSchemaVersion, Generation: record.Active}
	return writeJSONAtomic(filepath.Join(s.Root, "active.json"), pointer)
}

func (s StateStore) activeUnlocked() (*ActivePointer, error) {
	path := filepath.Join(s.Root, "active.json")
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var pointer ActivePointer
	if err := decodeStrict(file, &pointer); err != nil {
		return nil, err
	}
	if pointer.SchemaVersion != ActivePointerSchemaVersion {
		return nil, fmt.Errorf("invalid active pointer schema")
	}
	if err := ValidateGenerationStamp(pointer.Generation); err != nil {
		return nil, err
	}
	return &pointer, nil
}

func (s StateStore) lock() (func(), error) {
	if err := os.MkdirAll(s.Root, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(s.Root, ".activation.lock")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil, ErrStateLocked
	}
	if err != nil {
		return nil, err
	}
	_ = file.Close()
	return func() { _ = os.Remove(path) }, nil
}

func readinessMatches(input PackageActivationInput, report ReadinessReport) bool {
	return input.PackageID == report.PackageID && input.PackageChecksum == report.PackageChecksum && input.CatalogID == report.CatalogID && input.CatalogVersion == report.CatalogVersion && input.CatalogChecksum == report.CatalogChecksum && input.SourceManifestID == report.SourceManifestID
}

func writeJSONExclusive(path string, value any) error {
	data, err := marshalJSON(value)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func writeJSONAtomic(path string, value any) error {
	data, err := marshalJSON(value)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".active-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func marshalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func decodeStrict(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func (s StateStore) PersistPackage(packageID, packageChecksum, extension string, data []byte) (string, error) {
	if packageID == "" || extension == "" {
		return "", fmt.Errorf("package_id and extension are required")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != packageChecksum {
		return "", fmt.Errorf("package checksum mismatch")
	}
	dir := filepath.Join(s.Root, "packages")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, packageID+extension)
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

func (s StateStore) PersistReadiness(report ReadinessReport) (string, error) {
	if err := ValidateReadinessReport(report); err != nil {
		return "", err
	}
	dir := filepath.Join(s.Root, "readiness")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, report.ReportID+".json")
	data, err := marshalJSON(report)
	if err != nil {
		return "", err
	}
	if existing, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(existing, data) {
			return "", fmt.Errorf("immutable readiness collision at %s", path)
		}
		return path, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return path, writeJSONExclusive(path, report)
}
