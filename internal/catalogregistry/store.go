package catalogregistry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Store struct {
	Root string
}

func (s Store) Initialize(namespace string) (Registry, error) {
	var result Registry
	err := s.withLock(func() error {
		registry, err := s.loadUnlocked()
		if err == nil {
			if registry.Namespace != strings.TrimSpace(namespace) {
				return fmt.Errorf("registry namespace is %q, not %q", registry.Namespace, namespace)
			}
			result = registry
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		registry, err = NewRegistry(namespace)
		if err != nil {
			return err
		}
		if err := s.writeRegistryUnlocked(registry); err != nil {
			return err
		}
		result = registry
		return nil
	})
	return result, err
}

func (s Store) RegisterComponent(component Component) (Registry, error) {
	var result Registry
	err := s.withLock(func() error {
		registry, err := s.loadUnlocked()
		if err != nil {
			return err
		}
		if err := ValidateComponent(component); err != nil {
			return err
		}
		if component.Namespace != registry.Namespace {
			return fmt.Errorf("component namespace %q does not match registry %q", component.Namespace, registry.Namespace)
		}
		for _, existing := range registry.Components {
			if existing.ComponentID == component.ComponentID {
				if existing.ComponentChecksum != component.ComponentChecksum {
					return fmt.Errorf("immutable component collision for %s", component.ComponentID)
				}
				result = registry
				return nil
			}
			if existing.ComponentKey == component.ComponentKey {
				return fmt.Errorf("component_key %q is already registered", component.ComponentKey)
			}
		}
		if err := s.writeImmutable(filepath.Join("components", component.ComponentID+".json"), component); err != nil {
			return err
		}
		registry.Components = append(registry.Components, component)
		sort.Slice(registry.Components, func(i, j int) bool { return registry.Components[i].ComponentID < registry.Components[j].ComponentID })
		registry.RegistryChecksum = registryChecksum(registry)
		if err := ValidateRegistry(registry); err != nil {
			return err
		}
		if err := s.writeRegistryUnlocked(registry); err != nil {
			return err
		}
		result = registry
		return nil
	})
	return result, err
}

func (s Store) RegisterVersion(version CatalogVersion) (Registry, error) {
	var result Registry
	err := s.withLock(func() error {
		registry, err := s.loadUnlocked()
		if err != nil {
			return err
		}
		component, ok := findComponent(registry, version.ComponentID)
		if !ok {
			return fmt.Errorf("unknown component %s", version.ComponentID)
		}
		if err := ValidateVersion(version, component); err != nil {
			return err
		}
		for _, existing := range registry.Versions {
			if existing.VersionID == version.VersionID {
				if existing.VersionChecksum != version.VersionChecksum {
					return fmt.Errorf("immutable version collision for %s", version.VersionID)
				}
				result = registry
				return nil
			}
		}
		if err := s.writeImmutable(filepath.Join("versions", version.VersionID+".json"), version); err != nil {
			return err
		}
		registry.Versions = append(registry.Versions, version)
		sort.Slice(registry.Versions, func(i, j int) bool { return registry.Versions[i].VersionID < registry.Versions[j].VersionID })
		registry.RegistryChecksum = registryChecksum(registry)
		if err := ValidateRegistry(registry); err != nil {
			return err
		}
		if err := s.writeRegistryUnlocked(registry); err != nil {
			return err
		}
		result = registry
		return nil
	})
	return result, err
}

func (s Store) Activate(request ActivationRequest) (ActivationRecord, Registry, error) {
	var record ActivationRecord
	var result Registry
	err := s.withLock(func() error {
		registry, err := s.loadUnlocked()
		if err != nil {
			return err
		}
		component, ok := findComponent(registry, strings.TrimSpace(request.ComponentID))
		if !ok {
			return fmt.Errorf("unknown component %s", request.ComponentID)
		}
		if component.Status != ComponentStatusActive {
			return fmt.Errorf("component %s is not active", component.ComponentID)
		}
		version, ok := findVersion(registry, strings.TrimSpace(request.TargetVersionID))
		if !ok || version.ComponentID != component.ComponentID {
			return fmt.Errorf("target version does not belong to component")
		}
		action := request.Action
		if action == "" {
			action = ActivationActionActivate
		}
		current, hasCurrent := findActive(registry, component.ComponentID)
		if request.ExpectedCurrentVersionID != "" {
			if !hasCurrent || current.VersionID != strings.TrimSpace(request.ExpectedCurrentVersionID) {
				return fmt.Errorf("active version precondition failed")
			}
		}
		if hasCurrent && current.VersionID == version.VersionID {
			return fmt.Errorf("version %s is already active", version.VersionID)
		}
		if action == ActivationActionRollback && !wasActivated(registry, component.ComponentID, version.VersionID) {
			return fmt.Errorf("rollback target %s was never active", version.VersionID)
		}
		if action != ActivationActionActivate && action != ActivationActionRollback {
			return fmt.Errorf("unsupported activation action %q", action)
		}
		if strings.TrimSpace(request.Reason) == "" || strings.TrimSpace(request.ActivatedBy) == "" || request.ActivatedAt.IsZero() {
			return fmt.Errorf("reason, activated_by, and activated_at are required")
		}
		epoch := uint64(1)
		previousVersionID := ""
		if hasCurrent {
			epoch = current.Epoch + 1
			previousVersionID = current.VersionID
		}
		record = ActivationRecord{
			SchemaVersion:     ActivationSchemaVersion,
			RegistryID:        registry.RegistryID,
			Sequence:          registry.LastSequence + 1,
			ComponentID:       component.ComponentID,
			Action:            action,
			TargetVersionID:   version.VersionID,
			PreviousVersionID: previousVersionID,
			ComponentEpoch:    epoch,
			Reason:            strings.TrimSpace(request.Reason),
			ActivatedAt:       request.ActivatedAt.UTC(),
			ActivatedBy:       strings.TrimSpace(request.ActivatedBy),
			PreviousEventHash: registry.AuditHead,
		}
		record.ActivationID = activationID(record)
		record.EventHash = activationEventHash(record)
		if err := ValidateActivation(record, registry); err != nil {
			return err
		}
		if err := s.writeImmutable(filepath.Join("activations", fmt.Sprintf("%020d-%s.json", record.Sequence, record.ActivationID)), record); err != nil {
			return err
		}
		pointer := ActivePointer{
			SchemaVersion: PointerSchemaVersion,
			ComponentID:   component.ComponentID,
			VersionID:     version.VersionID,
			ActivationID:  record.ActivationID,
			Epoch:         epoch,
			ActivatedAt:   record.ActivatedAt,
			ActivatedBy:   record.ActivatedBy,
		}
		if err := s.writeAtomic(filepath.Join("active", component.ComponentID+".json"), pointer); err != nil {
			return err
		}
		registry.Activations = append(registry.Activations, record)
		registry.LastSequence = record.Sequence
		registry.AuditHead = record.EventHash
		setActive(&registry, pointer)
		registry.RegistryChecksum = registryChecksum(registry)
		if err := ValidateRegistry(registry); err != nil {
			return err
		}
		if err := s.writeRegistryUnlocked(registry); err != nil {
			return err
		}
		result = registry
		return nil
	})
	return record, result, err
}

func (s Store) Load() (Registry, error) {
	registry, err := s.loadUnlocked()
	if err != nil {
		return Registry{}, err
	}
	if err := s.Verify(registry); err != nil {
		return Registry{}, err
	}
	return registry, nil
}

func (s Store) Verify(registry Registry) error {
	if err := ValidateRegistry(registry); err != nil {
		return err
	}
	for _, component := range registry.Components {
		var stored Component
		if err := s.read(filepath.Join("components", component.ComponentID+".json"), &stored); err != nil {
			return err
		}
		if stored.ComponentChecksum != component.ComponentChecksum {
			return fmt.Errorf("component file mismatch for %s", component.ComponentID)
		}
	}
	for _, version := range registry.Versions {
		var stored CatalogVersion
		if err := s.read(filepath.Join("versions", version.VersionID+".json"), &stored); err != nil {
			return err
		}
		if stored.VersionChecksum != version.VersionChecksum {
			return fmt.Errorf("version file mismatch for %s", version.VersionID)
		}
	}
	for _, activation := range registry.Activations {
		var stored ActivationRecord
		path := filepath.Join("activations", fmt.Sprintf("%020d-%s.json", activation.Sequence, activation.ActivationID))
		if err := s.read(path, &stored); err != nil {
			return err
		}
		if stored.EventHash != activation.EventHash {
			return fmt.Errorf("activation file mismatch for %s", activation.ActivationID)
		}
	}
	for _, pointer := range registry.Active {
		var stored ActivePointer
		if err := s.read(filepath.Join("active", pointer.ComponentID+".json"), &stored); err != nil {
			return err
		}
		if stored != pointer {
			return fmt.Errorf("active pointer mismatch for %s", pointer.ComponentID)
		}
	}
	return nil
}

func (s Store) loadUnlocked() (Registry, error) {
	var registry Registry
	if err := s.read("registry.json", &registry); err != nil {
		return Registry{}, err
	}
	return registry, nil
}

func (s Store) writeRegistryUnlocked(registry Registry) error {
	return s.writeAtomic("registry.json", registry)
}

func (s Store) writeImmutable(relative string, value any) error {
	path := filepath.Join(s.Root, relative)
	data, err := jsonBytes(value)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
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
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func (s Store) writeAtomic(relative string, value any) error {
	path := filepath.Join(s.Root, relative)
	data, err := jsonBytes(value)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".catalog-registry-*.tmp")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func (s Store) read(relative string, target any) error {
	file, err := os.Open(filepath.Join(s.Root, relative))
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing JSON value in %s", relative)
	}
	return nil
}

func (s Store) withLock(fn func() error) error {
	if strings.TrimSpace(s.Root) == "" {
		return fmt.Errorf("registry store root is required")
	}
	if err := os.MkdirAll(s.Root, 0o755); err != nil {
		return err
	}
	lockPath := filepath.Join(s.Root, ".lock")
	if err := os.Mkdir(lockPath, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("catalog registry is locked at %s", lockPath)
		}
		return err
	}
	defer os.Remove(lockPath)
	return fn()
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

func findComponent(registry Registry, id string) (Component, bool) {
	for _, component := range registry.Components {
		if component.ComponentID == id {
			return component, true
		}
	}
	return Component{}, false
}

func findVersion(registry Registry, id string) (CatalogVersion, bool) {
	for _, version := range registry.Versions {
		if version.VersionID == id {
			return version, true
		}
	}
	return CatalogVersion{}, false
}

func findActive(registry Registry, componentID string) (ActivePointer, bool) {
	for _, pointer := range registry.Active {
		if pointer.ComponentID == componentID {
			return pointer, true
		}
	}
	return ActivePointer{}, false
}

func setActive(registry *Registry, pointer ActivePointer) {
	for index := range registry.Active {
		if registry.Active[index].ComponentID == pointer.ComponentID {
			registry.Active[index] = pointer
			sort.Slice(registry.Active, func(i, j int) bool { return registry.Active[i].ComponentID < registry.Active[j].ComponentID })
			return
		}
	}
	registry.Active = append(registry.Active, pointer)
	sort.Slice(registry.Active, func(i, j int) bool { return registry.Active[i].ComponentID < registry.Active[j].ComponentID })
}

func wasActivated(registry Registry, componentID, versionID string) bool {
	for _, activation := range registry.Activations {
		if activation.ComponentID == componentID && activation.TargetVersionID == versionID {
			return true
		}
	}
	return false
}
