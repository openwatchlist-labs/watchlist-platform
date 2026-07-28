package alertlistmapping

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
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogregistry"
)

type Store struct {
	Root string
}

func (s Store) Initialize(namespace string) (Registry, error) {
	namespace = strings.TrimSpace(namespace)
	var result Registry
	err := s.withLock(func() error {
		registry, err := s.loadUnlocked(catalogregistry.Registry{})
		if err == nil {
			if registry.Namespace != namespace {
				return fmt.Errorf("mapping registry namespace is %q, not %q", registry.Namespace, namespace)
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

func (s Store) Register(input MappingInput, catalog catalogregistry.Registry) (MappingVersion, Registry, error) {
	var registered MappingVersion
	var result Registry
	err := s.withLock(func() error {
		registry, err := s.loadUnlocked(catalog)
		if err != nil {
			return err
		}
		version, err := BuildVersion(registry, input, catalog)
		if err != nil {
			return err
		}
		for _, existing := range registry.Versions {
			if existing.MappingVersionID == version.MappingVersionID {
				if existing.VersionChecksum != version.VersionChecksum {
					return fmt.Errorf("immutable mapping version collision for %s", version.MappingVersionID)
				}
				registered = existing
				result = registry
				return nil
			}
		}
		keyIndex := -1
		for index, key := range registry.Keys {
			if key.MappingID == version.MappingID {
				keyIndex = index
				break
			}
		}
		if keyIndex < 0 {
			key, err := BuildKey(registry, input)
			if err != nil {
				return err
			}
			if err := s.writeImmutable(filepath.Join("mappings", key.MappingID+".json"), key); err != nil {
				return err
			}
			registry.Keys = append(registry.Keys, key)
			sort.Slice(registry.Keys, func(i, j int) bool { return registry.Keys[i].MappingID < registry.Keys[j].MappingID })
		}
		versionFile := fmt.Sprintf("%020d-%s.json", version.Sequence, version.MappingVersionID)
		if err := s.writeImmutable(filepath.Join("versions", versionFile), version); err != nil {
			return err
		}
		registry.Versions = append(registry.Versions, version)
		registry.LastSequence = version.Sequence
		registry.AuditHead = version.EventHash
		registry.RegistryChecksum = registryChecksum(registry)
		if err := ValidateRegistry(registry, catalog); err != nil {
			return err
		}
		if err := s.writeRegistryUnlocked(registry); err != nil {
			return err
		}
		registered = version
		result = registry
		return nil
	})
	return registered, result, err
}

func (s Store) Load(catalog catalogregistry.Registry) (Registry, error) {
	return s.loadUnlocked(catalog)
}

func (s Store) Verify(registry Registry, catalog catalogregistry.Registry) error {
	if err := ValidateRegistry(registry, catalog); err != nil {
		return err
	}
	for _, key := range registry.Keys {
		var stored MappingKey
		if err := s.read(filepath.Join("mappings", key.MappingID+".json"), &stored); err != nil {
			return err
		}
		if stored.KeyChecksum != key.KeyChecksum || digest(stored) != digest(key) {
			return fmt.Errorf("immutable mapping key mismatch for %s", key.MappingID)
		}
	}
	for _, version := range registry.Versions {
		var stored MappingVersion
		name := fmt.Sprintf("%020d-%s.json", version.Sequence, version.MappingVersionID)
		if err := s.read(filepath.Join("versions", name), &stored); err != nil {
			return err
		}
		if stored.VersionChecksum != version.VersionChecksum || digest(stored) != digest(version) {
			return fmt.Errorf("immutable mapping version mismatch for %s", version.MappingVersionID)
		}
	}
	return nil
}

func (s Store) loadUnlocked(catalog catalogregistry.Registry) (Registry, error) {
	var registry Registry
	if err := s.read("registry.json", &registry); err != nil {
		return Registry{}, err
	}
	if err := ValidateRegistry(registry, catalog); err != nil {
		return Registry{}, err
	}
	if err := s.Verify(registry, catalog); err != nil {
		return Registry{}, err
	}
	return registry, nil
}

func (s Store) writeRegistryUnlocked(registry Registry) error {
	return s.writeAtomic("registry.json", registry)
}

func (s Store) writeImmutable(relative string, value any) error {
	path := filepath.Join(s.Root, relative)
	if existing, err := os.ReadFile(path); err == nil {
		expected, err := marshal(value)
		if err != nil {
			return err
		}
		if !bytes.Equal(existing, expected) {
			return fmt.Errorf("immutable file collision at %s", relative)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return s.writeAtomic(relative, value)
}

func (s Store) writeAtomic(relative string, value any) error {
	data, err := marshal(value)
	if err != nil {
		return err
	}
	path := filepath.Join(s.Root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".alert-list-mapping-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
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
		if err == nil {
			return fmt.Errorf("trailing JSON value in %s", relative)
		}
		return err
	}
	return nil
}

func (s Store) withLock(fn func() error) error {
	if s.Root == "" {
		return fmt.Errorf("mapping store root is required")
	}
	if err := os.MkdirAll(s.Root, 0o755); err != nil {
		return err
	}
	lockPath := filepath.Join(s.Root, ".lock")
	deadline := time.Now().Add(10 * time.Second)
	for {
		file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			file.Close()
			defer os.Remove(lockPath)
			return fn()
		}
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for mapping store lock")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func marshal(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
