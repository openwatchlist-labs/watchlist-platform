package providerrefresh

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

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogregistry"
)

type Store struct{ Root string }

func (s Store) Initialize(namespace string, catalog catalogregistry.Registry) (Registry, error) {
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
		registry = Registry{SchemaVersion: RegistrySchemaVersion, RegistryID: registryID(namespace), Namespace: strings.TrimSpace(namespace), EngineVersion: EngineVersion, Candidates: []RefreshCandidate{}, Decisions: []PromotionDecision{}, Executions: []PromotionExecution{}}
		registry.RegistryChecksum = registryChecksum(registry)
		if err := ValidateRegistry(registry, catalog); err != nil {
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

func (s Store) AddCandidate(candidate RefreshCandidate, catalog catalogregistry.Registry) (Registry, error) {
	var result Registry
	err := s.withLock(func() error {
		registry, err := s.loadUnlocked()
		if err != nil {
			return err
		}
		if candidate.RegistryID != registry.RegistryID {
			return fmt.Errorf("candidate registry_id does not match refresh registry")
		}
		if err := ValidateCandidate(candidate, catalog); err != nil {
			return err
		}
		for _, existing := range registry.Candidates {
			if existing.CandidateID == candidate.CandidateID {
				if existing.CandidateChecksum != candidate.CandidateChecksum {
					return fmt.Errorf("immutable candidate collision for %s", candidate.CandidateID)
				}
				result = registry
				return nil
			}
		}
		if err := s.writeImmutable(filepath.Join("candidates", candidate.CandidateID+".json"), candidate); err != nil {
			return err
		}
		registry.Candidates = append(registry.Candidates, candidate)
		sort.Slice(registry.Candidates, func(i, j int) bool { return registry.Candidates[i].CandidateID < registry.Candidates[j].CandidateID })
		registry.RegistryChecksum = registryChecksum(registry)
		if err := ValidateRegistry(registry, catalog); err != nil {
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

func (s Store) Decide(input DecisionInput, catalog catalogregistry.Registry) (PromotionDecision, Registry, error) {
	var decision PromotionDecision
	var result Registry
	err := s.withLock(func() error {
		registry, err := s.loadUnlocked()
		if err != nil {
			return err
		}
		candidate, ok := findCandidate(registry, strings.TrimSpace(input.CandidateID))
		if !ok {
			return fmt.Errorf("unknown refresh candidate %s", input.CandidateID)
		}
		if input.Action != DecisionApprove && input.Action != DecisionReject {
			return fmt.Errorf("decision action must be approve or reject")
		}
		if input.Action == DecisionApprove && candidate.Status != CandidateReady {
			return fmt.Errorf("blocked candidate cannot be approved")
		}
		if strings.TrimSpace(input.Reason) == "" || strings.TrimSpace(input.DecidedBy) == "" || input.DecidedAt.IsZero() {
			return fmt.Errorf("reason, decided_by, and decided_at are required")
		}
		decision = PromotionDecision{SchemaVersion: DecisionSchemaVersion, RegistryID: registry.RegistryID, Sequence: registry.LastSequence + 1, CandidateID: candidate.CandidateID, Action: input.Action, Reason: strings.TrimSpace(input.Reason), DecidedAt: input.DecidedAt.UTC(), DecidedBy: strings.TrimSpace(input.DecidedBy), PreviousEventHash: registry.AuditHead}
		decision.DecisionID = decisionID(decision)
		decision.EventHash = decisionEventHash(decision)
		decision.DecisionChecksum = decisionChecksum(decision)
		if err := s.writeImmutable(filepath.Join("decisions", fmt.Sprintf("%020d-%s.json", decision.Sequence, decision.DecisionID)), decision); err != nil {
			return err
		}
		registry.Decisions = append(registry.Decisions, decision)
		registry.LastSequence = decision.Sequence
		registry.AuditHead = decision.EventHash
		registry.RegistryChecksum = registryChecksum(registry)
		if err := ValidateRegistry(registry, catalog); err != nil {
			return err
		}
		if err := s.writeRegistryUnlocked(registry); err != nil {
			return err
		}
		result = registry
		return nil
	})
	return decision, result, err
}

func (s Store) Promote(input PromoteInput, catalogStore catalogregistry.Store) (PromotionExecution, Registry, catalogregistry.Registry, error) {
	catalog, err := catalogStore.Load()
	if err != nil {
		return PromotionExecution{}, Registry{}, catalogregistry.Registry{}, err
	}
	registry, err := s.Load(catalog)
	if err != nil {
		return PromotionExecution{}, Registry{}, catalogregistry.Registry{}, err
	}
	candidate, ok := findCandidate(registry, strings.TrimSpace(input.CandidateID))
	if !ok {
		return PromotionExecution{}, Registry{}, catalogregistry.Registry{}, fmt.Errorf("unknown refresh candidate %s", input.CandidateID)
	}
	if candidate.Status != CandidateReady {
		return PromotionExecution{}, Registry{}, catalogregistry.Registry{}, fmt.Errorf("candidate is blocked")
	}
	decision, ok := latestDecision(registry, candidate.CandidateID)
	if !ok || decision.Action != DecisionApprove {
		return PromotionExecution{}, Registry{}, catalogregistry.Registry{}, fmt.Errorf("candidate does not have a current approval")
	}
	if alreadyPromoted(registry, candidate.CandidateID) {
		return PromotionExecution{}, Registry{}, catalogregistry.Registry{}, fmt.Errorf("candidate was already promoted")
	}
	if strings.TrimSpace(input.Reason) == "" || strings.TrimSpace(input.ExecutedBy) == "" || input.ExecutedAt.IsZero() {
		return PromotionExecution{}, Registry{}, catalogregistry.Registry{}, fmt.Errorf("reason, executed_by, and executed_at are required")
	}
	component, ok := findComponent(catalog, candidate.TargetComponentID)
	if !ok {
		return PromotionExecution{}, Registry{}, catalogregistry.Registry{}, fmt.Errorf("target component is no longer registered")
	}
	pointer, ok := findActive(catalog, component.ComponentID)
	if !ok || pointer.VersionID != candidate.CandidateVersion.ExpectedCurrentVersionID {
		return PromotionExecution{}, Registry{}, catalogregistry.Registry{}, fmt.Errorf("active version precondition failed")
	}
	cv := candidate.CandidateVersion
	version, err := catalogregistry.BuildVersion(catalogregistry.VersionInput{ComponentID: cv.ComponentID, CatalogID: cv.CatalogID, CatalogVersion: cv.CatalogVersion, CatalogChecksum: cv.CatalogChecksum, CatalogSchema: cv.CatalogSchema, ArtifactURI: cv.ArtifactURI, ArtifactSHA256: cv.ArtifactSHA256, SourceManifestID: cv.SourceManifestID, SourceManifestHash: cv.SourceManifestHash, RecordCount: cv.RecordCount, ProducerVersion: cv.ProducerVersion, Source: catalogregistry.SourceDescriptor{Kind: catalogregistry.SourceKindProvider, Provider: &catalogregistry.ProviderSource{ProviderID: cv.ProviderID, ProviderComponentRef: cv.ProviderComponentRef, ProviderTitle: cv.ProviderTitle, ProviderVersion: cv.ProviderVersion}}, Metadata: cv.Metadata, RegisteredAt: input.ExecutedAt, RegisteredBy: input.ExecutedBy}, component)
	if err != nil {
		return PromotionExecution{}, Registry{}, catalogregistry.Registry{}, err
	}
	catalog, err = catalogStore.RegisterVersion(version)
	if err != nil {
		return PromotionExecution{}, Registry{}, catalogregistry.Registry{}, err
	}
	activation, catalog, err := catalogStore.Activate(catalogregistry.ActivationRequest{ComponentID: component.ComponentID, TargetVersionID: version.VersionID, Action: catalogregistry.ActivationActionActivate, ExpectedCurrentVersionID: cv.ExpectedCurrentVersionID, Reason: input.Reason, ActivatedAt: input.ExecutedAt, ActivatedBy: input.ExecutedBy})
	if err != nil {
		return PromotionExecution{}, Registry{}, catalogregistry.Registry{}, err
	}
	execution, result, err := s.recordExecution(PromotionExecution{SchemaVersion: ExecutionSchemaVersion, Action: ExecutionPromote, CandidateID: candidate.CandidateID, DecisionID: decision.DecisionID, ComponentID: component.ComponentID, PreviousVersionID: cv.ExpectedCurrentVersionID, TargetVersionID: version.VersionID, CatalogActivationID: activation.ActivationID, Reason: strings.TrimSpace(input.Reason), ExecutedAt: input.ExecutedAt.UTC(), ExecutedBy: strings.TrimSpace(input.ExecutedBy)}, catalog)
	return execution, result, catalog, err
}

func (s Store) Rollback(input RollbackInput, catalogStore catalogregistry.Store) (PromotionExecution, Registry, catalogregistry.Registry, error) {
	catalog, err := catalogStore.Load()
	if err != nil {
		return PromotionExecution{}, Registry{}, catalogregistry.Registry{}, err
	}
	if strings.TrimSpace(input.Reason) == "" || strings.TrimSpace(input.ExecutedBy) == "" || input.ExecutedAt.IsZero() {
		return PromotionExecution{}, Registry{}, catalogregistry.Registry{}, fmt.Errorf("reason, executed_by, and executed_at are required")
	}
	pointer, ok := findActive(catalog, strings.TrimSpace(input.ComponentID))
	if !ok || pointer.VersionID != strings.TrimSpace(input.ExpectedCurrentVersionID) {
		return PromotionExecution{}, Registry{}, catalogregistry.Registry{}, fmt.Errorf("active version precondition failed")
	}
	activation, catalog, err := catalogStore.Activate(catalogregistry.ActivationRequest{ComponentID: input.ComponentID, TargetVersionID: input.TargetVersionID, Action: catalogregistry.ActivationActionRollback, ExpectedCurrentVersionID: input.ExpectedCurrentVersionID, Reason: input.Reason, ActivatedAt: input.ExecutedAt, ActivatedBy: input.ExecutedBy})
	if err != nil {
		return PromotionExecution{}, Registry{}, catalogregistry.Registry{}, err
	}
	execution, result, err := s.recordExecution(PromotionExecution{SchemaVersion: ExecutionSchemaVersion, Action: ExecutionRollback, ComponentID: input.ComponentID, PreviousVersionID: input.ExpectedCurrentVersionID, TargetVersionID: input.TargetVersionID, CatalogActivationID: activation.ActivationID, Reason: strings.TrimSpace(input.Reason), ExecutedAt: input.ExecutedAt.UTC(), ExecutedBy: strings.TrimSpace(input.ExecutedBy)}, catalog)
	return execution, result, catalog, err
}

func (s Store) recordExecution(base PromotionExecution, catalog catalogregistry.Registry) (PromotionExecution, Registry, error) {
	var execution PromotionExecution
	var result Registry
	err := s.withLock(func() error {
		registry, err := s.loadUnlocked()
		if err != nil {
			return err
		}
		base.RegistryID = registry.RegistryID
		base.Sequence = registry.LastSequence + 1
		base.PreviousEventHash = registry.AuditHead
		base.ExecutionID = executionID(base)
		base.EventHash = executionEventHash(base)
		base.ExecutionChecksum = executionChecksum(base)
		execution = base
		if err := s.writeImmutable(filepath.Join("executions", fmt.Sprintf("%020d-%s.json", execution.Sequence, execution.ExecutionID)), execution); err != nil {
			return err
		}
		registry.Executions = append(registry.Executions, execution)
		registry.LastSequence = execution.Sequence
		registry.AuditHead = execution.EventHash
		registry.RegistryChecksum = registryChecksum(registry)
		if err := ValidateRegistry(registry, catalog); err != nil {
			return err
		}
		if err := s.writeRegistryUnlocked(registry); err != nil {
			return err
		}
		result = registry
		return nil
	})
	return execution, result, err
}

func (s Store) Load(catalog catalogregistry.Registry) (Registry, error) {
	registry, err := s.loadUnlocked()
	if err != nil {
		return Registry{}, err
	}
	if err := s.Verify(registry, catalog); err != nil {
		return Registry{}, err
	}
	return registry, nil
}
func (s Store) Verify(registry Registry, catalog catalogregistry.Registry) error {
	if err := ValidateRegistry(registry, catalog); err != nil {
		return err
	}
	for _, v := range registry.Candidates {
		var stored RefreshCandidate
		if err := s.read(filepath.Join("candidates", v.CandidateID+".json"), &stored); err != nil {
			return err
		}
		if stored.CandidateChecksum != v.CandidateChecksum {
			return fmt.Errorf("candidate file mismatch for %s", v.CandidateID)
		}
	}
	for _, v := range registry.Decisions {
		var stored PromotionDecision
		if err := s.read(filepath.Join("decisions", fmt.Sprintf("%020d-%s.json", v.Sequence, v.DecisionID)), &stored); err != nil {
			return err
		}
		if stored.DecisionChecksum != v.DecisionChecksum {
			return fmt.Errorf("decision file mismatch for %s", v.DecisionID)
		}
	}
	for _, v := range registry.Executions {
		var stored PromotionExecution
		if err := s.read(filepath.Join("executions", fmt.Sprintf("%020d-%s.json", v.Sequence, v.ExecutionID)), &stored); err != nil {
			return err
		}
		if stored.ExecutionChecksum != v.ExecutionChecksum {
			return fmt.Errorf("execution file mismatch for %s", v.ExecutionID)
		}
	}
	return nil
}
func (s Store) loadUnlocked() (Registry, error) {
	var r Registry
	if err := s.read("registry.json", &r); err != nil {
		return Registry{}, err
	}
	return r, nil
}
func (s Store) writeRegistryUnlocked(r Registry) error { return s.writeAtomic("registry.json", r) }
func (s Store) writeImmutable(relative string, value any) error {
	path := filepath.Join(s.Root, relative)
	data, err := jsonBytes(value)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	if old, e := os.ReadFile(path); e == nil {
		if !bytes.Equal(old, data) {
			return fmt.Errorf("immutable state collision at %s", path)
		}
		return nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
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
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".provider-refresh-*.tmp")
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
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	if err = d.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err = d.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing JSON value in %s", relative)
	}
	return nil
}
func (s Store) withLock(fn func() error) error {
	if strings.TrimSpace(s.Root) == "" {
		return fmt.Errorf("provider refresh store root is required")
	}
	if err := os.MkdirAll(s.Root, 0755); err != nil {
		return err
	}
	lock := filepath.Join(s.Root, ".lock")
	if err := os.Mkdir(lock, 0700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("provider refresh registry is locked at %s", lock)
		}
		return err
	}
	defer os.Remove(lock)
	return fn()
}
func jsonBytes(value any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	if err := e.Encode(value); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
func findCandidate(r Registry, id string) (RefreshCandidate, bool) {
	for _, v := range r.Candidates {
		if v.CandidateID == id {
			return v, true
		}
	}
	return RefreshCandidate{}, false
}
func latestDecision(r Registry, candidateID string) (PromotionDecision, bool) {
	var out PromotionDecision
	ok := false
	for _, v := range r.Decisions {
		if v.CandidateID == candidateID && (!ok || v.Sequence > out.Sequence) {
			out = v
			ok = true
		}
	}
	return out, ok
}
func alreadyPromoted(r Registry, candidateID string) bool {
	for _, v := range r.Executions {
		if v.Action == ExecutionPromote && v.CandidateID == candidateID {
			return true
		}
	}
	return false
}
