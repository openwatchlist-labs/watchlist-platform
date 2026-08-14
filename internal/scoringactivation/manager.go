package scoringactivation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/candidatescoring"
	"github.com/openwatchlist-labs/watchlist-platform/internal/projectionpackage"
)

var activationIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Manager struct {
	stateDirectory string
}

func NewManager(stateDirectory string) (*Manager, error) {
	if strings.TrimSpace(stateDirectory) == "" {
		return nil, errors.New("activation state directory is required")
	}
	absolute, err := filepath.Abs(stateDirectory)
	if err != nil {
		return nil, err
	}
	return &Manager{stateDirectory: absolute}, nil
}

func (m *Manager) StateDirectory() string { return m.stateDirectory }

func (m *Manager) Activate(request ActivateRequest) (Snapshot, error) {
	if !activationIDPattern.MatchString(request.ActivationID) {
		return Snapshot{}, errors.New("activation_id must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}")
	}
	descriptorPath, err := filepath.Abs(request.CatalogDescriptorPath)
	if err != nil {
		return Snapshot{}, err
	}
	packagePath, err := filepath.Abs(request.ProjectionPackagePath)
	if err != nil {
		return Snapshot{}, err
	}
	policyPath, err := filepath.Abs(request.ScoringPolicyPath)
	if err != nil {
		return Snapshot{}, err
	}
	descriptor, err := projectionpackage.LoadCatalogDescriptor(descriptorPath)
	if err != nil {
		return Snapshot{}, err
	}
	pkg, err := projectionpackage.LoadPackage(packagePath)
	if err != nil {
		return Snapshot{}, err
	}
	policy, err := candidatescoring.LoadPolicy(policyPath)
	if err != nil {
		return Snapshot{}, err
	}
	if err := validateTuple(descriptor, pkg, policy); err != nil {
		return Snapshot{}, err
	}
	previousID := ""
	if current, err := m.loadActiveDocument(); err == nil {
		previousID = current.ActivationID
	} else if !errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, err
	}
	relativeCatalogPackagePath, err := relativeToStateDirectory(m.stateDirectory, descriptor.CatalogPackagePath)
	if err != nil {
		return Snapshot{}, err
	}
	relativePackagePath, err := relativeToStateDirectory(m.stateDirectory, packagePath)
	if err != nil {
		return Snapshot{}, err
	}
	relativePolicyPath, err := relativeToStateDirectory(m.stateDirectory, policyPath)
	if err != nil {
		return Snapshot{}, err
	}
	activation := Activation{
		SchemaVersion:        ActivationSchemaV1,
		ActivationID:         request.ActivationID,
		PreviousActivationID: previousID,
		Catalog:              descriptor,
		Projection: ProjectionBinding{
			PackagePath:        relativePackagePath,
			PackageSHA256:      pkg.PackageSHA256,
			ProjectionsSHA256:  pkg.Manifest.ProjectionsSHA256,
			ProjectionCount:    pkg.Manifest.ProjectionCount,
			CandidateIDsSHA256: pkg.Manifest.CandidateIDsSHA256,
		},
		Policy: PolicyBinding{
			Path:                 relativePolicyPath,
			PolicyID:             policy.Policy.PolicyID,
			PolicyVersion:        policy.Policy.PolicyVersion,
			PolicySHA256:         policy.SHA256,
			NormalizationProfile: policy.Policy.NormalizationProfile,
		},
	}
	activation.Catalog.CatalogPackagePath = relativeCatalogPackagePath
	if err := m.ensureDirectories(); err != nil {
		return Snapshot{}, err
	}
	activationRaw, err := marshalCanonical(activation)
	if err != nil {
		return Snapshot{}, err
	}
	activationPath := m.activationPath(activation.ActivationID)
	if existing, err := os.ReadFile(activationPath); err == nil {
		if !bytes.Equal(existing, activationRaw) {
			return Snapshot{}, fmt.Errorf("activation_id %q already exists with different bytes", activation.ActivationID)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, err
	} else if err := atomicWrite(activationPath, activationRaw, 0o644); err != nil {
		return Snapshot{}, err
	}
	pending := pendingDocument{SchemaVersion: PendingSchemaV1, TargetActivationID: activation.ActivationID, PreviousActivationID: previousID}
	pendingRaw, _ := marshalCanonical(pending)
	if err := atomicWrite(m.pendingPath(), pendingRaw, 0o644); err != nil {
		return Snapshot{}, err
	}
	if err := atomicWrite(m.activePath(), activationRaw, 0o644); err != nil {
		return Snapshot{}, err
	}
	if err := os.Remove(m.pendingPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, err
	}
	return Snapshot{Activation: activation, ProjectionPackage: pkg, Policy: policy}, nil
}

func (m *Manager) LoadActive() (Snapshot, error) {
	activation, err := m.loadActiveDocument()
	if err != nil {
		return Snapshot{}, err
	}
	return m.validateActivation(activation)
}

func (m *Manager) Rollback() (Snapshot, error) {
	active, err := m.loadActiveDocument()
	if err != nil {
		return Snapshot{}, err
	}
	if active.PreviousActivationID == "" {
		return Snapshot{}, errors.New("active tuple has no previous activation")
	}
	previous, err := m.loadActivationDocument(active.PreviousActivationID)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot, err := m.validateActivation(previous)
	if err != nil {
		return Snapshot{}, err
	}
	pending := pendingDocument{SchemaVersion: PendingSchemaV1, TargetActivationID: previous.ActivationID, PreviousActivationID: active.ActivationID}
	pendingRaw, _ := marshalCanonical(pending)
	if err := atomicWrite(m.pendingPath(), pendingRaw, 0o644); err != nil {
		return Snapshot{}, err
	}
	activeRaw, _ := marshalCanonical(previous)
	if err := atomicWrite(m.activePath(), activeRaw, 0o644); err != nil {
		return Snapshot{}, err
	}
	_ = os.Remove(m.pendingPath())
	return snapshot, nil
}

func (m *Manager) Recover() (string, error) {
	var pending pendingDocument
	if err := decodeStrictFile(m.pendingPath(), &pending); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "clean", nil
		}
		return "", fmt.Errorf("decode pending activation: %w", err)
	}
	if pending.SchemaVersion != PendingSchemaV1 {
		return "", errors.New("unsupported pending activation schema")
	}
	if active, err := m.loadActiveDocument(); err == nil && active.ActivationID == pending.TargetActivationID {
		if _, err := m.validateActivation(active); err == nil {
			_ = os.Remove(m.pendingPath())
			return "completed", nil
		}
	}
	if pending.PreviousActivationID != "" {
		previous, err := m.loadActivationDocument(pending.PreviousActivationID)
		if err != nil {
			return "", err
		}
		if _, err := m.validateActivation(previous); err != nil {
			return "", err
		}
		raw, _ := marshalCanonical(previous)
		if err := atomicWrite(m.activePath(), raw, 0o644); err != nil {
			return "", err
		}
	} else {
		_ = os.Remove(m.activePath())
	}
	_ = os.Remove(m.pendingPath())
	return "rolled_back", nil
}

func (m *Manager) LookupActiveCandidate(candidateID string) (candidatescoring.Candidate, bool, error) {
	snapshot, err := m.LoadActive()
	if err != nil {
		return candidatescoring.Candidate{}, false, err
	}
	id := strings.TrimSpace(candidateID)
	for _, candidate := range snapshot.ProjectionPackage.Projections.Candidates {
		if candidate.CandidateID == id {
			return candidate, true, nil
		}
	}
	return candidatescoring.Candidate{}, false, nil
}

func (m *Manager) validateActivation(activation Activation) (Snapshot, error) {
	if activation.SchemaVersion != ActivationSchemaV1 || !activationIDPattern.MatchString(activation.ActivationID) {
		return Snapshot{}, errors.New("invalid activation document")
	}
	activation = m.resolveActivationPaths(activation)
	pkg, err := projectionpackage.LoadPackage(activation.Projection.PackagePath)
	if err != nil {
		return Snapshot{}, err
	}
	policy, err := candidatescoring.LoadPolicy(activation.Policy.Path)
	if err != nil {
		return Snapshot{}, err
	}
	if err := validateTuple(activation.Catalog, pkg, policy); err != nil {
		return Snapshot{}, err
	}
	if pkg.PackageSHA256 != activation.Projection.PackageSHA256 ||
		pkg.Manifest.ProjectionsSHA256 != activation.Projection.ProjectionsSHA256 ||
		pkg.Manifest.ProjectionCount != activation.Projection.ProjectionCount ||
		pkg.Manifest.CandidateIDsSHA256 != activation.Projection.CandidateIDsSHA256 {
		return Snapshot{}, errors.New("active projection binding does not match package")
	}
	if policy.SHA256 != activation.Policy.PolicySHA256 ||
		policy.Policy.PolicyID != activation.Policy.PolicyID ||
		policy.Policy.PolicyVersion != activation.Policy.PolicyVersion ||
		policy.Policy.NormalizationProfile != activation.Policy.NormalizationProfile {
		return Snapshot{}, errors.New("active policy binding does not match policy content")
	}
	return Snapshot{Activation: activation, ProjectionPackage: pkg, Policy: policy}, nil
}

func validateTuple(descriptor projectionpackage.CatalogDescriptor, pkg projectionpackage.Package, policy candidatescoring.LoadedPolicy) error {
	if err := projectionpackage.ValidateCatalogPackageFile(descriptor); err != nil {
		return err
	}
	manifest := pkg.Manifest
	checks := [][3]string{
		{"provider", descriptor.Provider, manifest.Provider},
		{"catalog_id", descriptor.CatalogID, manifest.CatalogID},
		{"component_id", descriptor.ComponentID, manifest.ComponentID},
		{"component_version", descriptor.ComponentVersion, manifest.ComponentVersion},
		{"catalog_package_sha256", descriptor.CatalogPackageSHA256, manifest.CatalogPackageSHA256},
		{"normalization_profile", descriptor.NormalizationProfile, manifest.NormalizationProfile},
	}
	for _, check := range checks {
		if check[1] != check[2] {
			return fmt.Errorf("projection package %s %q does not match catalog descriptor %q", check[0], check[2], check[1])
		}
	}
	if manifest.SourceRecordCount != descriptor.RecordCount || manifest.ProjectionCount != descriptor.RetrievableCandidateCount || manifest.CandidateIDsSHA256 != descriptor.RetrievableCandidateIDsSHA256 {
		return errors.New("projection package counts or candidate coverage do not match catalog descriptor")
	}
	if policy.Policy.NormalizationProfile != descriptor.NormalizationProfile {
		return fmt.Errorf("scoring policy normalization_profile %q does not match active catalog %q", policy.Policy.NormalizationProfile, descriptor.NormalizationProfile)
	}
	return nil
}

func (m *Manager) resolveActivationPaths(activation Activation) Activation {
	activation.Catalog.CatalogPackagePath = resolvePath(m.stateDirectory, activation.Catalog.CatalogPackagePath)
	activation.Projection.PackagePath = resolvePath(m.stateDirectory, activation.Projection.PackagePath)
	activation.Policy.Path = resolvePath(m.stateDirectory, activation.Policy.Path)
	return activation
}

func resolvePath(base, value string) string {
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Clean(filepath.Join(base, value))
}

// relativeToStateDirectory expresses an absolute path relative to the
// activation state directory, the convention resolvePath expects at load
// time. Activation records must never persist a filesystem-absolute path:
// that bakes in the machine/checkout that generated them (see PR #119).
func relativeToStateDirectory(stateDirectory, absolutePath string) (string, error) {
	if absolutePath == "" {
		return "", nil
	}
	relative, err := filepath.Rel(stateDirectory, absolutePath)
	if err != nil {
		return "", fmt.Errorf("compute path relative to state directory: %w", err)
	}
	return relative, nil
}

func (m *Manager) ensureDirectories() error {
	for _, path := range []string{m.stateDirectory, filepath.Join(m.stateDirectory, "activations")} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) activePath() string  { return filepath.Join(m.stateDirectory, "active.json") }
func (m *Manager) pendingPath() string { return filepath.Join(m.stateDirectory, "pending.json") }
func (m *Manager) activationPath(id string) string {
	return filepath.Join(m.stateDirectory, "activations", id+".json")
}

func (m *Manager) loadActiveDocument() (Activation, error) {
	var activation Activation
	if err := decodeStrictFile(m.activePath(), &activation); err != nil {
		return Activation{}, err
	}
	return activation, nil
}

func (m *Manager) loadActivationDocument(id string) (Activation, error) {
	var activation Activation
	if err := decodeStrictFile(m.activationPath(id), &activation); err != nil {
		return Activation{}, err
	}
	return activation, nil
}

func decodeStrictFile(path string, destination any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func marshalCanonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func atomicWrite(path string, raw []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".atomic-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	cleanup := true
	defer func() {
		_ = temporary.Close()
		if cleanup {
			_ = os.Remove(temporaryPath)
		}
	}()
	if _, err := temporary.Write(raw); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	cleanup = false
	directory, err := os.Open(filepath.Dir(path))
	if err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}
