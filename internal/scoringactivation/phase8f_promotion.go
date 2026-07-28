package scoringactivation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/openwatchlist-labs/watchlist-platform/internal/candidatescoring"
	"github.com/openwatchlist-labs/watchlist-platform/internal/projectionpackage"
)

// Stage validates and stores one immutable activation without moving active.json.
func (m *Manager) Stage(request ActivateRequest, expectedPreviousActivationID string) (Snapshot, error) {
	if !activationIDPattern.MatchString(request.ActivationID) {
		return Snapshot{}, errors.New("activation_id must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}")
	}
	active, err := m.LoadActive()
	if err != nil {
		return Snapshot{}, fmt.Errorf("load active activation: %w", err)
	}
	if expectedPreviousActivationID == "" {
		expectedPreviousActivationID = active.Activation.ActivationID
	}
	if active.Activation.ActivationID != expectedPreviousActivationID {
		return Snapshot{}, fmt.Errorf("active activation CAS mismatch: expected %q, found %q", expectedPreviousActivationID, active.Activation.ActivationID)
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
	activation := Activation{
		SchemaVersion:        ActivationSchemaV1,
		ActivationID:         request.ActivationID,
		PreviousActivationID: expectedPreviousActivationID,
		Catalog:              descriptor,
		Projection: ProjectionBinding{
			PackagePath:        packagePath,
			PackageSHA256:      pkg.PackageSHA256,
			ProjectionsSHA256:  pkg.Manifest.ProjectionsSHA256,
			ProjectionCount:    pkg.Manifest.ProjectionCount,
			CandidateIDsSHA256: pkg.Manifest.CandidateIDsSHA256,
		},
		Policy: PolicyBinding{
			Path:                 policyPath,
			PolicyID:             policy.Policy.PolicyID,
			PolicyVersion:        policy.Policy.PolicyVersion,
			PolicySHA256:         policy.SHA256,
			NormalizationProfile: policy.Policy.NormalizationProfile,
		},
	}
	if err := m.ensureDirectories(); err != nil {
		return Snapshot{}, err
	}
	raw, err := marshalCanonical(activation)
	if err != nil {
		return Snapshot{}, err
	}
	path := m.activationPath(activation.ActivationID)
	if existing, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(existing, raw) {
			return Snapshot{}, fmt.Errorf("activation_id %q already exists with different bytes", activation.ActivationID)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, err
	} else if err := atomicWrite(path, raw, 0o644); err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Activation: activation, ProjectionPackage: pkg, Policy: policy}, nil
}

// LoadActivation validates one immutable activation without requiring it to be active.
func (m *Manager) LoadActivation(activationID string) (Snapshot, error) {
	if !activationIDPattern.MatchString(activationID) {
		return Snapshot{}, errors.New("invalid activation_id")
	}
	activation, err := m.loadActivationDocument(activationID)
	if err != nil {
		return Snapshot{}, err
	}
	return m.validateActivation(activation)
}

// PromoteExisting atomically moves active.json to a staged activation using CAS.
func (m *Manager) PromoteExisting(activationID, expectedCurrentActivationID string) (Snapshot, error) {
	current, err := m.LoadActive()
	if err != nil {
		return Snapshot{}, err
	}
	if current.Activation.ActivationID != expectedCurrentActivationID {
		return Snapshot{}, fmt.Errorf("active activation CAS mismatch: expected %q, found %q", expectedCurrentActivationID, current.Activation.ActivationID)
	}
	target, err := m.LoadActivation(activationID)
	if err != nil {
		return Snapshot{}, err
	}
	if target.Activation.PreviousActivationID != expectedCurrentActivationID && activationID != current.Activation.PreviousActivationID {
		return Snapshot{}, fmt.Errorf("activation %q is not linked to current activation %q", activationID, expectedCurrentActivationID)
	}
	pending := pendingDocument{
		SchemaVersion:        PendingSchemaV1,
		TargetActivationID:   target.Activation.ActivationID,
		PreviousActivationID: current.Activation.ActivationID,
	}
	pendingRaw, _ := marshalCanonical(pending)
	if err := atomicWrite(m.pendingPath(), pendingRaw, 0o644); err != nil {
		return Snapshot{}, err
	}
	targetRaw, _ := marshalCanonical(target.Activation)
	if err := atomicWrite(m.activePath(), targetRaw, 0o644); err != nil {
		return Snapshot{}, err
	}
	if err := os.Remove(m.pendingPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, err
	}
	return target, nil
}

// ActivationDigest returns the SHA-256 of the canonical immutable activation document.
func ActivationDigest(activation Activation) (string, error) {
	raw, err := marshalCanonical(activation)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

// ActivationDocumentSHA256 returns the SHA-256 of the exact immutable activation file bytes.
func (m *Manager) ActivationDocumentSHA256(activationID string) (string, error) {
	if !activationIDPattern.MatchString(activationID) {
		return "", errors.New("invalid activation_id")
	}
	raw, err := os.ReadFile(m.activationPath(activationID))
	if err != nil {
		return "", err
	}
	var activation Activation
	if err := decodeStrictFile(m.activationPath(activationID), &activation); err != nil {
		return "", err
	}
	canonicalRaw, err := marshalCanonical(activation)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(raw, canonicalRaw) {
		return "", errors.New("activation document is not canonical")
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}
