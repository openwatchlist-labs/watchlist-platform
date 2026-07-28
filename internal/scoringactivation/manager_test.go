package scoringactivation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/projectionpackage"
)

func testFixture(parts ...string) string {
	all := append([]string{"..", "..", "test", "fixtures", "projection-package"}, parts...)
	return filepath.Join(all...)
}

func createTestTuple(t *testing.T) (string, string, string) {
	t.Helper()
	descriptorSource := testFixture("catalog-descriptor.json")
	inputSource := testFixture("canonical-input.json")
	policySource := filepath.Join("..", "..", "configs", "scoring", "candidate-scoring-r1.json")
	temporary := t.TempDir()
	descriptorPath := filepath.Join(temporary, "catalog-descriptor.json")
	catalogPath := filepath.Join(temporary, "catalog-fixture.mmap")
	policyPath := filepath.Join(temporary, "policy.json")
	copyFile(t, descriptorSource, descriptorPath)
	copyFile(t, testFixture("catalog-fixture.mmap"), catalogPath)
	copyFile(t, policySource, policyPath)
	descriptor, err := projectionpackage.LoadCatalogDescriptor(descriptorPath)
	if err != nil {
		t.Fatal(err)
	}
	input, err := projectionpackage.LoadCanonicalInput(inputSource)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := projectionpackage.Compile(descriptor, input, filepath.Join(temporary, "packages"))
	if err != nil {
		t.Fatal(err)
	}
	return descriptorPath, pkg.Directory, policyPath
}

func copyFile(t *testing.T, source, destination string) {
	t.Helper()
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestActivateRollbackAndActiveOnlyLookup(t *testing.T) {
	descriptorPath, packagePath, policyPath := createTestTuple(t)
	manager, err := NewManager(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := manager.Activate(ActivateRequest{
		ActivationID: "activation-one", CatalogDescriptorPath: descriptorPath,
		ProjectionPackagePath: packagePath, ScoringPolicyPath: policyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Activate(ActivateRequest{
		ActivationID: "activation-two", CatalogDescriptorPath: descriptorPath,
		ProjectionPackagePath: packagePath, ScoringPolicyPath: policyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Activation.PreviousActivationID != first.Activation.ActivationID {
		t.Fatal("previous activation lineage was not retained")
	}
	candidate, ok, err := manager.LookupActiveCandidate("candidate-exact-lei")
	if err != nil || !ok || candidate.CandidateID != "candidate-exact-lei" {
		t.Fatalf("active lookup failed: %v %v %#v", err, ok, candidate)
	}
	rolledBack, err := manager.Rollback()
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.Activation.ActivationID != "activation-one" {
		t.Fatalf("rollback selected %q", rolledBack.Activation.ActivationID)
	}
}

func TestActiveTupleRejectsPolicyTampering(t *testing.T) {
	descriptorPath, packagePath, policyPath := createTestTuple(t)
	manager, _ := NewManager(filepath.Join(t.TempDir(), "state"))
	if _, err := manager.Activate(ActivateRequest{
		ActivationID: "activation-tamper", CatalogDescriptorPath: descriptorPath,
		ProjectionPackagePath: packagePath, ScoringPolicyPath: policyPath,
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), "\"score_ceiling\": 1000", "\"score_ceiling\": 999", 1))
	if err := os.WriteFile(policyPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.LoadActive(); err == nil {
		t.Fatal("tampered scoring policy was accepted")
	}
}

func TestRecoverCompletesOrRollsBackPendingActivation(t *testing.T) {
	descriptorPath, packagePath, policyPath := createTestTuple(t)
	manager, _ := NewManager(filepath.Join(t.TempDir(), "state"))
	first, err := manager.Activate(ActivateRequest{
		ActivationID: "activation-base", CatalogDescriptorPath: descriptorPath,
		ProjectionPackagePath: packagePath, ScoringPolicyPath: policyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	pending := pendingDocument{SchemaVersion: PendingSchemaV1, TargetActivationID: "activation-missing", PreviousActivationID: first.Activation.ActivationID}
	raw, _ := marshalCanonical(pending)
	if err := atomicWrite(manager.pendingPath(), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := manager.Recover()
	if err != nil {
		t.Fatal(err)
	}
	if result != "rolled_back" {
		t.Fatalf("recover result=%q", result)
	}
	active, err := manager.LoadActive()
	if err != nil || active.Activation.ActivationID != first.Activation.ActivationID {
		t.Fatalf("active tuple not restored: %v %#v", err, active.Activation)
	}
}
