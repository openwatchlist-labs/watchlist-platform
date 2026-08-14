package scoringactivation

import (
	"encoding/json"
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

func TestActivatePersistsPathsRelativeToStateDirectory(t *testing.T) {
	descriptorPath, packagePath, policyPath := createTestTuple(t)
	tupleDirectory := filepath.Dir(descriptorPath)
	stateDirectory := filepath.Join(t.TempDir(), "state")
	manager, err := NewManager(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}

	// Invoke from a CWD distinct from both the tuple directory and the
	// state directory, passing paths relative to that CWD -- mirrors how
	// the CLI is actually invoked (see cmd/scoring-activation/main_test.go).
	invocationDirectory := t.TempDir()
	t.Chdir(invocationDirectory)
	relativeDescriptor, err := filepath.Rel(invocationDirectory, descriptorPath)
	if err != nil {
		t.Fatal(err)
	}
	relativePackage, err := filepath.Rel(invocationDirectory, packagePath)
	if err != nil {
		t.Fatal(err)
	}
	relativePolicy, err := filepath.Rel(invocationDirectory, policyPath)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := manager.Activate(ActivateRequest{
		ActivationID: "activation-portable", CatalogDescriptorPath: relativeDescriptor,
		ProjectionPackagePath: relativePackage, ScoringPolicyPath: relativePolicy,
	}); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(manager.activationPath("activation-portable"))
	if err != nil {
		t.Fatal(err)
	}
	var stored Activation
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}

	for name, path := range map[string]string{
		"catalog.catalog_package_path": stored.Catalog.CatalogPackagePath,
		"projection.package_path":      stored.Projection.PackagePath,
		"policy.path":                  stored.Policy.Path,
	} {
		if filepath.IsAbs(path) {
			t.Fatalf("%s was persisted as an absolute path %q -- not portable across machines/checkouts", name, path)
		}
		if strings.Contains(path, tupleDirectory) {
			t.Fatalf("%s leaked the tuple directory %q into the persisted path %q", name, tupleDirectory, path)
		}
	}

	if resolved := filepath.Clean(filepath.Join(stateDirectory, stored.Catalog.CatalogPackagePath)); resolved != filepath.Clean(descriptorPathCatalogPackage(t, descriptorPath)) {
		t.Fatalf("catalog_package_path %q does not resolve against the state directory to the original file (got %q)", stored.Catalog.CatalogPackagePath, resolved)
	}
	if resolved := filepath.Clean(filepath.Join(stateDirectory, stored.Projection.PackagePath)); resolved != filepath.Clean(packagePath) {
		t.Fatalf("package_path %q does not resolve against the state directory to %q (got %q)", stored.Projection.PackagePath, packagePath, resolved)
	}
	if resolved := filepath.Clean(filepath.Join(stateDirectory, stored.Policy.Path)); resolved != filepath.Clean(policyPath) {
		t.Fatalf("policy.path %q does not resolve against the state directory to %q (got %q)", stored.Policy.Path, policyPath, resolved)
	}

	// A load from yet another, unrelated CWD must still succeed -- this is
	// the guarantee resolvePath's relative-path convention exists to provide.
	t.Chdir(t.TempDir())
	if _, err := manager.LoadActive(); err != nil {
		t.Fatalf("LoadActive from an unrelated CWD failed: %v", err)
	}
}

func descriptorPathCatalogPackage(t *testing.T, descriptorPath string) string {
	t.Helper()
	descriptor, err := projectionpackage.LoadCatalogDescriptor(descriptorPath)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor.CatalogPackagePath
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
