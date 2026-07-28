package catalogruntime

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStateStorePersistsImmutableActivationAndRollbackRecords(t *testing.T) {
	root := t.TempDir()
	store := StateStore{Root: root}
	compiledA := time.Date(2026, 7, 13, 17, 0, 0, 0, time.UTC)
	compiledB := compiledA.Add(24 * time.Hour)
	inputA := testPackageInput("package-a", digest64('a'), "catalog-a", digest64('b'), "manifest-a", compiledA)
	inputB := testPackageInput("package-b", digest64('c'), "catalog-b", digest64('d'), "manifest-b", compiledB)
	readyA, err := NewReadinessReport(inputA, compiledA.Add(time.Minute), []ReadinessCheck{{Name: "integrity", Status: CheckPass, Detail: "verified"}})
	if err != nil {
		t.Fatal(err)
	}
	readyB, err := NewReadinessReport(inputB, compiledB.Add(time.Minute), []ReadinessCheck{{Name: "integrity", Status: CheckPass, Detail: "verified"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PersistPackage(inputA.PackageID, inputA.PackageChecksum, ".owpcat", []byte("artifact-a")); err == nil {
		t.Fatal("incorrect package checksum accepted")
	}
	activationA, err := store.Activate(inputA, readyA, compiledA.Add(2*time.Minute))
	if err != nil || activationA.Active.ActivationEpoch != 1 {
		t.Fatalf("activation A failed: %+v %v", activationA, err)
	}
	activationB, err := store.Activate(inputB, readyB, compiledB.Add(2*time.Minute))
	if err != nil || activationB.Active.ActivationEpoch != 2 {
		t.Fatalf("activation B failed: %+v %v", activationB, err)
	}
	rollback, err := store.Rollback(inputA, readyA, "canary regression", compiledB.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if rollback.Rollback.NewGeneration.ActivationEpoch != 3 || rollback.Rollback.TargetPackageID != inputA.PackageID {
		t.Fatalf("rollback mismatch: %+v", rollback)
	}
	active, err := store.Active()
	if err != nil || active.Generation.PackageID != inputA.PackageID || active.Generation.ActivationEpoch != 3 {
		t.Fatalf("active pointer mismatch: %+v %v", active, err)
	}
	for _, path := range []string{
		filepath.Join(root, "activations", activationA.ActivationID+".json"),
		filepath.Join(root, "activations", activationB.ActivationID+".json"),
		filepath.Join(root, "rollbacks", rollback.Rollback.RollbackID+".json"),
		filepath.Join(root, "active.json"),
	} {
		if info, err := os.Stat(path); err != nil || info.Size() == 0 {
			t.Fatalf("missing state record %s: %v", path, err)
		}
	}
}

func testPackageInput(packageID, packageChecksum, version, catalogChecksum, manifest string, compiled time.Time) PackageActivationInput {
	return PackageActivationInput{PackageID: packageID, PackageChecksum: packageChecksum, CatalogID: "ofac-sdn-direct", CatalogVersion: version, CatalogChecksum: catalogChecksum, SourceManifestID: manifest, CompiledAt: compiled}
}

func digest64(r byte) string {
	return string(make([]byte, 0)) + repeatByte(r, 64)
}

func repeatByte(value byte, count int) string {
	out := make([]byte, count)
	for index := range out {
		out[index] = value
	}
	return string(out)
}
