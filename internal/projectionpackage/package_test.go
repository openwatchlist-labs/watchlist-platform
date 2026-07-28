package projectionpackage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixturePath(parts ...string) string {
	all := append([]string{"..", "..", "test", "fixtures", "projection-package"}, parts...)
	return filepath.Join(all...)
}

func TestCompileIsDeterministicAndBounded(t *testing.T) {
	descriptor, err := LoadCatalogDescriptor(fixturePath("catalog-descriptor.json"))
	if err != nil {
		t.Fatal(err)
	}
	input, err := LoadCanonicalInput(fixturePath("canonical-input.json"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := Compile(descriptor, input, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Compile(descriptor, input, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if first.PackageSHA256 != second.PackageSHA256 {
		t.Fatalf("package digest changed: %s != %s", first.PackageSHA256, second.PackageSHA256)
	}
	firstBytes, _ := os.ReadFile(first.ProjectionsPath)
	secondBytes, _ := os.ReadFile(second.ProjectionsPath)
	if string(firstBytes) != string(secondBytes) {
		t.Fatal("projection bytes changed across identical compiles")
	}
	if len(first.Projections.Candidates) != descriptor.RetrievableCandidateCount {
		t.Fatalf("projection count=%d", len(first.Projections.Candidates))
	}
	if strings.Contains(string(firstBytes), "hidden-record") || strings.Contains(string(firstBytes), "Hidden Full Catalog Record") {
		t.Fatal("non-retrievable full catalog record leaked into projection package")
	}
	if first.Projections.Candidates[0].CandidateID != "a-tie" || first.Projections.Candidates[len(first.Projections.Candidates)-1].CandidateID != "z-tie" {
		t.Fatal("candidate ordering is not canonical")
	}
}

func TestLoadPackageRejectsTampering(t *testing.T) {
	descriptor, _ := LoadCatalogDescriptor(fixturePath("catalog-descriptor.json"))
	input, _ := LoadCanonicalInput(fixturePath("canonical-input.json"))
	pkg, err := Compile(descriptor, input, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(pkg.Directory, "projections.json")
	raw, _ := os.ReadFile(path)
	raw[len(raw)/2] ^= 1
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPackage(pkg.Directory); err == nil {
		t.Fatal("tampered package was accepted")
	}
}

func TestCompileRejectsCoverageMismatch(t *testing.T) {
	descriptor, _ := LoadCatalogDescriptor(fixturePath("catalog-descriptor.json"))
	input, _ := LoadCanonicalInput(fixturePath("canonical-input.json"))
	descriptor.RetrievableCandidateIDsSHA256 = strings.Repeat("2", 64)
	if _, err := Compile(descriptor, input, t.TempDir()); err == nil || !strings.Contains(err.Error(), "coverage checksum") {
		t.Fatalf("expected coverage error, got %v", err)
	}
}
