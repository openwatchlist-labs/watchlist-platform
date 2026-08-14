package scoringactivation

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestCheckedInActivationRecordsUseRelativePaths is a mechanical guard
// against the failure mode found in PR #119: cmd/scoring-activation activate
// baking a filepath.Abs()-resolved, machine-specific path into a committed
// activation record's catalog_package_path / package_path / policy.path
// fields. Such a record loads on the machine that generated it (resolvePath
// returns an already-absolute path unchanged) and silently breaks
// everywhere else, including CI. It ran as part of `go test -race
// -count=1 ./...`, already required by run-ci.sh, so it needs no separate
// CI gate wiring.
func TestCheckedInActivationRecordsUseRelativePaths(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	roots := []string{
		filepath.Join(repoRoot, "test", "fixtures"),
		filepath.Join(repoRoot, "configs"),
	}
	checked := 0
	for _, root := range roots {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			var probe struct {
				SchemaVersion string `json:"schema_version"`
			}
			if json.Unmarshal(raw, &probe) != nil || probe.SchemaVersion != ActivationSchemaV1 {
				return nil
			}
			var activation Activation
			if err := json.Unmarshal(raw, &activation); err != nil {
				t.Errorf("%s: decode activation record: %v", path, err)
				return nil
			}
			checked++
			for field, value := range map[string]string{
				"catalog.catalog_package_path": activation.Catalog.CatalogPackagePath,
				"projection.package_path":      activation.Projection.PackagePath,
				"policy.path":                  activation.Policy.Path,
			} {
				if value != "" && filepath.IsAbs(value) {
					t.Errorf("%s: %s is an absolute path (%q) -- activation records must use paths relative to the state directory (see scoringactivation.resolvePath)", path, field, value)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if checked == 0 {
		t.Fatal("no checked-in activation records found under test/fixtures or configs -- test is not exercising anything; update the search roots")
	}
}
