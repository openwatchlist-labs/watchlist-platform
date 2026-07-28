package runtimecataloginput

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestExportOfficialAndProviderDeterministic(t *testing.T) {
	root := filepath.Join("..", "..")
	cases := []struct{ path, component, mode string }{
		{filepath.Join(root, "test/golden/ofac-advanced/ofac-sdn-catalog.json"), "catalog_component_ed835720fdb2b3a505927488", "official_list"},
		{filepath.Join(root, "test/golden/live-source/opensanctions-provider-catalog.json"), "catalog_component_da31b8f413b14c5fcfccdb4a", "provider"},
	}
	for _, tc := range cases {
		data, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		first, summary, err := Export(bytes.NewReader(data), tc.component)
		if err != nil {
			t.Fatal(err)
		}
		second, summary2, err := Export(bytes.NewReader(data), tc.component)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, second) || summary != summary2 {
			t.Fatal("export is not deterministic")
		}
		parsed, err := Parse(bytes.NewReader(first))
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Metadata.CatalogMode != tc.mode || parsed.Metadata.ComponentID != tc.component {
			t.Fatalf("unexpected metadata: %+v", parsed.Metadata)
		}
		if summary.RecordCount != len(parsed.Records) || summary.NameCount != len(parsed.Names) || summary.IdentifierCount != len(parsed.Identifiers) {
			t.Fatal("summary count mismatch")
		}
	}
}

func TestParseRejectsCaseChangedMagic(t *testing.T) {
	_, err := Parse(bytes.NewBufferString("owcinput1\nE\t0\t0\t0\n"))
	if err == nil {
		t.Fatal("expected invalid magic")
	}
}
