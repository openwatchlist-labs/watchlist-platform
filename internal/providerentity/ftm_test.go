package providerentity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
)

func TestImportFTMAndCompare(t *testing.T) {
	root := filepath.Join("..", "..", "test")
	data, err := os.ReadFile(filepath.Join(root, "fixtures", "live-source", "opensanctions-us-ofac-sdn.ftm.json"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ImportFTM(strings.NewReader(string(data)), FTMImportOptions{DatasetID: "us_ofac_sdn", DatasetTitle: "Synthetic OpenSanctions OFAC SDN fixture", SnapshotVersion: "2026-07-14", SourceChecksum: SHA256Hex(data), ProviderName: "opensanctions-us_ofac_sdn"})
	if err != nil {
		t.Fatal(err)
	}
	goldenSnapshot := loadFTMSnapshot(t, filepath.Join(root, "golden", "live-source", "opensanctions-provider-snapshot.json"))
	if !jsonEqual(snapshot, goldenSnapshot) {
		t.Fatal("FtM snapshot differs from golden")
	}
	catalog, err := ProjectFTM(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	goldenCatalog := loadFTMCatalog(t, filepath.Join(root, "golden", "live-source", "opensanctions-provider-catalog.json"))
	if !jsonEqual(catalog, goldenCatalog) {
		t.Fatal("FtM catalog differs from golden")
	}
	if catalog.AdapterVersion != FTMAdapterVersion || catalog.RecordCount != 3 {
		t.Fatalf("unexpected catalog: %+v", catalog)
	}
	for _, entity := range catalog.Entities {
		if len(entity.SourceMemberships) != 2 || entity.SourceMemberships[0].SourceID != "ofac-sls" || entity.SourceMemberships[1].SourceID != "opensanctions" {
			t.Fatalf("lineage not preserved: %+v", entity.SourceMemberships)
		}
	}
	directFile, err := os.Open(filepath.Join(root, "golden", "ofac", "ofac-sdn-fixture.catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer directFile.Close()
	direct, err := ofaccatalog.Load(directFile)
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := Compare(catalog, direct)
	if err != nil {
		t.Fatal(err)
	}
	if comparison.Summary.LinkedRecords != 3 || comparison.Summary.ProviderOnly != 0 || comparison.Summary.DirectOnly != 0 || comparison.Summary.NameDifferences != 0 || comparison.Summary.TypeDifferences != 0 || comparison.Summary.ProgramDifferences != 0 {
		t.Fatalf("unexpected comparison: %+v", comparison.Summary)
	}
	second, err := ImportFTM(strings.NewReader(string(data)), FTMImportOptions{DatasetID: "us_ofac_sdn", SnapshotVersion: "2026-07-14", SourceChecksum: SHA256Hex(data), ProviderName: "opensanctions-us_ofac_sdn"})
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(snapshot, second) {
		t.Fatal("FtM replay is not deterministic")
	}
}

func TestImportFTMRejectsMalformedInput(t *testing.T) {
	options := FTMImportOptions{DatasetID: "us_ofac_sdn", SnapshotVersion: "2026-07-14", SourceChecksum: strings.Repeat("a", 64), ProviderName: "opensanctions-us_ofac_sdn"}
	if _, err := ImportFTM(strings.NewReader("not json\n"), options); err == nil {
		t.Fatal("malformed JSON accepted")
	}
	dup := `{"id":"Q1","schema":"Person","caption":"One","properties":{}}` + "\n" + `{"id":"Q1","schema":"Person","caption":"One","properties":{}}` + "\n"
	if _, err := ImportFTM(strings.NewReader(dup), options); err == nil {
		t.Fatal("duplicate entity accepted")
	}
}

func TestImportFTMUsesNumericOFACReferents(t *testing.T) {
	root := filepath.Join("..", "..", "test")
	data, err := os.ReadFile(filepath.Join(root, "fixtures", "live-source", "opensanctions-us-ofac-sdn-referents-only.ftm.json"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ImportFTM(strings.NewReader(string(data)), FTMImportOptions{
		DatasetID:       "us_ofac_sdn",
		SnapshotVersion: "2026-07-14-live-shape",
		SourceChecksum:  SHA256Hex(data),
		ProviderName:    "opensanctions-us_ofac_sdn",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Entities) != 2 {
		t.Fatalf("unexpected entity count: %d", len(snapshot.Entities))
	}
	first := snapshot.Entities[0]
	if first.EntityID != "NK-REFERENT-ONE" || len(first.SourceMemberships) != 2 {
		t.Fatalf("unexpected referent-only lineage: %+v", first)
	}
	if got := first.SourceMemberships[0]; got.SourceID != "ofac-sls" || got.SourceRecordID != "54742" {
		t.Fatalf("numeric OFAC referent not projected: %+v", got)
	}
	if got := first.SourceMemberships[1]; got.SourceID != "opensanctions" || got.SourceRecordID != "NK-REFERENT-ONE" {
		t.Fatalf("provider lineage not preserved: %+v", got)
	}
	second := snapshot.Entities[1]
	want := []string{"16033", "40950"}
	var got []string
	for _, membership := range second.SourceMemberships {
		if membership.SourceID == "ofac-sls" {
			got = append(got, membership.SourceRecordID)
		}
	}
	if !stringSliceEqual(got, want) {
		t.Fatalf("unexpected OFAC referent IDs: got %v want %v", got, want)
	}
}

func TestImportFTMMergesSanctionAndReferentMemberships(t *testing.T) {
	data := []byte(`{"id":"Q1","schema":"Company","caption":"One","datasets":["us_ofac_sdn"],"referents":["ofac-1001"],"properties":{"name":["One"],"recordId":["1001"]}}
{"id":"S1","schema":"Sanction","caption":"Sanction","datasets":["us_ofac_sdn"],"properties":{"entity":["Q1"],"recordId":["1001"],"program":["DEMO"]}}
`)
	snapshot, err := ImportFTM(strings.NewReader(string(data)), FTMImportOptions{
		DatasetID:       "us_ofac_sdn",
		SnapshotVersion: "2026-07-14-merge",
		SourceChecksum:  SHA256Hex(data),
		ProviderName:    "opensanctions-us_ofac_sdn",
	})
	if err != nil {
		t.Fatal(err)
	}
	memberships := snapshot.Entities[0].SourceMemberships
	if len(memberships) != 2 {
		t.Fatalf("duplicate source membership was not merged: %+v", memberships)
	}
	if got := memberships[0]; got.SourceRecordID != "1001" || !stringSliceEqual(got.Programs, []string{"DEMO"}) {
		t.Fatalf("merged OFAC membership lost program lineage: %+v", got)
	}
}

func TestImportFTMResolvesSanctionsThroughReferentsAndSeparatesProgramTaxonomy(t *testing.T) {
	root := filepath.Join("..", "..", "test")
	data, err := os.ReadFile(filepath.Join(root, "fixtures", "live-source", "opensanctions-us-ofac-sdn-program-taxonomy.ftm.json"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ImportFTM(strings.NewReader(string(data)), FTMImportOptions{
		DatasetID:       "us_ofac_sdn",
		SnapshotVersion: "2026-07-14-program-taxonomy",
		SourceChecksum:  SHA256Hex(data),
		ProviderName:    "opensanctions-us_ofac_sdn",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Entities) != 2 {
		t.Fatalf("unexpected entity count: %d", len(snapshot.Entities))
	}
	first := snapshot.Entities[0]
	if first.EntityID != "NK-PROGRAM-ONE" {
		t.Fatalf("unexpected first entity: %s", first.EntityID)
	}
	if got := findMembership(first.SourceMemberships, "ofac-sls", "54742"); got == nil || !stringSliceEqual(got.Programs, []string{"GLOMAG"}) {
		t.Fatalf("source program code not preserved through referent relation: %+v", got)
	}
	if got := first.Attributes["ofac_program_ids"]; got != "US-GLOMAG" {
		t.Fatalf("provider program taxonomy not preserved separately: %q", got)
	}
	second := snapshot.Entities[1]
	if second.EntityID != "NK-PROGRAM-TWO" {
		t.Fatalf("unexpected second entity: %s", second.EntityID)
	}
	if got := findMembership(second.SourceMemberships, "ofac-sls", "49834"); got == nil || !stringSliceEqual(got.Programs, []string{"RUSSIA-EO14024"}) {
		t.Fatalf("target referent fallback did not receive sanction programs: %+v", got)
	}
	if got := second.Attributes["ofac_program_ids"]; got != "US-RUSHAR" {
		t.Fatalf("provider program taxonomy fallback not preserved separately: %q", got)
	}
}

func TestImportFTMDoesNotResolveAmbiguousReferentRelations(t *testing.T) {
	data := []byte(`{"id":"NK-ONE","schema":"Organization","caption":"One","referents":["ofac-shared"],"properties":{"name":["One"]}}
{"id":"NK-TWO","schema":"Organization","caption":"Two","referents":["ofac-shared"],"properties":{"name":["Two"]}}
{"id":"S1","schema":"Sanction","caption":"Ambiguous","properties":{"entity":["ofac-shared"],"recordId":["1001"],"program":["DEMO"]}}
`)
	snapshot, err := ImportFTM(strings.NewReader(string(data)), FTMImportOptions{
		DatasetID:       "us_ofac_sdn",
		SnapshotVersion: "2026-07-14-ambiguous",
		SourceChecksum:  SHA256Hex(data),
		ProviderName:    "opensanctions-us_ofac_sdn",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, entity := range snapshot.Entities {
		if findMembership(entity.SourceMemberships, "ofac-sls", "1001") != nil {
			t.Fatalf("ambiguous source relation was linked to %s", entity.EntityID)
		}
	}
}

func findMembership(values []SourceMembership, sourceID, recordID string) *SourceMembership {
	for i := range values {
		if values[i].SourceID == sourceID && values[i].SourceRecordID == recordID {
			return &values[i]
		}
	}
	return nil
}

func loadFTMSnapshot(t *testing.T, path string) Snapshot {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value Snapshot
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSnapshot(value); err != nil {
		t.Fatal(err)
	}
	return value
}
func loadFTMCatalog(t *testing.T, path string) Catalog {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value Catalog
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCatalog(value); err != nil {
		t.Fatal(err)
	}
	return value
}
