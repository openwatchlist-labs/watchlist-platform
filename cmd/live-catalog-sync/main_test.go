package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogsource"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacadvanced"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacsource"
)

func TestVerifyManifestBytesSupportsBothManifestContracts(t *testing.T) {
	root := filepath.Join("..", "..", "test")

	ofacPath := filepath.Join(root, "fixtures", "ofac", "advanced", "sdn-advanced-fixture.xml")
	ofacData, err := os.ReadFile(ofacPath)
	if err != nil {
		t.Fatal(err)
	}
	acquired, err := ofacadvanced.AcquireLocal(
		ofacPath,
		ofacadvanced.OfficialSDNXMLURL,
		time.Date(2026, 7, 14, 15, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ofacadvanced.Parse(acquired)
	if err != nil {
		t.Fatal(err)
	}
	ofacManifest, err := json.Marshal(result.Snapshot.SourceManifest)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := verifyManifestBytes(ofacManifest, ofacData)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.Valid || receipt.SchemaVersion != ofacsource.ManifestSchemaVersion || receipt.ManifestID != result.Snapshot.SourceManifest.ManifestID || receipt.ManifestChecksum != "" {
		t.Fatalf("unexpected OFAC verification receipt: %+v", receipt)
	}

	providerManifest, err := os.ReadFile(filepath.Join(root, "golden", "live-source", "opensanctions-source-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	providerData, err := os.ReadFile(filepath.Join(root, "fixtures", "live-source", "opensanctions-us-ofac-sdn.ftm.json"))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err = verifyManifestBytes(providerManifest, providerData)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.Valid || receipt.SchemaVersion != catalogsource.ManifestSchemaVersion || receipt.ManifestChecksum == "" {
		t.Fatalf("unexpected catalog-source verification receipt: %+v", receipt)
	}
}

func TestBuildOpenSanctionsProjectionPreservesManifestAndUsesCurrentAdapter(t *testing.T) {
	root := filepath.Join("..", "..", "test")
	manifestData, err := os.ReadFile(filepath.Join(root, "golden", "live-source", "opensanctions-source-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "fixtures", "live-source", "opensanctions-us-ofac-sdn.ftm.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, snapshot, catalog, err := buildOpenSanctionsProjection(manifestData, data)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ManifestID != "catalog_source_manifest_030f43631491e5215a06a77e" {
		t.Fatalf("source manifest changed during re-projection: %+v", manifest)
	}
	if snapshot.EntityCount != 3 || catalog.RecordCount != 3 {
		t.Fatalf("unexpected projection counts: snapshot=%d catalog=%d", snapshot.EntityCount, catalog.RecordCount)
	}
	if catalog.AdapterVersion != "opensanctions-ftm-adapter/v0.1.2" {
		t.Fatalf("unexpected adapter version: %s", catalog.AdapterVersion)
	}
	goldenSnapshot := filepath.Join(root, "golden", "live-source", "opensanctions-provider-snapshot.json")
	goldenCatalog := filepath.Join(root, "golden", "live-source", "opensanctions-provider-catalog.json")
	wantSnapshot, err := os.ReadFile(goldenSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	wantCatalog, err := os.ReadFile(goldenCatalog)
	if err != nil {
		t.Fatal(err)
	}
	gotSnapshot, _ := json.MarshalIndent(snapshot, "", "  ")
	gotSnapshot = append(gotSnapshot, '\n')
	gotCatalog, _ := json.MarshalIndent(catalog, "", "  ")
	gotCatalog = append(gotCatalog, '\n')
	if string(gotSnapshot) != string(wantSnapshot) {
		t.Fatal("re-projected snapshot differs from golden")
	}
	if string(gotCatalog) != string(wantCatalog) {
		t.Fatal("re-projected catalog differs from golden")
	}
}

func TestBuildOpenSanctionsProjectionRejectsWrongSourceAndTamperedData(t *testing.T) {
	root := filepath.Join("..", "..", "test")
	manifestData, err := os.ReadFile(filepath.Join(root, "golden", "live-source", "opensanctions-source-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "fixtures", "live-source", "opensanctions-us-ofac-sdn.ftm.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := buildOpenSanctionsProjection(manifestData, append(append([]byte(nil), data...), 'x')); err == nil {
		t.Fatal("tampered FtM bytes accepted for re-projection")
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["source_kind"] = "other"
	manifest["manifest_id"] = "broken"
	manifest["manifest_checksum"] = "broken"
	bad, _ := json.Marshal(manifest)
	if _, _, _, err := buildOpenSanctionsProjection(bad, data); err == nil {
		t.Fatal("non-OpenSanctions manifest accepted")
	}
}

func TestVerifyManifestBytesRejectsUnknownTamperedAndUnsupportedManifests(t *testing.T) {
	root := filepath.Join("..", "..", "test")
	path := filepath.Join(root, "fixtures", "ofac", "sdn", "sdn-fixture.xml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	acquired, err := ofacsource.AcquireLocal(path, ofacsource.OfficialSDNXMLURL, time.Date(2026, 7, 14, 13, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := ofacsource.Parse(acquired)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(pkg.Manifest)
	if err != nil {
		t.Fatal(err)
	}

	var unknown map[string]any
	if err := json.Unmarshal(manifest, &unknown); err != nil {
		t.Fatal(err)
	}
	unknown["unexpected"] = true
	unknownManifest, _ := json.Marshal(unknown)
	if _, err := verifyManifestBytes(unknownManifest, data); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field was not rejected strictly: %v", err)
	}
	if _, err := verifyManifestBytes(manifest, append(append([]byte(nil), data...), 'x')); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("tampered data was not rejected: %v", err)
	}
	if _, err := verifyManifestBytes([]byte(`{"schema_version":"unknown/v1"}`), data); err == nil || !strings.Contains(err.Error(), "unsupported manifest") {
		t.Fatalf("unsupported schema was not rejected: %v", err)
	}
	if _, err := verifyManifestBytes(append(manifest, []byte(` {}`)...), data); err == nil {
		t.Fatal("trailing JSON was not rejected")
	}
}
