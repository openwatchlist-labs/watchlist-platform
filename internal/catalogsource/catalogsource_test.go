package catalogsource

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAcquireManifestAndIndex(t *testing.T) {
	root := filepath.Join("..", "..", "test", "fixtures", "live-source")
	metadataBytes, err := os.ReadFile(filepath.Join(root, "opensanctions-us-ofac-sdn.index.json"))
	if err != nil {
		t.Fatal(err)
	}
	resource, err := ParseOpenSanctionsIndex(metadataBytes, "https://data.opensanctions.org/datasets/latest/us_ofac_sdn/index.json", "us_ofac_sdn", "entities.ftm.json")
	if err != nil {
		t.Fatal(err)
	}
	if resource.DatasetID != "us_ofac_sdn" || resource.ChecksumAlgorithm != "sha256" || len(resource.Checksum) != 64 {
		t.Fatalf("unexpected resource: %+v", resource)
	}
	at := time.Date(2026, 7, 14, 12, 30, 0, 0, time.UTC)
	acquired, err := AcquireLocal(filepath.Join(root, "opensanctions-us-ofac-sdn.ftm.json"), resource.ResourceURL, resource.MediaType, AcquireOptions{AcquiredAt: at})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyUpstreamChecksum(acquired.Bytes, resource.ChecksumAlgorithm, resource.Checksum); err != nil {
		t.Fatal(err)
	}
	manifest, err := BuildManifest(acquired, ManifestOptions{SourceKind: "opensanctions_ftm", Authority: "OpenSanctions", DatasetID: resource.DatasetID, MetadataURL: "https://data.opensanctions.org/datasets/latest/us_ofac_sdn/index.json", UpstreamVersion: resource.Version, UpstreamChecksumAlgorithm: resource.ChecksumAlgorithm, UpstreamChecksum: resource.Checksum, LicenseMode: LicenseNonCommercial, LicenseReference: "https://www.opensanctions.org/licensing/", LocalDataFile: "source/entities.ftm.json"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifest(manifest); err != nil {
		t.Fatal(err)
	}
	second, err := BuildManifest(acquired, ManifestOptions{SourceKind: "opensanctions_ftm", Authority: "OpenSanctions", DatasetID: resource.DatasetID, MetadataURL: "https://data.opensanctions.org/datasets/latest/us_ofac_sdn/index.json", UpstreamVersion: resource.Version, UpstreamChecksumAlgorithm: resource.ChecksumAlgorithm, UpstreamChecksum: resource.Checksum, LicenseMode: LicenseNonCommercial, LicenseReference: "https://www.opensanctions.org/licensing/", LocalDataFile: "source/entities.ftm.json"})
	if err != nil || second != manifest {
		t.Fatal("manifest generation is not deterministic")
	}
	tampered := manifest
	tampered.DatasetID = "tampered"
	if ValidateManifest(tampered) == nil {
		t.Fatal("tampered manifest accepted")
	}
	if VerifyUpstreamChecksum(append([]byte(nil), acquired.Bytes...), "sha256", strings.Repeat("0", 64)) == nil {
		t.Fatal("bad checksum accepted")
	}
}

func TestSourceSafetyGates(t *testing.T) {
	bad := []string{"http://data.opensanctions.org/x", "https://example.com/x", "https://user@example.com/x", "https://data.opensanctions.org/x#fragment"}
	for _, raw := range bad {
		if _, err := ValidateURL(raw); err == nil {
			t.Fatalf("unsafe URL accepted: %s", raw)
		}
	}
	if _, err := ValidateURL("https://data.opensanctions.org/datasets/latest/us_ofac_sdn/index.json"); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(bytes.NewReader(nil), 10); err == nil {
		t.Fatal("empty source accepted")
	}
	if _, err := readBounded(bytes.NewReader([]byte("123456")), 5); err == nil {
		t.Fatal("oversized source accepted")
	}
}
