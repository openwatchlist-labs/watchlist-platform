package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogsource"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacadvanced"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacsource"
	"github.com/openwatchlist-labs/watchlist-platform/internal/providerentity"
)

const (
	ofACLicenseReference          = "https://ofac.treasury.gov/sanctions-list-service"
	openSanctionsLicenseReference = "https://www.opensanctions.org/licensing/"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: live-catalog-sync <ofac|opensanctions|reproject-opensanctions|verify> [flags]")
	}
	switch os.Args[1] {
	case "ofac":
		syncOFAC(os.Args[2:])
	case "ofac-legacy-fixture":
		syncLegacyOFACFixture(os.Args[2:])
	case "opensanctions":
		syncOpenSanctions(os.Args[2:])
	case "reproject-opensanctions":
		reprojectOpenSanctions(os.Args[2:])
	case "verify":
		verify(os.Args[2:])
	default:
		fatalf("unsupported subcommand %q", os.Args[1])
	}
}

func syncOFAC(args []string) {
	fs := flag.NewFlagSet("ofac", flag.ExitOnError)
	input := fs.String("input", "", "local SDN Advanced XML fixture; omit for official HTTPS download")
	sourceURL := fs.String("source-url", ofacadvanced.OfficialSDNXMLURL, "official OFAC SDN Advanced XML URL")
	acquiredAtRaw := fs.String("acquired-at", "", "RFC3339 acquisition time")
	outputDir := fs.String("output-dir", "var/live-catalogs/ofac-sdn", "ignored local output directory")
	legacyCatalogPath := fs.String("legacy-catalog", "", "optional legacy catalog used only to emit a migration parity report")
	fs.Parse(args)
	mustNoArgs(fs)
	acquiredAt := parseTime(*acquiredAtRaw)

	var acquired ofacadvanced.Acquired
	var err error
	if *input == "" {
		acquired, err = ofacadvanced.AcquireHTTP(context.Background(), *sourceURL, acquiredAt)
	} else {
		acquired, err = ofacadvanced.AcquireLocal(*input, *sourceURL, acquiredAt)
	}
	check(err, "acquire OFAC Advanced XML source")
	result, err := ofacadvanced.Parse(acquired)
	check(err, "parse OFAC Advanced XML source")
	catalog, err := ofaccatalog.Project(result.Package)
	check(err, "project OFAC Advanced XML catalog")

	check(os.MkdirAll(filepath.Join(*outputDir, "source"), 0o755), "create output directory")
	check(writeAtomic(filepath.Join(*outputDir, "source", "SDN_ADVANCED.XML"), acquired.Bytes, 0o600), "write OFAC Advanced XML source")
	check(writeJSONAtomic(filepath.Join(*outputDir, "source-manifest.json"), result.Snapshot.SourceManifest), "write OFAC Advanced XML manifest")
	check(writeJSONAtomic(filepath.Join(*outputDir, "ofac-advanced-canonical.json"), result.Snapshot), "write OFAC Advanced canonical snapshot")
	check(writeJSONAtomic(filepath.Join(*outputDir, "ofac-sdn-catalog.json"), catalog), "write OFAC catalog")

	var parity *ofacadvanced.ParityReport
	if strings.TrimSpace(*legacyCatalogPath) != "" {
		legacyFile, err := os.Open(*legacyCatalogPath)
		check(err, "open legacy OFAC catalog")
		legacy, err := ofaccatalog.Load(legacyFile)
		legacyFile.Close()
		check(err, "load legacy OFAC catalog")
		report, err := ofacadvanced.CompareCatalogs(catalog, legacy)
		check(err, "compare Advanced and legacy OFAC catalogs")
		check(writeJSONAtomic(filepath.Join(*outputDir, "advanced-legacy-parity.json"), report), "write OFAC Advanced parity report")
		parity = &report
	}

	receipt := map[string]any{
		"source":            "ofac",
		"source_format":     ofacadvanced.SourceFormat,
		"xml_version":       ofacadvanced.AdvancedXMLVersion,
		"parser_version":    ofacadvanced.ParserVersion,
		"live_download":     *input == "",
		"output_dir":        *outputDir,
		"record_count":      catalog.RecordCount,
		"source_stats":      result.Snapshot.SourceStats,
		"source_sha256":     result.Snapshot.SourceManifest.ContentSHA256,
		"snapshot_checksum": result.Snapshot.SnapshotChecksum,
		"catalog_checksum":  catalog.CatalogChecksum,
		"license_reference": ofACLicenseReference,
	}
	if parity != nil {
		receipt["parity_summary"] = parity.Summary
	}
	encode(receipt)
}

// syncLegacyOFACFixture is retained only for deterministic Phase 2/7 regression
// fixtures. It is intentionally omitted from public documentation and is not a
// supported production acquisition path.
func syncLegacyOFACFixture(args []string) {
	fs := flag.NewFlagSet("ofac-legacy-fixture", flag.ExitOnError)
	input := fs.String("input", "", "local legacy SDN.XML fixture")
	sourceURL := fs.String("source-url", ofacsource.OfficialSDNXMLURL, "legacy fixture source URL")
	acquiredAtRaw := fs.String("acquired-at", "", "RFC3339 acquisition time")
	outputDir := fs.String("output-dir", "", "fixture output directory")
	fs.Parse(args)
	mustNoArgs(fs)
	if *input == "" || *outputDir == "" {
		fatalf("--input and --output-dir are required")
	}
	acquired, err := ofacsource.AcquireLocal(*input, *sourceURL, parseTime(*acquiredAtRaw))
	check(err, "acquire legacy OFAC fixture")
	pkg, err := ofacsource.Parse(acquired)
	check(err, "parse legacy OFAC fixture")
	catalog, err := ofaccatalog.Project(pkg)
	check(err, "project legacy OFAC fixture")
	check(os.MkdirAll(filepath.Join(*outputDir, "source"), 0o755), "create fixture output directory")
	check(writeAtomic(filepath.Join(*outputDir, "source", "SDN.XML"), acquired.Bytes, 0o600), "write legacy fixture")
	check(writeJSONAtomic(filepath.Join(*outputDir, "source-manifest.json"), pkg.Manifest), "write legacy fixture manifest")
	check(writeJSONAtomic(filepath.Join(*outputDir, "ofac-sdn-catalog.json"), catalog), "write legacy fixture catalog")
	encode(map[string]any{"source": "ofac", "source_format": "legacy_fixture_only", "live_download": false, "output_dir": *outputDir, "record_count": catalog.RecordCount, "source_sha256": pkg.Manifest.ContentSHA256, "catalog_checksum": catalog.CatalogChecksum, "license_reference": ofACLicenseReference})
}

func syncOpenSanctions(args []string) {
	fs := flag.NewFlagSet("opensanctions", flag.ExitOnError)
	dataset := fs.String("dataset", "us_ofac_sdn", "OpenSanctions source-scoped dataset")
	resourceName := fs.String("resource", "entities.ftm.json", "bulk resource file")
	metadataInput := fs.String("metadata-input", "", "local metadata index fixture; omit for HTTPS download")
	input := fs.String("input", "", "local FtM JSON-lines fixture; omit for HTTPS download")
	metadataURL := fs.String("metadata-url", "", "dataset metadata index URL")
	dataURL := fs.String("data-url", "", "bulk data URL override")
	licenseModeRaw := fs.String("license-mode", "", "required: noncommercial or commercial")
	tokenEnv := fs.String("token-env", "OPENSANCTIONS_DELIVERY_TOKEN", "commercial delivery-token environment variable")
	acquiredAtRaw := fs.String("acquired-at", "", "RFC3339 acquisition time")
	outputDir := fs.String("output-dir", "var/live-catalogs/opensanctions-us-ofac-sdn", "ignored local output directory")
	maxBytes := fs.Int64("max-bytes", catalogsource.DefaultMaxBytes, "maximum metadata/data bytes")
	fs.Parse(args)
	mustNoArgs(fs)
	licenseMode, token := parseLicenseMode(*licenseModeRaw, *tokenEnv)
	acquiredAt := parseTime(*acquiredAtRaw)
	if *metadataURL == "" {
		*metadataURL = "https://data.opensanctions.org/datasets/latest/" + *dataset + "/index.json"
	}

	metadataOptions := catalogsource.AcquireOptions{AcquiredAt: acquiredAt, MaxBytes: 16 << 20, Accept: "application/json", BearerToken: token}
	var metadata catalogsource.Acquired
	var err error
	if *metadataInput == "" {
		metadata, err = catalogsource.AcquireHTTPS(context.Background(), *metadataURL, metadataOptions)
	} else {
		metadata, err = catalogsource.AcquireLocal(*metadataInput, *metadataURL, "application/json", metadataOptions)
	}
	check(err, "acquire OpenSanctions metadata")
	resource, err := catalogsource.ParseOpenSanctionsIndex(metadata.Bytes, *metadataURL, *dataset, *resourceName)
	check(err, "parse OpenSanctions metadata")
	if *dataURL != "" {
		resource.ResourceURL = *dataURL
	}

	dataOptions := catalogsource.AcquireOptions{AcquiredAt: acquiredAt, MaxBytes: *maxBytes, Accept: "application/x-ndjson,application/json;q=0.9", BearerToken: token}
	var data catalogsource.Acquired
	if *input == "" {
		data, err = catalogsource.AcquireHTTPS(context.Background(), resource.ResourceURL, dataOptions)
	} else {
		data, err = catalogsource.AcquireLocal(*input, resource.ResourceURL, resource.MediaType, dataOptions)
	}
	check(err, "acquire OpenSanctions FtM data")
	check(catalogsource.VerifyUpstreamChecksum(data.Bytes, resource.ChecksumAlgorithm, resource.Checksum), "verify OpenSanctions upstream checksum")

	manifest, err := catalogsource.BuildManifest(data, catalogsource.ManifestOptions{
		SourceKind: "opensanctions_ftm", Authority: "OpenSanctions", DatasetID: resource.DatasetID,
		MetadataURL: metadata.SourceURL, UpstreamVersion: resource.Version,
		UpstreamChecksumAlgorithm: resource.ChecksumAlgorithm, UpstreamChecksum: resource.Checksum,
		LicenseMode: licenseMode, LicenseReference: openSanctionsLicenseReference,
		LocalDataFile: filepath.Join("source", *resourceName),
	})
	check(err, "build source manifest")
	snapshot, err := providerentity.ImportFTM(bytes.NewReader(data.Bytes), providerentity.FTMImportOptions{
		DatasetID: resource.DatasetID, DatasetTitle: resource.DatasetTitle,
		SnapshotVersion: firstNonEmpty(resource.Version, acquiredAt.Format("2006-01-02")),
		SourceChecksum:  data.ContentSHA256, ProviderName: "opensanctions-" + resource.DatasetID,
	})
	check(err, "import OpenSanctions FtM")
	catalog, err := providerentity.ProjectFTM(snapshot)
	check(err, "project provider catalog")

	check(os.MkdirAll(filepath.Join(*outputDir, "source"), 0o755), "create output directory")
	check(writeAtomic(filepath.Join(*outputDir, "source", "index.json"), metadata.Bytes, 0o600), "write metadata index")
	check(writeAtomic(filepath.Join(*outputDir, "source", *resourceName), data.Bytes, 0o600), "write FtM source")
	check(writeJSONAtomic(filepath.Join(*outputDir, "source-manifest.json"), manifest), "write source manifest")
	check(writeJSONAtomic(filepath.Join(*outputDir, "provider-snapshot.json"), snapshot), "write provider snapshot")
	check(writeJSONAtomic(filepath.Join(*outputDir, "provider-catalog.json"), catalog), "write provider catalog")
	encode(map[string]any{
		"source": "opensanctions", "dataset": resource.DatasetID, "upstream_version": resource.Version,
		"live_download": *input == "" && *metadataInput == "", "license_mode": licenseMode,
		"output_dir": *outputDir, "record_count": catalog.RecordCount,
		"source_sha256": manifest.ContentSHA256, "catalog_checksum": catalog.CatalogChecksum,
		"license_reference": openSanctionsLicenseReference,
	})
}

func reprojectOpenSanctions(args []string) {
	fs := flag.NewFlagSet("reproject-opensanctions", flag.ExitOnError)
	manifestPath := fs.String("manifest", "", "existing OpenSanctions catalog-source manifest")
	dataPath := fs.String("data", "", "existing verified FtM JSON-lines file")
	outputDir := fs.String("output-dir", "", "directory containing provider-snapshot.json and provider-catalog.json")
	fs.Parse(args)
	mustNoArgs(fs)
	if *manifestPath == "" || *dataPath == "" || *outputDir == "" {
		fatalf("--manifest, --data, and --output-dir are required")
	}
	manifestData, err := os.ReadFile(*manifestPath)
	check(err, "read OpenSanctions manifest")
	data, err := os.ReadFile(*dataPath)
	check(err, "read OpenSanctions FtM data")
	manifest, snapshot, catalog, err := buildOpenSanctionsProjection(manifestData, data)
	check(err, "reproject OpenSanctions FtM")
	check(os.MkdirAll(*outputDir, 0o755), "create projection output directory")
	check(writeJSONAtomic(filepath.Join(*outputDir, "provider-snapshot.json"), snapshot), "write provider snapshot")
	check(writeJSONAtomic(filepath.Join(*outputDir, "provider-catalog.json"), catalog), "write provider catalog")
	encode(map[string]any{
		"source":               "opensanctions",
		"dataset":              manifest.DatasetID,
		"reprojected":          true,
		"live_download":        false,
		"manifest_id":          manifest.ManifestID,
		"source_sha256":        manifest.ContentSHA256,
		"adapter_version":      catalog.AdapterVersion,
		"record_count":         catalog.RecordCount,
		"catalog_checksum":     catalog.CatalogChecksum,
		"output_dir":           *outputDir,
		"source_manifest_kept": true,
	})
}

func buildOpenSanctionsProjection(manifestData, data []byte) (catalogsource.Manifest, providerentity.Snapshot, providerentity.Catalog, error) {
	var manifest catalogsource.Manifest
	if err := decodeStrictJSON(manifestData, &manifest); err != nil {
		return catalogsource.Manifest{}, providerentity.Snapshot{}, providerentity.Catalog{}, fmt.Errorf("decode catalog-source manifest: %w", err)
	}
	if err := catalogsource.ValidateManifest(manifest); err != nil {
		return catalogsource.Manifest{}, providerentity.Snapshot{}, providerentity.Catalog{}, fmt.Errorf("validate catalog-source manifest: %w", err)
	}
	if manifest.SourceKind != "opensanctions_ftm" || manifest.Authority != "OpenSanctions" {
		return catalogsource.Manifest{}, providerentity.Snapshot{}, providerentity.Catalog{}, fmt.Errorf("manifest is not an OpenSanctions FtM source")
	}
	if providerentity.SHA256Hex(data) != manifest.ContentSHA256 || int64(len(data)) != manifest.ContentLength {
		return catalogsource.Manifest{}, providerentity.Snapshot{}, providerentity.Catalog{}, fmt.Errorf("data does not match catalog-source manifest")
	}
	if err := catalogsource.VerifyUpstreamChecksum(data, manifest.UpstreamChecksumAlgorithm, manifest.UpstreamChecksum); err != nil {
		return catalogsource.Manifest{}, providerentity.Snapshot{}, providerentity.Catalog{}, fmt.Errorf("verify upstream checksum: %w", err)
	}
	version := firstNonEmpty(manifest.UpstreamVersion, manifest.AcquiredAt.UTC().Format("2006-01-02"))
	snapshot, err := providerentity.ImportFTM(bytes.NewReader(data), providerentity.FTMImportOptions{
		DatasetID:       manifest.DatasetID,
		SnapshotVersion: version,
		SourceChecksum:  manifest.ContentSHA256,
		ProviderName:    "opensanctions-" + manifest.DatasetID,
	})
	if err != nil {
		return catalogsource.Manifest{}, providerentity.Snapshot{}, providerentity.Catalog{}, err
	}
	catalog, err := providerentity.ProjectFTM(snapshot)
	if err != nil {
		return catalogsource.Manifest{}, providerentity.Snapshot{}, providerentity.Catalog{}, err
	}
	return manifest, snapshot, catalog, nil
}

type verificationReceipt struct {
	Valid            bool   `json:"valid"`
	SchemaVersion    string `json:"schema_version"`
	ManifestID       string `json:"manifest_id"`
	ManifestChecksum string `json:"manifest_checksum,omitempty"`
	ContentSHA256    string `json:"content_sha256"`
	ContentLength    int64  `json:"content_length"`
}

func verify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	manifestPath := fs.String("manifest", "", "OFAC or catalog-source manifest JSON")
	dataPath := fs.String("data", "", "downloaded data file")
	fs.Parse(args)
	mustNoArgs(fs)
	if *manifestPath == "" || *dataPath == "" {
		fatalf("--manifest and --data are required")
	}
	manifestData, err := os.ReadFile(*manifestPath)
	check(err, "read manifest")
	data, err := os.ReadFile(*dataPath)
	check(err, "read data")
	receipt, err := verifyManifestBytes(manifestData, data)
	check(err, "verify manifest")
	encode(receipt)
}

func verifyManifestBytes(manifestData, data []byte) (verificationReceipt, error) {
	var envelope struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(manifestData, &envelope); err != nil {
		return verificationReceipt{}, fmt.Errorf("decode manifest envelope: %w", err)
	}
	switch envelope.SchemaVersion {
	case catalogsource.ManifestSchemaVersion:
		var manifest catalogsource.Manifest
		if err := decodeStrictJSON(manifestData, &manifest); err != nil {
			return verificationReceipt{}, fmt.Errorf("decode catalog-source manifest: %w", err)
		}
		if err := catalogsource.ValidateManifest(manifest); err != nil {
			return verificationReceipt{}, fmt.Errorf("validate catalog-source manifest: %w", err)
		}
		if providerentity.SHA256Hex(data) != manifest.ContentSHA256 || int64(len(data)) != manifest.ContentLength {
			return verificationReceipt{}, fmt.Errorf("data does not match catalog-source manifest")
		}
		if err := catalogsource.VerifyUpstreamChecksum(data, manifest.UpstreamChecksumAlgorithm, manifest.UpstreamChecksum); err != nil {
			return verificationReceipt{}, fmt.Errorf("verify upstream checksum: %w", err)
		}
		return verificationReceipt{Valid: true, SchemaVersion: manifest.SchemaVersion, ManifestID: manifest.ManifestID, ManifestChecksum: manifest.ManifestChecksum, ContentSHA256: manifest.ContentSHA256, ContentLength: manifest.ContentLength}, nil
	case ofacsource.ManifestSchemaVersion:
		var manifest ofacsource.SourceManifest
		if err := decodeStrictJSON(manifestData, &manifest); err != nil {
			return verificationReceipt{}, fmt.Errorf("decode OFAC source manifest: %w", err)
		}
		if err := ofacsource.ValidateManifest(manifest); err != nil {
			return verificationReceipt{}, fmt.Errorf("validate OFAC source manifest: %w", err)
		}
		if providerentity.SHA256Hex(data) != manifest.ContentSHA256 || int64(len(data)) != manifest.ContentLength {
			return verificationReceipt{}, fmt.Errorf("data does not match OFAC source manifest")
		}
		return verificationReceipt{Valid: true, SchemaVersion: manifest.SchemaVersion, ManifestID: manifest.ManifestID, ContentSHA256: manifest.ContentSHA256, ContentLength: manifest.ContentLength}, nil
	default:
		return verificationReceipt{}, fmt.Errorf("unsupported manifest schema_version %q", envelope.SchemaVersion)
	}
}

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return fmt.Errorf("unexpected trailing JSON value")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return fmt.Errorf("unexpected trailing JSON value")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func parseLicenseMode(raw, tokenEnv string) (catalogsource.LicenseMode, string) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "noncommercial":
		return catalogsource.LicenseNonCommercial, ""
	case "commercial":
		token := strings.TrimSpace(os.Getenv(tokenEnv))
		if token == "" {
			fatalf("commercial OpenSanctions synchronization requires %s", tokenEnv)
		}
		return catalogsource.LicenseCommercial, token
	default:
		fatalf("--license-mode is required and must be noncommercial or commercial")
		return "", ""
	}
}

func parseTime(raw string) time.Time {
	if strings.TrimSpace(raw) == "" {
		return time.Now().UTC()
	}
	value, err := time.Parse(time.RFC3339, raw)
	check(err, "parse --acquired-at")
	return value.UTC()
}
func mustNoArgs(fs *flag.FlagSet) {
	if fs.NArg() != 0 {
		fatalf("unexpected positional arguments: %v", fs.Args())
	}
}
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".openwatchlist-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
func writeJSONAtomic(path string, value any) error {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return err
	}
	return writeAtomic(path, buffer.Bytes(), 0o600)
}
func encode(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	check(encoder.Encode(value), "encode output")
}
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
func check(err error, action string) {
	if err != nil {
		fatalf("%s: %v", action, err)
	}
}
func fatalf(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(1) }
