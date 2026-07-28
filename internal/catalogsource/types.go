package catalogsource

import "time"

const (
	ManifestSchemaVersion = "catalog-source-manifest/v1alpha1"
	AcquirerVersion       = "catalog-source-acquirer/v0.1.0"
)

type AcquisitionMethod string

const (
	AcquisitionHTTPS AcquisitionMethod = "https"
	AcquisitionLocal AcquisitionMethod = "local_fixture"
)

type LicenseMode string

const (
	LicenseGovernmentPublic LicenseMode = "government_public_data"
	LicenseNonCommercial    LicenseMode = "cc_by_nc_4_0_noncommercial"
	LicenseCommercial       LicenseMode = "commercial_license"
)

type Acquired struct {
	Bytes         []byte
	SourceURL     string
	Method        AcquisitionMethod
	MediaType     string
	ETag          string
	LastModified  string
	AcquiredAt    time.Time
	ContentSHA256 string
	ContentLength int64
}

type Manifest struct {
	SchemaVersion             string            `json:"schema_version"`
	ManifestID                string            `json:"manifest_id"`
	ManifestChecksum          string            `json:"manifest_checksum"`
	SourceKind                string            `json:"source_kind"`
	Authority                 string            `json:"authority"`
	DatasetID                 string            `json:"dataset_id"`
	SourceURL                 string            `json:"source_url"`
	MetadataURL               string            `json:"metadata_url,omitempty"`
	AcquisitionMethod         AcquisitionMethod `json:"acquisition_method"`
	AcquiredAt                time.Time         `json:"acquired_at"`
	MediaType                 string            `json:"media_type"`
	ContentLength             int64             `json:"content_length"`
	ContentSHA256             string            `json:"content_sha256"`
	HTTPETag                  string            `json:"http_etag,omitempty"`
	HTTPLastModified          string            `json:"http_last_modified,omitempty"`
	UpstreamVersion           string            `json:"upstream_version,omitempty"`
	UpstreamChecksumAlgorithm string            `json:"upstream_checksum_algorithm,omitempty"`
	UpstreamChecksum          string            `json:"upstream_checksum,omitempty"`
	LicenseMode               LicenseMode       `json:"license_mode"`
	LicenseReference          string            `json:"license_reference"`
	LocalDataFile             string            `json:"local_data_file"`
	AcquirerVersion           string            `json:"acquirer_version"`
}

type OpenSanctionsResource struct {
	DatasetID         string
	DatasetTitle      string
	Version           string
	LastExport        string
	ResourceName      string
	ResourceURL       string
	MediaType         string
	Size              int64
	ChecksumAlgorithm string
	Checksum          string
}
