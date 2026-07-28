package runtimecataloginput

const (
	SchemaVersion        = "runtime-catalog-input/v1alpha1"
	ExporterVersion      = "runtime-catalog-input-exporter/v0.1.0"
	NormalizationProfile = "openwatchlist-runtime-normalization/ascii-v1"
	Magic                = "OWCINPUT1"
)

type Metadata struct {
	SchemaVersion        string `json:"schema_version"`
	ExporterVersion      string `json:"exporter_version"`
	ComponentID          string `json:"component_id"`
	CatalogID            string `json:"catalog_id"`
	CatalogVersion       string `json:"catalog_version"`
	CatalogChecksum      string `json:"catalog_checksum"`
	CatalogMode          string `json:"catalog_mode"`
	SourceManifestID     string `json:"source_manifest_id"`
	SourceSchemaVersion  string `json:"source_schema_version"`
	NormalizationProfile string `json:"normalization_profile"`
}

type Record struct {
	RecordID    string `json:"record_id"`
	EntityType  string `json:"entity_type"`
	PrimaryName string `json:"primary_name"`
}

type Name struct {
	RecordID string `json:"record_id"`
	Kind     string `json:"kind"`
	Value    string `json:"value"`
}

type Identifier struct {
	RecordID string `json:"record_id"`
	Type     string `json:"type"`
	Value    string `json:"value"`
}

type Input struct {
	Metadata    Metadata     `json:"metadata"`
	Records     []Record     `json:"records"`
	Names       []Name       `json:"names"`
	Identifiers []Identifier `json:"identifiers"`
}

type Summary struct {
	SchemaVersion   string `json:"schema_version"`
	ExporterVersion string `json:"exporter_version"`
	ComponentID     string `json:"component_id"`
	CatalogID       string `json:"catalog_id"`
	CatalogVersion  string `json:"catalog_version"`
	CatalogChecksum string `json:"catalog_checksum"`
	CatalogMode     string `json:"catalog_mode"`
	RecordCount     int    `json:"record_count"`
	NameCount       int    `json:"name_count"`
	IdentifierCount int    `json:"identifier_count"`
	ContentSHA256   string `json:"content_sha256"`
}
