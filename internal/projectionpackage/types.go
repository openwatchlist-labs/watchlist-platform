package projectionpackage

import "github.com/openwatchlist-labs/watchlist-platform/internal/candidatescoring"

const (
	CatalogDescriptorSchemaV1  = "openwatchlist.catalog-package-descriptor.v1"
	CanonicalInputSchemaV1     = "openwatchlist.canonical-projection-input.v1"
	ManifestSchemaV1           = "openwatchlist.scoring-projection-package-manifest.v1"
	ProjectionRegistrySchemaV1 = "openwatchlist.candidate-projection-registry.v1"
)

// CatalogDescriptor is the bounded metadata emitted beside a catalog mmap package.
type CatalogDescriptor struct {
	SchemaVersion                 string `json:"schema_version"`
	Provider                      string `json:"provider"`
	CatalogID                     string `json:"catalog_id"`
	ComponentID                   string `json:"component_id"`
	ComponentVersion              string `json:"component_version"`
	CatalogPackageSHA256          string `json:"catalog_package_sha256"`
	CatalogPackagePath            string `json:"catalog_package_path"`
	NormalizationProfile          string `json:"normalization_profile"`
	RecordCount                   int    `json:"record_count"`
	RetrievableCandidateCount     int    `json:"retrievable_candidate_count"`
	RetrievableCandidateIDsSHA256 string `json:"retrievable_candidate_ids_sha256"`
}

// CanonicalInput is a deterministic projection feed derived from canonical catalog records.
type CanonicalInput struct {
	SchemaVersion        string         `json:"schema_version"`
	Provider             string         `json:"provider"`
	CatalogID            string         `json:"catalog_id"`
	ComponentID          string         `json:"component_id"`
	ComponentVersion     string         `json:"component_version"`
	CatalogPackageSHA256 string         `json:"catalog_package_sha256"`
	NormalizationProfile string         `json:"normalization_profile"`
	Records              []SourceRecord `json:"records"`
}

// SourceRecord contains only fields allowed in the bounded scoring projection.
type SourceRecord struct {
	CandidateID  string                        `json:"candidate_id"`
	Retrievable  bool                          `json:"retrievable"`
	Names        []string                      `json:"names,omitempty"`
	Identifiers  []candidatescoring.Identifier `json:"identifiers,omitempty"`
	Countries    []string                      `json:"countries,omitempty"`
	DatesOfBirth []string                      `json:"dates_of_birth,omitempty"`
	EntityType   string                        `json:"entity_type,omitempty"`
}

// Manifest binds a projection payload to one exact catalog package.
type Manifest struct {
	SchemaVersion        string `json:"schema_version"`
	Provider             string `json:"provider"`
	CatalogID            string `json:"catalog_id"`
	ComponentID          string `json:"component_id"`
	ComponentVersion     string `json:"component_version"`
	CatalogPackageSHA256 string `json:"catalog_package_sha256"`
	NormalizationProfile string `json:"normalization_profile"`
	SourceRecordCount    int    `json:"source_record_count"`
	ProjectionCount      int    `json:"projection_count"`
	CandidateIDsSHA256   string `json:"candidate_ids_sha256"`
	ProjectionsSHA256    string `json:"projections_sha256"`
	Compiler             string `json:"compiler"`
}

// ProjectionDocument stays byte-compatible with the accepted Phase 8D registry loader.
type ProjectionDocument struct {
	SchemaVersion string                       `json:"schema_version"`
	Candidates    []candidatescoring.Candidate `json:"candidates"`
}

// Package is a fully verified immutable projection package.
type Package struct {
	Directory       string
	PackageSHA256   string
	Manifest        Manifest
	Projections     ProjectionDocument
	ManifestPath    string
	ProjectionsPath string
}
