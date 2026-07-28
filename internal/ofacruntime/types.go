package ofacruntime

import (
	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
)

const (
	RuntimePayloadSchemaVersion  = "ofac-compiled-runtime/v1alpha1"
	PackageManifestSchemaVersion = "compiled-catalog-package-manifest/v1alpha1"
	PackageInfoSchemaVersion     = "compiled-catalog-package-info/v1alpha1"
	CompilerVersion              = "ofac-runtime-compiler/v0.1.0"
	PackageFormatVersion         = "owpcat/1"
	PackageMagic                 = "OWPCAT01"
)

type CompiledEntry struct {
	MatchRoute             canonical.MatchRoute              `json:"match_route"`
	NormalizedQuery        string                            `json:"normalized_query"`
	ProviderRecordID       string                            `json:"provider_record_id"`
	EntityType             canonical.CandidateType           `json:"entity_type"`
	PrimaryName            string                            `json:"primary_name"`
	MatchedValue           string                            `json:"matched_value"`
	NormalizedMatchedValue string                            `json:"normalized_matched_value"`
	ScoreBasisPoints       int                               `json:"score_basis_points"`
	Exact                  bool                              `json:"exact"`
	Attributes             map[string]string                 `json:"attributes,omitempty"`
	SourceAssertions       []matcherprovider.SourceAssertion `json:"source_assertions"`
}

type RuntimePayload struct {
	SchemaVersion    string                             `json:"schema_version"`
	CompilerVersion  string                             `json:"compiler_version"`
	Provider         matcherprovider.ProviderDescriptor `json:"provider"`
	SourceManifestID string                             `json:"source_manifest_id"`
	RecordCount      int                                `json:"record_count"`
	EntryCount       int                                `json:"entry_count"`
	Entries          []CompiledEntry                    `json:"entries"`
}

type PackageManifest struct {
	SchemaVersion       string                             `json:"schema_version"`
	PackageFormat       string                             `json:"package_format"`
	PackageID           string                             `json:"package_id"`
	CompilerVersion     string                             `json:"compiler_version"`
	PayloadSchema       string                             `json:"payload_schema_version"`
	Provider            matcherprovider.ProviderDescriptor `json:"provider"`
	SourceManifestID    string                             `json:"source_manifest_id"`
	SourceContentSHA256 string                             `json:"source_content_sha256"`
	RecordCount         int                                `json:"record_count"`
	EntryCount          int                                `json:"entry_count"`
	PayloadSHA256       string                             `json:"payload_sha256"`
	PayloadSize         int64                              `json:"payload_size"`
}

type PackageInfo struct {
	SchemaVersion   string          `json:"schema_version"`
	PackageID       string          `json:"package_id"`
	PackageChecksum string          `json:"package_checksum"`
	ArtifactSize    int64           `json:"artifact_size"`
	Manifest        PackageManifest `json:"manifest"`
}

type LoadedPackage struct {
	Info     PackageInfo
	Payload  RuntimePayload
	Provider *Provider
}
