package providerentity

import (
	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
)

const (
	SnapshotSchemaVersion   = "opensanctions-like-snapshot/v1alpha1"
	CatalogSchemaVersion    = "provider-entity-catalog/v1alpha1"
	HybridSchemaVersion     = "hybrid-overlay-catalog/v1alpha1"
	ComparisonSchemaVersion = "catalog-comparison/v1alpha1"
	AdapterVersion          = "opensanctions-like-adapter/v0.1.0"
	ProviderID              = "opensanctions-like-provider"
	ProviderVersion         = "v0.1.0"
	HybridProviderID        = "provider-entity-ofac-hybrid"
	HybridProviderVersion   = "v0.1.0"
)

type SourceMembership struct {
	SourceID       string   `json:"source_id"`
	Authority      string   `json:"authority"`
	ListID         string   `json:"list_id"`
	SourceRecordID string   `json:"source_record_id"`
	Programs       []string `json:"programs,omitempty"`
	Active         bool     `json:"active"`
}

type Alias struct {
	Name     string `json:"name"`
	Type     string `json:"type,omitempty"`
	Strength string `json:"strength,omitempty"`
}

type Address struct {
	Line1      string `json:"line1,omitempty"`
	Line2      string `json:"line2,omitempty"`
	City       string `json:"city,omitempty"`
	Region     string `json:"region,omitempty"`
	PostalCode string `json:"postal_code,omitempty"`
	Country    string `json:"country,omitempty"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type SnapshotEntity struct {
	EntityID          string                  `json:"entity_id"`
	Schema            string                  `json:"schema"`
	EntityType        canonical.CandidateType `json:"entity_type"`
	PrimaryName       string                  `json:"primary_name"`
	Aliases           []Alias                 `json:"aliases,omitempty"`
	Addresses         []Address               `json:"addresses,omitempty"`
	Identifiers       []Identifier            `json:"identifiers,omitempty"`
	DatesOfBirth      []string                `json:"dates_of_birth,omitempty"`
	Remarks           string                  `json:"remarks,omitempty"`
	SourceMemberships []SourceMembership      `json:"source_memberships"`
	Attributes        map[string]string       `json:"attributes,omitempty"`
}

type Snapshot struct {
	SchemaVersion    string           `json:"schema_version"`
	SnapshotID       string           `json:"snapshot_id"`
	SnapshotVersion  string           `json:"snapshot_version"`
	SnapshotChecksum string           `json:"snapshot_checksum"`
	ProviderName     string           `json:"provider_name"`
	EntityCount      int              `json:"entity_count"`
	Entities         []SnapshotEntity `json:"entities"`
}

type Entity struct {
	ProviderRecordID  string                  `json:"provider_record_id"`
	ProviderEntityID  string                  `json:"provider_entity_id"`
	EntityType        canonical.CandidateType `json:"entity_type"`
	PrimaryName       string                  `json:"primary_name"`
	Aliases           []Alias                 `json:"aliases,omitempty"`
	Addresses         []Address               `json:"addresses,omitempty"`
	Identifiers       []Identifier            `json:"identifiers,omitempty"`
	DatesOfBirth      []string                `json:"dates_of_birth,omitempty"`
	Remarks           string                  `json:"remarks,omitempty"`
	SourceMemberships []SourceMembership      `json:"source_memberships"`
	Attributes        map[string]string       `json:"attributes,omitempty"`
}

type Catalog struct {
	SchemaVersion     string                      `json:"schema_version"`
	CatalogID         string                      `json:"catalog_id"`
	CatalogVersion    string                      `json:"catalog_version"`
	CatalogChecksum   string                      `json:"catalog_checksum"`
	CatalogMode       matcherprovider.CatalogMode `json:"catalog_mode"`
	AdapterVersion    string                      `json:"adapter_version"`
	ProviderName      string                      `json:"provider_name"`
	SourceSnapshotID  string                      `json:"source_snapshot_id"`
	SourceSnapshotSHA string                      `json:"source_snapshot_checksum"`
	RecordCount       int                         `json:"record_count"`
	Entities          []Entity                    `json:"entities"`
}

type HybridCatalog struct {
	SchemaVersion        string                           `json:"schema_version"`
	CatalogID            string                           `json:"catalog_id"`
	CatalogVersion       string                           `json:"catalog_version"`
	CatalogChecksum      string                           `json:"catalog_checksum"`
	CatalogMode          matcherprovider.CatalogMode      `json:"catalog_mode"`
	BaseCatalog          matcherprovider.CatalogReference `json:"base_catalog"`
	OfficialOverlay      matcherprovider.CatalogReference `json:"official_overlay"`
	LinkPolicy           string                           `json:"link_policy"`
	UnlinkedRecordPolicy string                           `json:"unlinked_record_policy"`
}

type ComparisonLink struct {
	ProviderEntityID string `json:"provider_entity_id"`
	ProviderRecordID string `json:"provider_record_id"`
	DirectRecordID   string `json:"direct_record_id"`
	SourceKey        string `json:"source_key"`
	Status           string `json:"status"`
	NameEqual        bool   `json:"name_equal"`
	EntityTypeEqual  bool   `json:"entity_type_equal"`
	ProgramsEqual    bool   `json:"programs_equal"`
}

type ComparisonSummary struct {
	ProviderEntities   int `json:"provider_entities"`
	DirectRecords      int `json:"direct_records"`
	LinkedRecords      int `json:"linked_records"`
	ProviderOnly       int `json:"provider_only"`
	DirectOnly         int `json:"direct_only"`
	NameDifferences    int `json:"name_differences"`
	TypeDifferences    int `json:"entity_type_differences"`
	ProgramDifferences int `json:"program_differences"`
}

type Comparison struct {
	SchemaVersion      string                           `json:"schema_version"`
	ComparisonID       string                           `json:"comparison_id"`
	ComparisonChecksum string                           `json:"comparison_checksum"`
	ProviderCatalog    matcherprovider.CatalogReference `json:"provider_catalog"`
	DirectCatalog      matcherprovider.CatalogReference `json:"direct_catalog"`
	Summary            ComparisonSummary                `json:"summary"`
	Links              []ComparisonLink                 `json:"links"`
	ProviderOnlyIDs    []string                         `json:"provider_only_ids,omitempty"`
	DirectOnlyIDs      []string                         `json:"direct_only_ids,omitempty"`
}
