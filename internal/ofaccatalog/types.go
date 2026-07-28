package ofaccatalog

import (
	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacsource"
)

const (
	CatalogSchemaVersion = "ofac-direct-list-catalog/v1alpha1"
	ProjectorVersion     = "ofac-direct-list-projector/v0.1.0"
	ProviderID           = "ofac-direct-list"
	ProviderVersion      = "v0.1.0"
	CatalogID            = "ofac-sdn-direct"
)

type Alias struct {
	SourceUID string `json:"source_uid"`
	Type      string `json:"type"`
	Strength  string `json:"strength,omitempty"`
	Name      string `json:"name"`
}
type Address struct {
	SourceUID  string `json:"source_uid"`
	Address1   string `json:"address1,omitempty"`
	Address2   string `json:"address2,omitempty"`
	Address3   string `json:"address3,omitempty"`
	City       string `json:"city,omitempty"`
	State      string `json:"state,omitempty"`
	PostalCode string `json:"postal_code,omitempty"`
	Country    string `json:"country,omitempty"`
}
type Identifier struct {
	SourceUID  string `json:"source_uid"`
	Type       string `json:"type"`
	Number     string `json:"number"`
	Country    string `json:"country,omitempty"`
	IssueDate  string `json:"issue_date,omitempty"`
	ExpiryDate string `json:"expiry_date,omitempty"`
}

type DirectListRecord struct {
	ProviderRecordID string                          `json:"provider_record_id"`
	SourceUID        string                          `json:"source_uid"`
	EntityType       canonical.CandidateType         `json:"entity_type"`
	SDNType          string                          `json:"sdn_type"`
	PrimaryName      string                          `json:"primary_name"`
	Title            string                          `json:"title,omitempty"`
	Remarks          string                          `json:"remarks,omitempty"`
	Programs         []string                        `json:"programs"`
	Aliases          []Alias                         `json:"aliases,omitempty"`
	Addresses        []Address                       `json:"addresses,omitempty"`
	Identifiers      []Identifier                    `json:"identifiers,omitempty"`
	DatesOfBirth     []string                        `json:"dates_of_birth,omitempty"`
	PlacesOfBirth    []string                        `json:"places_of_birth,omitempty"`
	Nationalities    []string                        `json:"nationalities,omitempty"`
	Citizenships     []string                        `json:"citizenships,omitempty"`
	VesselAttributes map[string]string               `json:"vessel_attributes,omitempty"`
	SourceAssertion  matcherprovider.SourceAssertion `json:"source_assertion"`
}

type Catalog struct {
	SchemaVersion    string                      `json:"schema_version"`
	CatalogID        string                      `json:"catalog_id"`
	CatalogVersion   string                      `json:"catalog_version"`
	CatalogChecksum  string                      `json:"catalog_checksum"`
	CatalogMode      matcherprovider.CatalogMode `json:"catalog_mode"`
	ProjectorVersion string                      `json:"projector_version"`
	SourceManifest   ofacsource.SourceManifest   `json:"source_manifest"`
	RecordCount      int                         `json:"record_count"`
	Records          []DirectListRecord          `json:"records"`
}
