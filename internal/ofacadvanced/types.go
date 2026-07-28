package ofacadvanced

import (
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacsource"
)

const (
	SnapshotSchemaVersion = "ofac-advanced-canonical/v1alpha1"
	ParserVersion         = "ofac-sdn-advanced-xml-parser/v0.2.0"
	AdvancedXMLNamespace  = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/ADVANCED_XML"
	AdvancedXMLVersion    = "3"
	OfficialSDNXMLURL     = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN_ADVANCED.XML"
	OfficialXSDURL        = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/ADVANCED_XML.xsd"
	SourceFormat          = "ofac_advanced_xml"
	OfficialSDNListName   = "SDN List"
)

type Acquired struct {
	Bytes                         []byte
	SourceURL                     string
	Method                        ofacsource.AcquisitionMethod
	MediaType, ETag, LastModified string
	AcquiredAt                    time.Time
	ContentSHA256                 string
	ContentLength                 int64
}

type NamePart struct {
	Value         string `json:"value"`
	PartType      string `json:"part_type,omitempty"`
	PartTypeID    string `json:"part_type_id,omitempty"`
	Script        string `json:"script,omitempty"`
	ScriptID      string `json:"script_id,omitempty"`
	ScriptStatus  string `json:"script_status,omitempty"`
	Acronym       bool   `json:"acronym,omitempty"`
	SourceGroupID string `json:"source_group_id,omitempty"`
}

type Name struct {
	SourceAliasID          string     `json:"source_alias_id"`
	SourceDocumentedNameID string     `json:"source_documented_name_id,omitempty"`
	Value                  string     `json:"value"`
	Primary                bool       `json:"primary"`
	LowQuality             bool       `json:"low_quality"`
	AliasType              string     `json:"alias_type,omitempty"`
	Script                 string     `json:"script,omitempty"`
	ScriptID               string     `json:"script_id,omitempty"`
	Parts                  []NamePart `json:"parts"`
}

type AddressComponent struct {
	Type     string `json:"type"`
	TypeID   string `json:"type_id,omitempty"`
	Value    string `json:"value"`
	Script   string `json:"script,omitempty"`
	ScriptID string `json:"script_id,omitempty"`
}

type Address struct {
	SourceLocationID string             `json:"source_location_id"`
	Address1         string             `json:"address1,omitempty"`
	Address2         string             `json:"address2,omitempty"`
	Address3         string             `json:"address3,omitempty"`
	City             string             `json:"city,omitempty"`
	State            string             `json:"state,omitempty"`
	PostalCode       string             `json:"postal_code,omitempty"`
	Country          string             `json:"country,omitempty"`
	CountryID        string             `json:"country_id,omitempty"`
	Components       []AddressComponent `json:"components,omitempty"`
}

type Identifier struct {
	SourceDocumentID string `json:"source_document_id"`
	SourceIdentityID string `json:"source_identity_id,omitempty"`
	Type             string `json:"type"`
	TypeID           string `json:"type_id,omitempty"`
	Number           string `json:"number"`
	Country          string `json:"country,omitempty"`
	CountryID        string `json:"country_id,omitempty"`
	IssueDate        string `json:"issue_date,omitempty"`
	ExpiryDate       string `json:"expiry_date,omitempty"`
	IssuingAuthority string `json:"issuing_authority,omitempty"`
}

type FeatureDetail struct {
	Type       string `json:"type,omitempty"`
	TypeID     string `json:"type_id,omitempty"`
	Value      string `json:"value,omitempty"`
	DatePeriod string `json:"date_period,omitempty"`
	LocationID string `json:"location_id,omitempty"`
}

type Feature struct {
	SourceFeatureID string          `json:"source_feature_id,omitempty"`
	Type            string          `json:"type"`
	TypeID          string          `json:"type_id,omitempty"`
	Details         []FeatureDetail `json:"details,omitempty"`
}

type LegalAuthority struct {
	SourceEventID string `json:"source_event_id,omitempty"`
	Authority     string `json:"authority,omitempty"`
	AuthorityID   string `json:"authority_id,omitempty"`
	EventType     string `json:"event_type,omitempty"`
	EventTypeID   string `json:"event_type_id,omitempty"`
	Date          string `json:"date,omitempty"`
	Comment       string `json:"comment,omitempty"`
}

type Relationship struct {
	SanctionsEntryID     string `json:"sanctions_entry_id,omitempty"`
	SourceRelationshipID string `json:"source_relationship_id,omitempty"`
	FromProfileID        string `json:"from_profile_id"`
	ToProfileID          string `json:"to_profile_id"`
	Type                 string `json:"type,omitempty"`
	TypeID               string `json:"type_id,omitempty"`
	Quality              string `json:"quality,omitempty"`
	QualityID            string `json:"quality_id,omitempty"`
	Former               bool   `json:"former,omitempty"`
	Comment              string `json:"comment,omitempty"`
}

type Party struct {
	UID              int              `json:"uid"`
	ProfileID        string           `json:"profile_id"`
	ProfileIDs       []string         `json:"profile_ids,omitempty"`
	IdentityID       string           `json:"identity_id,omitempty"`
	IdentityIDs      []string         `json:"identity_ids,omitempty"`
	EntityType       string           `json:"entity_type"`
	EntityTypeID     string           `json:"entity_type_id,omitempty"`
	PrimaryName      string           `json:"primary_name"`
	Remarks          string           `json:"remarks,omitempty"`
	Programs         []string         `json:"programs"`
	Names            []Name           `json:"names"`
	Addresses        []Address        `json:"addresses,omitempty"`
	Identifiers      []Identifier     `json:"identifiers,omitempty"`
	Features         []Feature        `json:"features,omitempty"`
	LegalAuthorities []LegalAuthority `json:"legal_authorities,omitempty"`
	Relationships    []Relationship   `json:"relationships,omitempty"`
}

type SourceStats struct {
	DistinctPartyCount       int `json:"distinct_party_count"`
	ProfileCount             int `json:"profile_count"`
	SanctionsEntryCount      int `json:"sanctions_entry_count"`
	SelectedSDNEntryCount    int `json:"selected_sdn_entry_count"`
	FilteredNonSDNEntryCount int `json:"filtered_non_sdn_entry_count"`
}

type Snapshot struct {
	SchemaVersion    string                    `json:"schema_version"`
	SnapshotID       string                    `json:"snapshot_id"`
	SnapshotChecksum string                    `json:"snapshot_checksum"`
	ParserVersion    string                    `json:"parser_version"`
	XMLNamespace     string                    `json:"xml_namespace"`
	XMLVersion       string                    `json:"xml_version"`
	SchemaLocation   string                    `json:"schema_location"`
	DateOfIssue      string                    `json:"date_of_issue"`
	SourceManifest   ofacsource.SourceManifest `json:"source_manifest"`
	SourceStats      SourceStats               `json:"source_stats"`
	RecordCount      int                       `json:"record_count"`
	Parties          []Party                   `json:"parties"`
}

type Result struct {
	Snapshot Snapshot
	Package  ofacsource.SourcePackage
}
