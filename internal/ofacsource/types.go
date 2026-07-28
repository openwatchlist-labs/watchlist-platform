package ofacsource

import "time"

const (
	ManifestSchemaVersion      = "ofac-source-manifest/v1alpha1"
	PackageSchemaVersion       = "ofac-source-package/v1alpha1"
	ParserVersion              = "ofac-sdn-legacy-xml-parser/v0.1.0"
	AdvancedParserVersion      = "ofac-sdn-advanced-xml-parser/v0.2.0"
	PriorAdvancedParserVersion = "ofac-sdn-advanced-xml-parser/v0.1.0"
	OfficialSDNXMLURL          = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML"
	LegacyXMLNamespace         = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/XML"
	AdvancedXMLNamespace       = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/ADVANCED_XML"
)

type AcquisitionMethod string

const (
	AcquisitionHTTP  AcquisitionMethod = "https"
	AcquisitionLocal AcquisitionMethod = "local_fixture"
)

type SourceManifest struct {
	SchemaVersion       string            `json:"schema_version"`
	ManifestID          string            `json:"manifest_id"`
	Authority           string            `json:"authority"`
	DatasetID           string            `json:"dataset_id"`
	SourceURL           string            `json:"source_url"`
	AcquisitionMethod   AcquisitionMethod `json:"acquisition_method"`
	AcquiredAt          time.Time         `json:"acquired_at"`
	MediaType           string            `json:"media_type"`
	ContentLength       int64             `json:"content_length"`
	ContentSHA256       string            `json:"content_sha256"`
	HTTPETag            string            `json:"http_etag,omitempty"`
	HTTPLastModified    string            `json:"http_last_modified,omitempty"`
	XMLNamespace        string            `json:"xml_namespace"`
	PublishDate         string            `json:"publish_date"`
	DeclaredRecordCount int               `json:"declared_record_count"`
	ParserVersion       string            `json:"parser_version"`
	SourceFormat        string            `json:"source_format,omitempty"`
	XMLSchemaVersion    string            `json:"xml_schema_version,omitempty"`
	SchemaLocation      string            `json:"schema_location,omitempty"`
	SourceFilename      string            `json:"source_filename,omitempty"`
}

type SourcePackage struct {
	SchemaVersion string         `json:"schema_version"`
	Manifest      SourceManifest `json:"manifest"`
	Document      Document       `json:"document"`
}
type Document struct {
	Namespace   string
	PublishDate string
	RecordCount int
	Entries     []Entry
}
type Entry struct {
	UID                                                      int
	FirstName, LastName, SDNType, Title, Remarks             string
	Programs                                                 []string
	Aliases                                                  []Alias
	Addresses                                                []Address
	Identifiers                                              []Identifier
	DatesOfBirth, PlacesOfBirth, Nationalities, Citizenships []string
	Vessel                                                   Vessel
}
type Alias struct {
	UID                                 int
	Type, Category, FirstName, LastName string
}
type Address struct {
	UID                                                            int
	Address1, Address2, Address3, City, State, PostalCode, Country string
}
type Identifier struct {
	UID                                  int
	Type, Number, Country, Issue, Expiry string
}
type Vessel struct{ CallSign, Type, Flag, Owner, Tonnage, GRT string }
