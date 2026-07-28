package runtimemmapclient

import "context"

const (
	ProtocolVersion = "1"
	ClientVersion   = "rust-mmap-worker-client/v0.1.0"
)

type PackageInfo struct {
	ProtocolVersion string `json:"protocol_version"`
	ComponentID     string `json:"component_id"`
	CatalogID       string `json:"catalog_id"`
	CatalogVersion  string `json:"catalog_version"`
	CatalogChecksum string `json:"catalog_checksum"`
	CatalogMode     string `json:"catalog_mode"`
	PackageSHA256   string `json:"package_sha256"`
	RecordCount     uint64 `json:"record_count"`
}

type Candidate struct {
	RecordID        string `json:"record_id"`
	EntityType      string `json:"entity_type"`
	PrimaryName     string `json:"primary_name"`
	MatchKind       string `json:"match_kind"`
	MatchedValue    string `json:"matched_value"`
	NormalizedQuery string `json:"normalized_query"`
}

type QueryKind string

const (
	QueryRecordID   QueryKind = "record_id"
	QueryName       QueryKind = "name"
	QueryIdentifier QueryKind = "identifier"
)

type Query struct {
	RequestID      string
	Kind           QueryKind
	Value          string
	IdentifierType string
	Prefix         bool
	Limit          int
}

type Runtime interface {
	Info() PackageInfo
	Lookup(context.Context, Query) ([]Candidate, error)
	Close() error
}
