package runtimecataloginput

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
	"github.com/openwatchlist-labs/watchlist-platform/internal/providerentity"
)

var ErrInvalidInput = errors.New("invalid runtime catalog input")

func Export(r io.Reader, componentID string) ([]byte, Summary, error) {
	componentID = strings.TrimSpace(componentID)
	if !strings.HasPrefix(componentID, "catalog_component_") {
		return nil, Summary{}, fmt.Errorf("%w: component_id must be a stable catalog_component_ ID", ErrInvalidInput)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, Summary{}, fmt.Errorf("%w: read catalog: %v", ErrInvalidInput, err)
	}
	var header struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, Summary{}, fmt.Errorf("%w: decode catalog header: %v", ErrInvalidInput, err)
	}

	var input Input
	switch header.SchemaVersion {
	case ofaccatalog.CatalogSchemaVersion:
		catalog, err := ofaccatalog.Load(bytes.NewReader(data))
		if err != nil {
			return nil, Summary{}, err
		}
		if catalog.SourceManifest.SourceFormat != "ofac_advanced_xml" || catalog.SourceManifest.XMLSchemaVersion != "3" {
			return nil, Summary{}, fmt.Errorf("%w: official catalogs must originate from OFAC Advanced XML Version 3", ErrInvalidInput)
		}
		input = fromOfficial(catalog, componentID)
	case providerentity.CatalogSchemaVersion:
		catalog, err := providerentity.LoadCatalog(bytes.NewReader(data))
		if err != nil {
			return nil, Summary{}, err
		}
		input = fromProvider(catalog, componentID)
	default:
		return nil, Summary{}, fmt.Errorf("%w: unsupported catalog schema %q", ErrInvalidInput, header.SchemaVersion)
	}
	canonicalize(&input)
	if err := Validate(input); err != nil {
		return nil, Summary{}, err
	}
	encoded, err := Encode(input)
	if err != nil {
		return nil, Summary{}, err
	}
	sum := sha256.Sum256(encoded)
	summary := Summary{
		SchemaVersion:   input.Metadata.SchemaVersion,
		ExporterVersion: input.Metadata.ExporterVersion,
		ComponentID:     input.Metadata.ComponentID,
		CatalogID:       input.Metadata.CatalogID,
		CatalogVersion:  input.Metadata.CatalogVersion,
		CatalogChecksum: input.Metadata.CatalogChecksum,
		CatalogMode:     input.Metadata.CatalogMode,
		RecordCount:     len(input.Records),
		NameCount:       len(input.Names),
		IdentifierCount: len(input.Identifiers),
		ContentSHA256:   hex.EncodeToString(sum[:]),
	}
	return encoded, summary, nil
}

func fromOfficial(catalog ofaccatalog.Catalog, componentID string) Input {
	input := Input{Metadata: Metadata{
		SchemaVersion:        SchemaVersion,
		ExporterVersion:      ExporterVersion,
		ComponentID:          componentID,
		CatalogID:            catalog.CatalogID,
		CatalogVersion:       catalog.CatalogVersion,
		CatalogChecksum:      catalog.CatalogChecksum,
		CatalogMode:          "official_list",
		SourceManifestID:     catalog.SourceManifest.ManifestID,
		SourceSchemaVersion:  catalog.SchemaVersion,
		NormalizationProfile: NormalizationProfile,
	}}
	for _, source := range catalog.Records {
		input.Records = append(input.Records, Record{RecordID: source.ProviderRecordID, EntityType: string(source.EntityType), PrimaryName: source.PrimaryName})
		input.Names = append(input.Names, Name{RecordID: source.ProviderRecordID, Kind: "primary", Value: source.PrimaryName})
		for _, alias := range source.Aliases {
			input.Names = append(input.Names, Name{RecordID: source.ProviderRecordID, Kind: "alias", Value: alias.Name})
		}
		for _, identifier := range source.Identifiers {
			input.Identifiers = append(input.Identifiers, Identifier{RecordID: source.ProviderRecordID, Type: identifier.Type, Value: identifier.Number})
		}
	}
	return input
}

func fromProvider(catalog providerentity.Catalog, componentID string) Input {
	input := Input{Metadata: Metadata{
		SchemaVersion:        SchemaVersion,
		ExporterVersion:      ExporterVersion,
		ComponentID:          componentID,
		CatalogID:            catalog.CatalogID,
		CatalogVersion:       catalog.CatalogVersion,
		CatalogChecksum:      catalog.CatalogChecksum,
		CatalogMode:          "provider",
		SourceManifestID:     catalog.SourceSnapshotID,
		SourceSchemaVersion:  catalog.SchemaVersion,
		NormalizationProfile: NormalizationProfile,
	}}
	for _, source := range catalog.Entities {
		input.Records = append(input.Records, Record{RecordID: source.ProviderRecordID, EntityType: string(source.EntityType), PrimaryName: source.PrimaryName})
		input.Names = append(input.Names, Name{RecordID: source.ProviderRecordID, Kind: "primary", Value: source.PrimaryName})
		for _, alias := range source.Aliases {
			input.Names = append(input.Names, Name{RecordID: source.ProviderRecordID, Kind: "alias", Value: alias.Name})
		}
		for _, identifier := range source.Identifiers {
			input.Identifiers = append(input.Identifiers, Identifier{RecordID: source.ProviderRecordID, Type: identifier.Type, Value: identifier.Value})
		}
	}
	return input
}

func canonicalize(input *Input) {
	input.Records = uniqueRecords(input.Records)
	input.Names = uniqueNames(input.Names)
	input.Identifiers = uniqueIdentifiers(input.Identifiers)
}

func uniqueRecords(values []Record) []Record {
	sort.Slice(values, func(i, j int) bool { return values[i].RecordID < values[j].RecordID })
	out := values[:0]
	for _, value := range values {
		if len(out) > 0 && out[len(out)-1].RecordID == value.RecordID {
			continue
		}
		out = append(out, value)
	}
	return out
}

func uniqueNames(values []Name) []Name {
	for i := range values {
		values[i].Value = strings.TrimSpace(values[i].Value)
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].RecordID != values[j].RecordID {
			return values[i].RecordID < values[j].RecordID
		}
		if values[i].Kind != values[j].Kind {
			return values[i].Kind < values[j].Kind
		}
		return values[i].Value < values[j].Value
	})
	out := values[:0]
	for _, value := range values {
		if value.Value == "" {
			continue
		}
		if len(out) > 0 && out[len(out)-1] == value {
			continue
		}
		out = append(out, value)
	}
	return out
}

func uniqueIdentifiers(values []Identifier) []Identifier {
	for i := range values {
		values[i].Type = strings.TrimSpace(values[i].Type)
		values[i].Value = strings.TrimSpace(values[i].Value)
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].RecordID != values[j].RecordID {
			return values[i].RecordID < values[j].RecordID
		}
		if values[i].Type != values[j].Type {
			return values[i].Type < values[j].Type
		}
		return values[i].Value < values[j].Value
	})
	out := values[:0]
	for _, value := range values {
		if value.Type == "" || value.Value == "" {
			continue
		}
		if len(out) > 0 && out[len(out)-1] == value {
			continue
		}
		out = append(out, value)
	}
	return out
}

func Encode(input Input) ([]byte, error) {
	if err := Validate(input); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	writer := bufio.NewWriter(&buffer)
	fmt.Fprintln(writer, Magic)
	metadata := []struct{ key, value string }{
		{"schema_version", input.Metadata.SchemaVersion},
		{"exporter_version", input.Metadata.ExporterVersion},
		{"component_id", input.Metadata.ComponentID},
		{"catalog_id", input.Metadata.CatalogID},
		{"catalog_version", input.Metadata.CatalogVersion},
		{"catalog_checksum", input.Metadata.CatalogChecksum},
		{"catalog_mode", input.Metadata.CatalogMode},
		{"source_manifest_id", input.Metadata.SourceManifestID},
		{"source_schema_version", input.Metadata.SourceSchemaVersion},
		{"normalization_profile", input.Metadata.NormalizationProfile},
	}
	for _, field := range metadata {
		fmt.Fprintf(writer, "M\t%s\t%s\n", field.key, encodeHex(field.value))
	}
	for _, record := range input.Records {
		fmt.Fprintf(writer, "R\t%s\t%s\t%s\n", encodeHex(record.RecordID), encodeHex(record.EntityType), encodeHex(record.PrimaryName))
	}
	for _, name := range input.Names {
		fmt.Fprintf(writer, "N\t%s\t%s\t%s\n", encodeHex(name.RecordID), name.Kind, encodeHex(name.Value))
	}
	for _, identifier := range input.Identifiers {
		fmt.Fprintf(writer, "I\t%s\t%s\t%s\n", encodeHex(identifier.RecordID), encodeHex(identifier.Type), encodeHex(identifier.Value))
	}
	fmt.Fprintf(writer, "E\t%d\t%d\t%d\n", len(input.Records), len(input.Names), len(input.Identifiers))
	if err := writer.Flush(); err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrInvalidInput, err)
	}
	return buffer.Bytes(), nil
}

func encodeHex(value string) string { return hex.EncodeToString([]byte(value)) }
