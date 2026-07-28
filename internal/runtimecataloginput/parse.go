package runtimecataloginput

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

func Parse(r io.Reader) (Input, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	line := 0
	var input Input
	metadata := map[string]string{}
	ended := false
	for scanner.Scan() {
		line++
		text := scanner.Text()
		if line == 1 {
			if text != Magic {
				return Input{}, fmt.Errorf("%w: invalid magic", ErrInvalidInput)
			}
			continue
		}
		if ended {
			return Input{}, fmt.Errorf("%w: data after end marker", ErrInvalidInput)
		}
		parts := strings.Split(text, "\t")
		if len(parts) == 0 {
			continue
		}
		switch parts[0] {
		case "M":
			if len(parts) != 3 {
				return Input{}, lineError(line, "metadata field count")
			}
			value, err := decodeHex(parts[2])
			if err != nil {
				return Input{}, lineError(line, err.Error())
			}
			if _, exists := metadata[parts[1]]; exists {
				return Input{}, lineError(line, "duplicate metadata key")
			}
			metadata[parts[1]] = value
		case "R":
			if len(parts) != 4 {
				return Input{}, lineError(line, "record field count")
			}
			id, err := decodeHex(parts[1])
			if err != nil {
				return Input{}, lineError(line, err.Error())
			}
			entityType, err := decodeHex(parts[2])
			if err != nil {
				return Input{}, lineError(line, err.Error())
			}
			name, err := decodeHex(parts[3])
			if err != nil {
				return Input{}, lineError(line, err.Error())
			}
			input.Records = append(input.Records, Record{RecordID: id, EntityType: entityType, PrimaryName: name})
		case "N":
			if len(parts) != 4 {
				return Input{}, lineError(line, "name field count")
			}
			id, err := decodeHex(parts[1])
			if err != nil {
				return Input{}, lineError(line, err.Error())
			}
			value, err := decodeHex(parts[3])
			if err != nil {
				return Input{}, lineError(line, err.Error())
			}
			input.Names = append(input.Names, Name{RecordID: id, Kind: parts[2], Value: value})
		case "I":
			if len(parts) != 4 {
				return Input{}, lineError(line, "identifier field count")
			}
			id, err := decodeHex(parts[1])
			if err != nil {
				return Input{}, lineError(line, err.Error())
			}
			typeValue, err := decodeHex(parts[2])
			if err != nil {
				return Input{}, lineError(line, err.Error())
			}
			value, err := decodeHex(parts[3])
			if err != nil {
				return Input{}, lineError(line, err.Error())
			}
			input.Identifiers = append(input.Identifiers, Identifier{RecordID: id, Type: typeValue, Value: value})
		case "E":
			if len(parts) != 4 {
				return Input{}, lineError(line, "end field count")
			}
			counts := []int{len(input.Records), len(input.Names), len(input.Identifiers)}
			for i := 0; i < 3; i++ {
				n, err := strconv.Atoi(parts[i+1])
				if err != nil || n != counts[i] {
					return Input{}, lineError(line, "count mismatch")
				}
			}
			ended = true
		default:
			return Input{}, lineError(line, "unknown record type")
		}
	}
	if err := scanner.Err(); err != nil {
		return Input{}, fmt.Errorf("%w: scan: %v", ErrInvalidInput, err)
	}
	if line == 0 || !ended {
		return Input{}, fmt.Errorf("%w: missing input or end marker", ErrInvalidInput)
	}
	input.Metadata = Metadata{
		SchemaVersion: metadata["schema_version"], ExporterVersion: metadata["exporter_version"], ComponentID: metadata["component_id"], CatalogID: metadata["catalog_id"], CatalogVersion: metadata["catalog_version"], CatalogChecksum: metadata["catalog_checksum"], CatalogMode: metadata["catalog_mode"], SourceManifestID: metadata["source_manifest_id"], SourceSchemaVersion: metadata["source_schema_version"], NormalizationProfile: metadata["normalization_profile"],
	}
	if len(metadata) != 10 {
		return Input{}, fmt.Errorf("%w: metadata key set mismatch", ErrInvalidInput)
	}
	if err := Validate(input); err != nil {
		return Input{}, err
	}
	return input, nil
}

func Validate(input Input) error {
	m := input.Metadata
	if m.SchemaVersion != SchemaVersion || m.ExporterVersion != ExporterVersion || m.NormalizationProfile != NormalizationProfile {
		return fmt.Errorf("%w: unsupported metadata contract", ErrInvalidInput)
	}
	if !strings.HasPrefix(m.ComponentID, "catalog_component_") || m.CatalogID == "" || m.CatalogVersion == "" || m.SourceManifestID == "" || m.SourceSchemaVersion == "" {
		return fmt.Errorf("%w: incomplete metadata", ErrInvalidInput)
	}
	if len(m.CatalogChecksum) != 64 {
		return fmt.Errorf("%w: catalog checksum must be SHA-256", ErrInvalidInput)
	}
	if _, err := hex.DecodeString(m.CatalogChecksum); err != nil {
		return fmt.Errorf("%w: catalog checksum is not hexadecimal", ErrInvalidInput)
	}
	if m.CatalogMode != "official_list" && m.CatalogMode != "provider" {
		return fmt.Errorf("%w: unsupported catalog mode %q", ErrInvalidInput, m.CatalogMode)
	}
	if len(input.Records) == 0 {
		return fmt.Errorf("%w: no records", ErrInvalidInput)
	}
	records := map[string]Record{}
	last := ""
	for _, record := range input.Records {
		if record.RecordID == "" || record.EntityType == "" || strings.TrimSpace(record.PrimaryName) == "" {
			return fmt.Errorf("%w: incomplete record", ErrInvalidInput)
		}
		if last != "" && record.RecordID <= last {
			return fmt.Errorf("%w: records must be unique and sorted", ErrInvalidInput)
		}
		records[record.RecordID] = record
		last = record.RecordID
	}
	lastKey := ""
	primary := map[string]int{}
	for _, name := range input.Names {
		if _, ok := records[name.RecordID]; !ok || (name.Kind != "primary" && name.Kind != "alias") || strings.TrimSpace(name.Value) == "" {
			return fmt.Errorf("%w: invalid name", ErrInvalidInput)
		}
		key := name.RecordID + "\x00" + name.Kind + "\x00" + name.Value
		if lastKey != "" && key <= lastKey {
			return fmt.Errorf("%w: names must be unique and sorted", ErrInvalidInput)
		}
		lastKey = key
		if name.Kind == "primary" {
			primary[name.RecordID]++
		}
	}
	for id := range records {
		if primary[id] != 1 {
			return fmt.Errorf("%w: record %q must have one primary index name", ErrInvalidInput, id)
		}
	}
	lastKey = ""
	for _, identifier := range input.Identifiers {
		if _, ok := records[identifier.RecordID]; !ok || identifier.Type == "" || identifier.Value == "" {
			return fmt.Errorf("%w: invalid identifier", ErrInvalidInput)
		}
		key := identifier.RecordID + "\x00" + identifier.Type + "\x00" + identifier.Value
		if lastKey != "" && key <= lastKey {
			return fmt.Errorf("%w: identifiers must be unique and sorted", ErrInvalidInput)
		}
		lastKey = key
	}
	return nil
}

func decodeHex(value string) (string, error) {
	data, err := hex.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("invalid hex")
	}
	if !utf8.Valid(data) {
		return "", fmt.Errorf("invalid UTF-8")
	}
	return string(data), nil
}
func lineError(line int, detail string) error {
	return fmt.Errorf("%w: line %d: %s", ErrInvalidInput, line, detail)
}
