package mmapcatalogcontract

import (
	"encoding/binary"
	"fmt"
)

const metadataFieldCount = 12

// normalizationProfileFieldIndex is metadata[10] in the field order Compile
// writes (see the metadataValues slice in format.go): schema_version,
// compiler_version, source schema_version, component_id, catalog_id,
// catalog_version, catalog_checksum, catalog_mode, source_manifest_id,
// source_schema_version, normalization_profile, input_sha256.
const normalizationProfileFieldIndex = 10

// ReadNormalizationProfile parses the OWMMAP01 header and metadata section
// of a compiled catalog package directly from its bytes and returns the
// normalization_profile field the header already stores. It is a read-only
// counterpart to Compile: no on-disk format changes, and it does not
// require the Rust runtime worker to be running.
func ReadNormalizationProfile(raw []byte) (string, error) {
	if len(raw) < int(HeaderSize) {
		return "", fmt.Errorf("%w: file is smaller than the package header", ErrInvalidPackage)
	}
	if string(raw[0:8]) != Magic {
		return "", fmt.Errorf("%w: bad magic", ErrInvalidPackage)
	}
	sectionCount := binary.LittleEndian.Uint32(raw[12:16])
	if sectionCount == 0 {
		return "", fmt.Errorf("%w: no sections", ErrInvalidPackage)
	}
	directoryOffset := binary.LittleEndian.Uint64(raw[24:32])
	entryEnd := directoryOffset + DirectoryEntrySize
	if directoryOffset > uint64(len(raw)) || entryEnd > uint64(len(raw)) {
		return "", fmt.Errorf("%w: truncated section directory", ErrInvalidPackage)
	}
	entry := raw[directoryOffset:entryEnd]
	kind := binary.LittleEndian.Uint32(entry[0:4])
	if kind != SectionMetadata {
		return "", fmt.Errorf("%w: first section is not metadata", ErrInvalidPackage)
	}
	sectionOffset := binary.LittleEndian.Uint64(entry[8:16])
	sectionLength := binary.LittleEndian.Uint64(entry[16:24])
	sectionEnd := sectionOffset + sectionLength
	if sectionOffset > uint64(len(raw)) || sectionEnd > uint64(len(raw)) {
		return "", fmt.Errorf("%w: truncated metadata section", ErrInvalidPackage)
	}
	values, err := decodeMetadataSection(raw[sectionOffset:sectionEnd])
	if err != nil {
		return "", err
	}
	if len(values) != metadataFieldCount {
		return "", fmt.Errorf("%w: unexpected metadata field count %d", ErrInvalidPackage, len(values))
	}
	return values[normalizationProfileFieldIndex], nil
}

func decodeMetadataSection(data []byte) ([]string, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("%w: truncated metadata count", ErrInvalidPackage)
	}
	count := binary.LittleEndian.Uint32(data[0:4])
	offset := uint32(4)
	values := make([]string, 0, count)
	for index := uint32(0); index < count; index++ {
		if uint64(offset)+4 > uint64(len(data)) {
			return nil, fmt.Errorf("%w: truncated metadata entry", ErrInvalidPackage)
		}
		length := binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4
		if uint64(offset)+uint64(length) > uint64(len(data)) {
			return nil, fmt.Errorf("%w: truncated metadata value", ErrInvalidPackage)
		}
		values = append(values, string(data[offset:offset+length]))
		offset += length
	}
	return values, nil
}
