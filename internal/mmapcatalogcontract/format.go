package mmapcatalogcontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/openwatchlist-labs/watchlist-platform/internal/runtimecataloginput"
)

const (
	Magic                = "OWMMAP01"
	FormatVersion        = uint32(1)
	HeaderSize           = uint64(64)
	DirectoryEntrySize   = uint64(32)
	PackageSchemaVersion = "memory-mapped-catalog/v1alpha1"
	CompilerVersion      = "catalog-mmap-compiler/v0.1.0"

	SectionMetadata    = uint32(1)
	SectionStrings     = uint32(2)
	SectionRecords     = uint32(3)
	SectionNames       = uint32(4)
	SectionIdentifiers = uint32(5)
)

var ErrInvalidPackage = errors.New("invalid memory-mapped catalog package")

type PackageInfo struct {
	SchemaVersion        string `json:"schema_version"`
	CompilerVersion      string `json:"compiler_version"`
	FormatVersion        uint32 `json:"format_version"`
	ComponentID          string `json:"component_id"`
	CatalogID            string `json:"catalog_id"`
	CatalogVersion       string `json:"catalog_version"`
	CatalogChecksum      string `json:"catalog_checksum"`
	CatalogMode          string `json:"catalog_mode"`
	SourceManifestID     string `json:"source_manifest_id"`
	SourceSchemaVersion  string `json:"source_schema_version"`
	NormalizationProfile string `json:"normalization_profile"`
	InputSHA256          string `json:"input_sha256"`
	PayloadSHA256        string `json:"payload_sha256"`
	PackageSHA256        string `json:"package_sha256"`
	PackageLength        uint64 `json:"package_length"`
	RecordCount          uint64 `json:"record_count"`
	NameCount            uint64 `json:"name_count"`
	IdentifierCount      uint64 `json:"identifier_count"`
}

type section struct {
	kind, entrySize uint32
	data            []byte
	count           uint64
}
type stringRef struct {
	offset uint64
	length uint32
}
type stringPool struct {
	data []byte
	refs map[string]stringRef
}

func Compile(inputBytes []byte) ([]byte, PackageInfo, error) {
	input, err := runtimecataloginput.Parse(bytes.NewReader(inputBytes))
	if err != nil {
		return nil, PackageInfo{}, err
	}
	inputSum := sha256.Sum256(inputBytes)
	pool := stringPool{refs: map[string]stringRef{}}
	recordIndex := map[string]uint32{}
	records := make([]byte, 0, len(input.Records)*32)
	for index, record := range input.Records {
		recordIndex[record.RecordID] = uint32(index)
		id := pool.intern(record.RecordID)
		primary := pool.intern(record.PrimaryName)
		entry := make([]byte, 32)
		binary.LittleEndian.PutUint64(entry[0:8], id.offset)
		binary.LittleEndian.PutUint32(entry[8:12], id.length)
		binary.LittleEndian.PutUint64(entry[12:20], primary.offset)
		binary.LittleEndian.PutUint32(entry[20:24], primary.length)
		entry[24] = entityTypeCode(record.EntityType)
		if entry[24] == 0 {
			return nil, PackageInfo{}, fmt.Errorf("%w: unsupported entity type %q", ErrInvalidPackage, record.EntityType)
		}
		records = append(records, entry...)
	}

	type nameItem struct {
		normalized, value string
		record            uint32
		kind              byte
	}
	names := make([]nameItem, 0, len(input.Names))
	for _, name := range input.Names {
		normalized := NormalizeName(name.Value)
		if normalized == "" {
			continue
		}
		kind := byte(2)
		if name.Kind == "primary" {
			kind = 1
		}
		names = append(names, nameItem{normalized: normalized, value: name.Value, record: recordIndex[name.RecordID], kind: kind})
	}
	sort.Slice(names, func(i, j int) bool {
		if names[i].normalized != names[j].normalized {
			return names[i].normalized < names[j].normalized
		}
		if names[i].record != names[j].record {
			return names[i].record < names[j].record
		}
		if names[i].kind != names[j].kind {
			return names[i].kind < names[j].kind
		}
		return names[i].value < names[j].value
	})
	nameData := make([]byte, 0, len(names)*32)
	for _, item := range names {
		normalized := pool.intern(item.normalized)
		value := pool.intern(item.value)
		entry := make([]byte, 32)
		binary.LittleEndian.PutUint64(entry[0:8], normalized.offset)
		binary.LittleEndian.PutUint32(entry[8:12], normalized.length)
		binary.LittleEndian.PutUint64(entry[12:20], value.offset)
		binary.LittleEndian.PutUint32(entry[20:24], value.length)
		binary.LittleEndian.PutUint32(entry[24:28], item.record)
		entry[28] = item.kind
		nameData = append(nameData, entry...)
	}

	type identifierItem struct {
		typ, normalized, value string
		record                 uint32
	}
	identifiers := make([]identifierItem, 0, len(input.Identifiers))
	for _, identifier := range input.Identifiers {
		normalized := NormalizeIdentifier(identifier.Value)
		typ := NormalizeType(identifier.Type)
		if normalized == "" || typ == "" {
			continue
		}
		identifiers = append(identifiers, identifierItem{typ: typ, normalized: normalized, value: identifier.Value, record: recordIndex[identifier.RecordID]})
	}
	sort.Slice(identifiers, func(i, j int) bool {
		if identifiers[i].typ != identifiers[j].typ {
			return identifiers[i].typ < identifiers[j].typ
		}
		if identifiers[i].normalized != identifiers[j].normalized {
			return identifiers[i].normalized < identifiers[j].normalized
		}
		if identifiers[i].record != identifiers[j].record {
			return identifiers[i].record < identifiers[j].record
		}
		return identifiers[i].value < identifiers[j].value
	})
	identifierData := make([]byte, 0, len(identifiers)*40)
	for _, item := range identifiers {
		typ := pool.intern(item.typ)
		normalized := pool.intern(item.normalized)
		value := pool.intern(item.value)
		entry := make([]byte, 40)
		binary.LittleEndian.PutUint64(entry[0:8], typ.offset)
		binary.LittleEndian.PutUint32(entry[8:12], typ.length)
		binary.LittleEndian.PutUint64(entry[12:20], normalized.offset)
		binary.LittleEndian.PutUint32(entry[20:24], normalized.length)
		binary.LittleEndian.PutUint64(entry[24:32], value.offset)
		binary.LittleEndian.PutUint32(entry[32:36], value.length)
		binary.LittleEndian.PutUint32(entry[36:40], item.record)
		identifierData = append(identifierData, entry...)
	}

	metadataValues := []string{PackageSchemaVersion, CompilerVersion, input.Metadata.SchemaVersion, input.Metadata.ComponentID, input.Metadata.CatalogID, input.Metadata.CatalogVersion, input.Metadata.CatalogChecksum, input.Metadata.CatalogMode, input.Metadata.SourceManifestID, input.Metadata.SourceSchemaVersion, input.Metadata.NormalizationProfile, hex.EncodeToString(inputSum[:])}
	metadata := encodeMetadata(metadataValues)
	sections := []section{{SectionMetadata, 0, metadata, uint64(len(metadataValues))}, {SectionStrings, 0, pool.data, uint64(len(pool.refs))}, {SectionRecords, 32, records, uint64(len(input.Records))}, {SectionNames, 32, nameData, uint64(len(names))}, {SectionIdentifiers, 40, identifierData, uint64(len(identifiers))}}
	directoryLength := DirectoryEntrySize * uint64(len(sections))
	offset := HeaderSize + directoryLength
	payload := make([]byte, directoryLength)
	for i, section := range sections {
		base := i * int(DirectoryEntrySize)
		binary.LittleEndian.PutUint32(payload[base:base+4], section.kind)
		binary.LittleEndian.PutUint32(payload[base+4:base+8], section.entrySize)
		binary.LittleEndian.PutUint64(payload[base+8:base+16], offset)
		binary.LittleEndian.PutUint64(payload[base+16:base+24], uint64(len(section.data)))
		binary.LittleEndian.PutUint64(payload[base+24:base+32], section.count)
		offset += uint64(len(section.data))
	}
	for _, section := range sections {
		payload = append(payload, section.data...)
	}
	payloadSum := sha256.Sum256(payload)
	artifact := make([]byte, HeaderSize)
	copy(artifact[0:8], []byte(Magic))
	binary.LittleEndian.PutUint32(artifact[8:12], FormatVersion)
	binary.LittleEndian.PutUint32(artifact[12:16], uint32(len(sections)))
	binary.LittleEndian.PutUint64(artifact[16:24], uint64(len(artifact)+len(payload)))
	binary.LittleEndian.PutUint64(artifact[24:32], HeaderSize)
	copy(artifact[32:64], payloadSum[:])
	artifact = append(artifact, payload...)
	packageSum := sha256.Sum256(artifact)
	info := PackageInfo{SchemaVersion: PackageSchemaVersion, CompilerVersion: CompilerVersion, FormatVersion: FormatVersion, ComponentID: input.Metadata.ComponentID, CatalogID: input.Metadata.CatalogID, CatalogVersion: input.Metadata.CatalogVersion, CatalogChecksum: input.Metadata.CatalogChecksum, CatalogMode: input.Metadata.CatalogMode, SourceManifestID: input.Metadata.SourceManifestID, SourceSchemaVersion: input.Metadata.SourceSchemaVersion, NormalizationProfile: input.Metadata.NormalizationProfile, InputSHA256: hex.EncodeToString(inputSum[:]), PayloadSHA256: hex.EncodeToString(payloadSum[:]), PackageSHA256: hex.EncodeToString(packageSum[:]), PackageLength: uint64(len(artifact)), RecordCount: uint64(len(input.Records)), NameCount: uint64(len(names)), IdentifierCount: uint64(len(identifiers))}
	return artifact, info, nil
}

func (p *stringPool) intern(value string) stringRef {
	if ref, ok := p.refs[value]; ok {
		return ref
	}
	ref := stringRef{offset: uint64(len(p.data)), length: uint32(len([]byte(value)))}
	p.data = append(p.data, []byte(value)...)
	p.refs[value] = ref
	return ref
}

func encodeMetadata(values []string) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint32(len(values)))
	for _, value := range values {
		_ = binary.Write(&b, binary.LittleEndian, uint32(len([]byte(value))))
		b.WriteString(value)
	}
	return b.Bytes()
}

func NormalizeName(value string) string       { return normalizeASCII(value, false, true) }
func NormalizeIdentifier(value string) string { return normalizeASCII(value, true, false) }
func NormalizeType(value string) string       { return normalizeASCII(value, false, false) }

func normalizeASCII(value string, upper bool, spaces bool) string {
	if !utf8.ValidString(value) {
		return ""
	}
	var b strings.Builder
	pendingSep := false
	for _, r := range value {
		if r > 127 {
			if pendingSep && b.Len() > 0 && spaces {
				b.WriteByte(' ')
			}
			pendingSep = false
			b.WriteRune(r)
			continue
		}
		c := byte(r)
		isAlpha := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		if isAlpha || isDigit {
			if pendingSep && b.Len() > 0 && spaces {
				b.WriteByte(' ')
			}
			pendingSep = false
			if upper && c >= 'a' && c <= 'z' {
				c -= 32
			} else if !upper && c >= 'A' && c <= 'Z' {
				c += 32
			}
			b.WriteByte(c)
		} else if spaces {
			pendingSep = true
		}
	}
	return strings.TrimSpace(b.String())
}

func entityTypeCode(value string) byte {
	switch value {
	case "individual":
		return 1
	case "organization":
		return 2
	case "government_entity":
		return 3
	case "financial_institution":
		return 4
	case "vessel":
		return 5
	case "aircraft":
		return 6
	case "jurisdiction":
		return 7
	default:
		return 0
	}
}
