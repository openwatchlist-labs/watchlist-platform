package runtimemmapclient

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

func parseHello(line string) (PackageInfo, error) {
	fields := strings.Split(line, "\t")
	if len(fields) != 9 || fields[0] != "H" {
		return PackageInfo{}, fmt.Errorf("invalid worker hello framing")
	}
	component, err := decodeHex(fields[2])
	if err != nil {
		return PackageInfo{}, fmt.Errorf("decode component_id: %w", err)
	}
	catalogID, err := decodeHex(fields[3])
	if err != nil {
		return PackageInfo{}, fmt.Errorf("decode catalog_id: %w", err)
	}
	catalogVersion, err := decodeHex(fields[4])
	if err != nil {
		return PackageInfo{}, fmt.Errorf("decode catalog_version: %w", err)
	}
	catalogMode, err := decodeHex(fields[6])
	if err != nil {
		return PackageInfo{}, fmt.Errorf("decode catalog_mode: %w", err)
	}
	recordCount, err := strconv.ParseUint(fields[8], 10, 64)
	if err != nil {
		return PackageInfo{}, fmt.Errorf("decode record_count: %w", err)
	}
	return PackageInfo{
		ProtocolVersion: fields[1],
		ComponentID:     component,
		CatalogID:       catalogID,
		CatalogVersion:  catalogVersion,
		CatalogChecksum: fields[5],
		CatalogMode:     catalogMode,
		PackageSHA256:   fields[7],
		RecordCount:     recordCount,
	}, nil
}

func encodeQuery(query Query) (string, error) {
	if err := validateRequestID(query.RequestID); err != nil {
		return "", err
	}
	if query.Limit <= 0 || query.Limit > 10_000 {
		return "", fmt.Errorf("limit must be between 1 and 10000")
	}
	switch query.Kind {
	case QueryRecordID:
		if query.Value == "" {
			return "", fmt.Errorf("record_id value is required")
		}
		return fmt.Sprintf("Q\t%s\trecord\t%d\t%s", query.RequestID, query.Limit, encodeHex(query.Value)), nil
	case QueryName:
		if query.Value == "" {
			return "", fmt.Errorf("name value is required")
		}
		prefix := 0
		if query.Prefix {
			prefix = 1
		}
		return fmt.Sprintf("Q\t%s\tname\t%d\t%d\t%s", query.RequestID, query.Limit, prefix, encodeHex(query.Value)), nil
	case QueryIdentifier:
		if query.IdentifierType == "" || query.Value == "" {
			return "", fmt.Errorf("identifier_type and value are required")
		}
		return fmt.Sprintf("Q\t%s\tidentifier\t%d\t%s\t%s", query.RequestID, query.Limit, encodeHex(query.IdentifierType), encodeHex(query.Value)), nil
	default:
		return "", fmt.Errorf("unsupported query kind %q", query.Kind)
	}
}

func parseCandidate(line, requestID string) (Candidate, error) {
	fields := strings.Split(line, "\t")
	if len(fields) != 8 || fields[0] != "C" || fields[1] != requestID {
		return Candidate{}, fmt.Errorf("invalid candidate framing")
	}
	values := make([]string, 6)
	for index := range values {
		decoded, err := decodeHex(fields[index+2])
		if err != nil {
			return Candidate{}, fmt.Errorf("decode candidate field %d: %w", index, err)
		}
		values[index] = decoded
	}
	return Candidate{RecordID: values[0], EntityType: values[1], PrimaryName: values[2], MatchKind: values[3], MatchedValue: values[4], NormalizedQuery: values[5]}, nil
}

func parseWorkerError(line, requestID string) error {
	fields := strings.Split(line, "\t")
	if len(fields) != 3 || fields[0] != "X" || fields[1] != requestID {
		return fmt.Errorf("invalid worker error framing")
	}
	message, err := decodeHex(fields[2])
	if err != nil {
		return fmt.Errorf("decode worker error: %w", err)
	}
	return fmt.Errorf("Rust runtime: %s", message)
}

func validateRequestID(value string) error {
	if value == "" || len(value) > 96 {
		return fmt.Errorf("request_id must contain 1..96 characters")
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("_-.:", char) {
			continue
		}
		return fmt.Errorf("request_id contains an unsupported character")
	}
	return nil
}

func encodeHex(value string) string { return hex.EncodeToString([]byte(value)) }
func decodeHex(value string) (string, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}
