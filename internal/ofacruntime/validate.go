package ofacruntime

import (
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
)

var (
	ErrInvalidPackage = errors.New("invalid compiled OFAC runtime package")
	ErrInvalidPayload = errors.New("invalid compiled OFAC runtime payload")
)

func ValidateManifest(manifest PackageManifest) error {
	if manifest.SchemaVersion != PackageManifestSchemaVersion || manifest.PackageFormat != PackageFormatVersion || manifest.CompilerVersion != CompilerVersion || manifest.PayloadSchema != RuntimePayloadSchemaVersion {
		return fmt.Errorf("%w: invalid manifest header", ErrInvalidPackage)
	}
	for field, value := range map[string]string{
		"package_id":            manifest.PackageID,
		"source_manifest_id":    manifest.SourceManifestID,
		"source_content_sha256": manifest.SourceContentSHA256,
		"payload_sha256":        manifest.PayloadSHA256,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidPackage, field)
		}
	}
	if err := validateSHA(manifest.SourceContentSHA256, "source_content_sha256"); err != nil {
		return err
	}
	if err := validateSHA(manifest.PayloadSHA256, "payload_sha256"); err != nil {
		return err
	}
	if manifest.RecordCount < 1 || manifest.EntryCount < 1 || manifest.PayloadSize < 1 {
		return fmt.Errorf("%w: record_count, entry_count, and payload_size must be positive", ErrInvalidPackage)
	}
	if err := matcherprovider.ValidateDescriptor(manifest.Provider); err != nil {
		return fmt.Errorf("%w: provider: %v", ErrInvalidPackage, err)
	}
	if expected := stablePackageID(manifest); manifest.PackageID != expected {
		return fmt.Errorf("%w: package_id=%q expected %q", ErrInvalidPackage, manifest.PackageID, expected)
	}
	return nil
}

func ValidateInfo(info PackageInfo) error {
	if info.SchemaVersion != PackageInfoSchemaVersion || info.PackageID == "" || info.PackageChecksum == "" || info.ArtifactSize < 1 {
		return fmt.Errorf("%w: invalid package info header", ErrInvalidPackage)
	}
	if err := validateSHA(info.PackageChecksum, "package_checksum"); err != nil {
		return err
	}
	if err := ValidateManifest(info.Manifest); err != nil {
		return err
	}
	if info.PackageID != info.Manifest.PackageID {
		return fmt.Errorf("%w: package info ID differs from manifest", ErrInvalidPackage)
	}
	return nil
}

func ValidatePayload(payload RuntimePayload) error {
	if payload.SchemaVersion != RuntimePayloadSchemaVersion || payload.CompilerVersion != CompilerVersion || strings.TrimSpace(payload.SourceManifestID) == "" {
		return fmt.Errorf("%w: invalid payload header", ErrInvalidPayload)
	}
	if err := matcherprovider.ValidateDescriptor(payload.Provider); err != nil {
		return fmt.Errorf("%w: provider: %v", ErrInvalidPayload, err)
	}
	if payload.RecordCount < 1 || payload.EntryCount != len(payload.Entries) || payload.EntryCount < 1 {
		return fmt.Errorf("%w: invalid record or entry count", ErrInvalidPayload)
	}
	seenRecords := map[string]struct{}{}
	seenEntries := map[string]struct{}{}
	for index, entry := range payload.Entries {
		for field, value := range map[string]string{
			"normalized_query":         entry.NormalizedQuery,
			"provider_record_id":       entry.ProviderRecordID,
			"primary_name":             entry.PrimaryName,
			"matched_value":            entry.MatchedValue,
			"normalized_matched_value": entry.NormalizedMatchedValue,
		} {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("%w: entries[%d].%s is required", ErrInvalidPayload, index, field)
			}
		}
		if entry.NormalizedQuery != normalize(entry.MatchedValue) || entry.NormalizedMatchedValue != normalize(entry.MatchedValue) {
			return fmt.Errorf("%w: entries[%d] normalized value mismatch", ErrInvalidPayload, index)
		}
		if entry.ScoreBasisPoints < 0 || entry.ScoreBasisPoints > 10000 || !entry.Exact || len(entry.SourceAssertions) == 0 {
			return fmt.Errorf("%w: entries[%d] invalid match attributes", ErrInvalidPayload, index)
		}
		key := string(entry.MatchRoute) + "\x1f" + entry.NormalizedQuery + "\x1f" + entry.ProviderRecordID + "\x1f" + entry.MatchedValue
		if _, exists := seenEntries[key]; exists {
			return fmt.Errorf("%w: duplicate entry %q", ErrInvalidPayload, key)
		}
		seenEntries[key] = struct{}{}
		seenRecords[entry.ProviderRecordID] = struct{}{}
	}
	if len(seenRecords) != payload.RecordCount {
		return fmt.Errorf("%w: unique provider record count=%d expected %d", ErrInvalidPayload, len(seenRecords), payload.RecordCount)
	}
	copyEntries := append([]CompiledEntry(nil), payload.Entries...)
	sort.Slice(copyEntries, func(i, j int) bool {
		left, right := copyEntries[i], copyEntries[j]
		if left.MatchRoute != right.MatchRoute {
			return left.MatchRoute < right.MatchRoute
		}
		if left.NormalizedQuery != right.NormalizedQuery {
			return left.NormalizedQuery < right.NormalizedQuery
		}
		if left.ProviderRecordID != right.ProviderRecordID {
			return left.ProviderRecordID < right.ProviderRecordID
		}
		if left.ScoreBasisPoints != right.ScoreBasisPoints {
			return left.ScoreBasisPoints > right.ScoreBasisPoints
		}
		return left.MatchedValue < right.MatchedValue
	})
	if !reflect.DeepEqual(copyEntries, payload.Entries) {
		return fmt.Errorf("%w: entries are not in canonical order", ErrInvalidPayload)
	}
	return nil
}

func validateSHA(value, field string) error {
	if len(value) != 64 {
		return fmt.Errorf("%w: %s must be a 64-character SHA-256 digest", ErrInvalidPackage, field)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("%w: %s is not hexadecimal", ErrInvalidPackage, field)
	}
	return nil
}
