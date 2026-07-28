package ofacsource

import (
	"encoding/hex"
	"fmt"
	"strings"
)

func ValidateManifest(m SourceManifest) error {
	if m.SchemaVersion != ManifestSchemaVersion {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidSource, ManifestSchemaVersion)
	}
	for k, v := range map[string]string{"manifest_id": m.ManifestID, "authority": m.Authority, "dataset_id": m.DatasetID, "source_url": m.SourceURL, "media_type": m.MediaType, "content_sha256": m.ContentSHA256, "xml_namespace": m.XMLNamespace, "publish_date": m.PublishDate, "parser_version": m.ParserVersion} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidSource, k)
		}
	}
	if m.DatasetID != "ofac-sdn" {
		return fmt.Errorf("%w: unsupported dataset", ErrInvalidSource)
	}
	switch m.ParserVersion {
	case ParserVersion:
		if m.XMLNamespace != LegacyXMLNamespace || (m.SourceFormat != "" && m.SourceFormat != "legacy_xml") {
			return fmt.Errorf("%w: unsupported legacy parser namespace or format", ErrInvalidSource)
		}
	case AdvancedParserVersion, PriorAdvancedParserVersion:
		if m.XMLNamespace != AdvancedXMLNamespace || m.SourceFormat != "ofac_advanced_xml" || m.XMLSchemaVersion != "3" || strings.TrimSpace(m.SchemaLocation) == "" {
			return fmt.Errorf("%w: unsupported Advanced XML parser namespace, format, or schema", ErrInvalidSource)
		}
	default:
		return fmt.Errorf("%w: unsupported parser_version", ErrInvalidSource)
	}
	if m.AcquisitionMethod != AcquisitionHTTP && m.AcquisitionMethod != AcquisitionLocal {
		return fmt.Errorf("%w: unsupported acquisition_method", ErrInvalidSource)
	}
	if m.AcquiredAt.IsZero() || m.ContentLength <= 0 || m.DeclaredRecordCount <= 0 {
		return fmt.Errorf("%w: acquired_at, content_length, and record_count are required", ErrInvalidSource)
	}
	raw, err := hex.DecodeString(m.ContentSHA256)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("%w: invalid content_sha256", ErrInvalidSource)
	}
	expected, err := assignManifestID(m)
	if err != nil {
		return err
	}
	if expected.ManifestID != m.ManifestID {
		return fmt.Errorf("%w: manifest_id mismatch", ErrInvalidSource)
	}
	return nil
}
