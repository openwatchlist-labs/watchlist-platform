package catalogsource

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type ManifestOptions struct {
	SourceKind                string
	Authority                 string
	DatasetID                 string
	MetadataURL               string
	UpstreamVersion           string
	UpstreamChecksumAlgorithm string
	UpstreamChecksum          string
	LicenseMode               LicenseMode
	LicenseReference          string
	LocalDataFile             string
}

func BuildManifest(acquired Acquired, options ManifestOptions) (Manifest, error) {
	manifest := Manifest{
		SchemaVersion:             ManifestSchemaVersion,
		SourceKind:                strings.TrimSpace(options.SourceKind),
		Authority:                 strings.TrimSpace(options.Authority),
		DatasetID:                 strings.TrimSpace(options.DatasetID),
		SourceURL:                 acquired.SourceURL,
		MetadataURL:               strings.TrimSpace(options.MetadataURL),
		AcquisitionMethod:         acquired.Method,
		AcquiredAt:                acquired.AcquiredAt.UTC(),
		MediaType:                 acquired.MediaType,
		ContentLength:             acquired.ContentLength,
		ContentSHA256:             acquired.ContentSHA256,
		HTTPETag:                  acquired.ETag,
		HTTPLastModified:          acquired.LastModified,
		UpstreamVersion:           strings.TrimSpace(options.UpstreamVersion),
		UpstreamChecksumAlgorithm: strings.ToLower(strings.TrimSpace(options.UpstreamChecksumAlgorithm)),
		UpstreamChecksum:          strings.ToLower(strings.TrimSpace(options.UpstreamChecksum)),
		LicenseMode:               options.LicenseMode,
		LicenseReference:          strings.TrimSpace(options.LicenseReference),
		LocalDataFile:             strings.TrimSpace(options.LocalDataFile),
		AcquirerVersion:           AcquirerVersion,
	}
	manifest.ManifestID = hashID("catalog_source_manifest_", manifestForID(manifest))
	manifest.ManifestChecksum = manifestChecksum(manifest)
	if err := ValidateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func ValidateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != ManifestSchemaVersion || manifest.AcquirerVersion != AcquirerVersion {
		return fmt.Errorf("%w: invalid manifest contract", ErrInvalidSource)
	}
	if manifest.ManifestID == "" || manifest.SourceKind == "" || manifest.Authority == "" || manifest.DatasetID == "" || manifest.SourceURL == "" || manifest.AcquiredAt.IsZero() || manifest.MediaType == "" || manifest.ContentLength < 1 || len(manifest.ContentSHA256) != 64 || manifest.LicenseReference == "" || manifest.LocalDataFile == "" {
		return fmt.Errorf("%w: incomplete source manifest", ErrInvalidSource)
	}
	if manifest.AcquisitionMethod != AcquisitionHTTPS && manifest.AcquisitionMethod != AcquisitionLocal {
		return fmt.Errorf("%w: invalid acquisition method", ErrInvalidSource)
	}
	switch manifest.LicenseMode {
	case LicenseGovernmentPublic, LicenseNonCommercial, LicenseCommercial:
	default:
		return fmt.Errorf("%w: invalid license mode", ErrInvalidSource)
	}
	if manifest.UpstreamChecksum != "" {
		if manifest.UpstreamChecksumAlgorithm != "sha1" && manifest.UpstreamChecksumAlgorithm != "sha256" {
			return fmt.Errorf("%w: unsupported upstream checksum algorithm", ErrInvalidSource)
		}
	}
	if manifest.ManifestID != hashID("catalog_source_manifest_", manifestForID(manifest)) {
		return fmt.Errorf("%w: manifest ID mismatch", ErrInvalidSource)
	}
	if manifest.ManifestChecksum != manifestChecksum(manifest) {
		return fmt.Errorf("%w: manifest checksum mismatch", ErrInvalidSource)
	}
	return nil
}

func manifestForID(value Manifest) Manifest {
	copy := value
	copy.ManifestID = ""
	copy.ManifestChecksum = ""
	return copy
}

func manifestChecksum(value Manifest) string {
	copy := value
	copy.ManifestChecksum = ""
	return digest(copy)
}

func hashID(prefix string, value any) string { return prefix + digest(value)[:24] }
func digest(value any) string {
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
