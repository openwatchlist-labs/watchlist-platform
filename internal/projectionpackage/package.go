package projectionpackage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/candidatescoring"
)

const compilerID = "openwatchlist-projection-package-go-v1"

func decodeStrict(path string, destination any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func LoadCatalogDescriptor(path string) (CatalogDescriptor, error) {
	var descriptor CatalogDescriptor
	if err := decodeStrict(path, &descriptor); err != nil {
		return CatalogDescriptor{}, fmt.Errorf("decode catalog descriptor: %w", err)
	}
	if descriptor.CatalogPackagePath != "" && !filepath.IsAbs(descriptor.CatalogPackagePath) {
		descriptor.CatalogPackagePath = filepath.Clean(filepath.Join(filepath.Dir(path), descriptor.CatalogPackagePath))
	}
	if err := validateCatalogDescriptor(descriptor); err != nil {
		return CatalogDescriptor{}, err
	}
	if err := ValidateCatalogPackageFile(descriptor); err != nil {
		return CatalogDescriptor{}, err
	}
	return descriptor, nil
}

func LoadCanonicalInput(path string) (CanonicalInput, error) {
	var input CanonicalInput
	if err := decodeStrict(path, &input); err != nil {
		return CanonicalInput{}, fmt.Errorf("decode canonical projection input: %w", err)
	}
	if input.SchemaVersion != CanonicalInputSchemaV1 {
		return CanonicalInput{}, fmt.Errorf("input schema_version %q is not %q", input.SchemaVersion, CanonicalInputSchemaV1)
	}
	return input, nil
}

func Compile(descriptor CatalogDescriptor, input CanonicalInput, outputRoot string) (Package, error) {
	if err := validateCatalogDescriptor(descriptor); err != nil {
		return Package{}, err
	}
	if err := validateInputBinding(descriptor, input); err != nil {
		return Package{}, err
	}
	if len(input.Records) != descriptor.RecordCount {
		return Package{}, fmt.Errorf("source record count %d does not match catalog descriptor %d", len(input.Records), descriptor.RecordCount)
	}

	seen := make(map[string]struct{}, len(input.Records))
	projections := make([]candidateWithID, 0, descriptor.RetrievableCandidateCount)
	retrievableIDs := make([]string, 0, descriptor.RetrievableCandidateCount)
	for _, record := range input.Records {
		id := strings.TrimSpace(record.CandidateID)
		if id == "" {
			return Package{}, errors.New("candidate_id is required")
		}
		if _, exists := seen[id]; exists {
			return Package{}, fmt.Errorf("duplicate candidate_id %q", id)
		}
		seen[id] = struct{}{}
		if !record.Retrievable {
			continue
		}
		candidate := normalizeRecord(record)
		projections = append(projections, candidateWithID{id: id, candidate: candidate})
		retrievableIDs = append(retrievableIDs, id)
	}
	if len(projections) != descriptor.RetrievableCandidateCount {
		return Package{}, fmt.Errorf("retrievable projection count %d does not match catalog descriptor %d", len(projections), descriptor.RetrievableCandidateCount)
	}
	sort.Slice(projections, func(i, j int) bool { return projections[i].id < projections[j].id })
	sort.Strings(retrievableIDs)
	candidateIDsDigest := digestCandidateIDs(retrievableIDs)
	if candidateIDsDigest != descriptor.RetrievableCandidateIDsSHA256 {
		return Package{}, fmt.Errorf("retrievable candidate coverage checksum %s does not match catalog descriptor %s", candidateIDsDigest, descriptor.RetrievableCandidateIDsSHA256)
	}

	document := ProjectionDocument{SchemaVersion: ProjectionRegistrySchemaV1, Candidates: make([]candidatescoring.Candidate, 0, len(projections))}
	for _, entry := range projections {
		document.Candidates = append(document.Candidates, entry.candidate)
	}
	projectionBytes, err := marshalCanonical(document)
	if err != nil {
		return Package{}, err
	}
	projectionDigest := digestBytes(projectionBytes)
	manifest := Manifest{
		SchemaVersion:        ManifestSchemaV1,
		Provider:             descriptor.Provider,
		CatalogID:            descriptor.CatalogID,
		ComponentID:          descriptor.ComponentID,
		ComponentVersion:     descriptor.ComponentVersion,
		CatalogPackageSHA256: descriptor.CatalogPackageSHA256,
		NormalizationProfile: descriptor.NormalizationProfile,
		SourceRecordCount:    descriptor.RecordCount,
		ProjectionCount:      len(document.Candidates),
		CandidateIDsSHA256:   candidateIDsDigest,
		ProjectionsSHA256:    projectionDigest,
		Compiler:             compilerID,
	}
	manifestBytes, err := marshalCanonical(manifest)
	if err != nil {
		return Package{}, err
	}
	filesBytes := []byte(fmt.Sprintf("%s  manifest.json\n%s  projections.json\n", digestBytes(manifestBytes), projectionDigest))
	packageDigest := digestBytes(filesBytes)
	if outputRoot == "" {
		return Package{}, errors.New("output root is required")
	}
	if err := os.MkdirAll(outputRoot, 0o755); err != nil {
		return Package{}, err
	}
	finalDirectory := filepath.Join(outputRoot, packageDigest)
	temporaryDirectory, err := os.MkdirTemp(outputRoot, ".projection-package-")
	if err != nil {
		return Package{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(temporaryDirectory)
		}
	}()
	for name, contents := range map[string][]byte{
		"manifest.json":    manifestBytes,
		"projections.json": projectionBytes,
		"FILES.sha256":     filesBytes,
		"PACKAGE.sha256":   []byte(packageDigest + "\n"),
	} {
		if err := os.WriteFile(filepath.Join(temporaryDirectory, name), contents, 0o644); err != nil {
			return Package{}, err
		}
	}
	if _, err := os.Stat(finalDirectory); err == nil {
		existing, loadErr := LoadPackage(finalDirectory)
		if loadErr != nil {
			return Package{}, fmt.Errorf("existing projection package is invalid: %w", loadErr)
		}
		cleanup = true
		return existing, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Package{}, err
	}
	if err := os.Rename(temporaryDirectory, finalDirectory); err != nil {
		return Package{}, err
	}
	cleanup = false
	return LoadPackage(finalDirectory)
}

type candidateWithID struct {
	id        string
	candidate candidatescoring.Candidate
}

func normalizeRecord(record SourceRecord) candidatescoring.Candidate {
	return candidatescoring.Candidate{
		CandidateID:  strings.TrimSpace(record.CandidateID),
		Names:        uniqueSorted(record.Names, normalizeText),
		Identifiers:  normalizeIdentifiers(record.Identifiers),
		Countries:    uniqueSorted(record.Countries, normalizeCountry),
		DatesOfBirth: uniqueSorted(record.DatesOfBirth, strings.TrimSpace),
		EntityType:   normalizeEntityType(record.EntityType),
	}
}

func LoadPackage(directory string) (Package, error) {
	manifestPath := filepath.Join(directory, "manifest.json")
	projectionsPath := filepath.Join(directory, "projections.json")
	filesPath := filepath.Join(directory, "FILES.sha256")
	packagePath := filepath.Join(directory, "PACKAGE.sha256")
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil {
		return Package{}, fmt.Errorf("read projection manifest: %w", err)
	}
	projectionRaw, err := os.ReadFile(projectionsPath)
	if err != nil {
		return Package{}, fmt.Errorf("read projection payload: %w", err)
	}
	filesRaw, err := os.ReadFile(filesPath)
	if err != nil {
		return Package{}, fmt.Errorf("read projection file checksums: %w", err)
	}
	packageRaw, err := os.ReadFile(packagePath)
	if err != nil {
		return Package{}, fmt.Errorf("read projection package checksum: %w", err)
	}
	var manifest Manifest
	if err := decodeBytesStrict(manifestRaw, &manifest); err != nil {
		return Package{}, fmt.Errorf("decode projection manifest: %w", err)
	}
	if manifest.SchemaVersion != ManifestSchemaV1 {
		return Package{}, fmt.Errorf("manifest schema_version %q is not %q", manifest.SchemaVersion, ManifestSchemaV1)
	}
	var projections ProjectionDocument
	if err := decodeBytesStrict(projectionRaw, &projections); err != nil {
		return Package{}, fmt.Errorf("decode projection payload: %w", err)
	}
	if projections.SchemaVersion != ProjectionRegistrySchemaV1 {
		return Package{}, fmt.Errorf("projection schema_version %q is not %q", projections.SchemaVersion, ProjectionRegistrySchemaV1)
	}
	if len(projections.Candidates) != manifest.ProjectionCount {
		return Package{}, fmt.Errorf("projection count %d does not match manifest %d", len(projections.Candidates), manifest.ProjectionCount)
	}
	ids := make([]string, 0, len(projections.Candidates))
	last := ""
	for _, candidate := range projections.Candidates {
		id := strings.TrimSpace(candidate.CandidateID)
		if id == "" || (last != "" && id <= last) {
			return Package{}, errors.New("projection candidate IDs must be non-empty, unique, and sorted")
		}
		last = id
		ids = append(ids, id)
	}
	if digestCandidateIDs(ids) != manifest.CandidateIDsSHA256 {
		return Package{}, errors.New("projection candidate coverage checksum mismatch")
	}
	manifestDigest := digestBytes(manifestRaw)
	projectionDigest := digestBytes(projectionRaw)
	if projectionDigest != manifest.ProjectionsSHA256 {
		return Package{}, errors.New("projection payload checksum mismatch")
	}
	expectedFiles := []byte(fmt.Sprintf("%s  manifest.json\n%s  projections.json\n", manifestDigest, projectionDigest))
	if !bytes.Equal(filesRaw, expectedFiles) {
		return Package{}, errors.New("FILES.sha256 content mismatch")
	}
	packageDigest := digestBytes(filesRaw)
	if strings.TrimSpace(string(packageRaw)) != packageDigest {
		return Package{}, errors.New("PACKAGE.sha256 content mismatch")
	}
	if filepath.Base(filepath.Clean(directory)) != packageDigest {
		return Package{}, errors.New("projection package directory is not checksum-addressed")
	}
	return Package{
		Directory:       directory,
		PackageSHA256:   packageDigest,
		Manifest:        manifest,
		Projections:     projections,
		ManifestPath:    manifestPath,
		ProjectionsPath: projectionsPath,
	}, nil
}

func decodeBytesStrict(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func validateCatalogDescriptor(descriptor CatalogDescriptor) error {
	if descriptor.SchemaVersion != CatalogDescriptorSchemaV1 {
		return fmt.Errorf("catalog descriptor schema_version %q is not %q", descriptor.SchemaVersion, CatalogDescriptorSchemaV1)
	}
	values := []string{descriptor.Provider, descriptor.CatalogID, descriptor.ComponentID, descriptor.ComponentVersion, descriptor.CatalogPackagePath, descriptor.NormalizationProfile}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return errors.New("catalog descriptor lineage fields are required")
		}
	}
	if !isSHA256(descriptor.CatalogPackageSHA256) || !isSHA256(descriptor.RetrievableCandidateIDsSHA256) {
		return errors.New("catalog descriptor SHA-256 fields must be 64 lowercase hexadecimal characters")
	}
	if descriptor.RecordCount < 0 || descriptor.RetrievableCandidateCount < 0 || descriptor.RetrievableCandidateCount > descriptor.RecordCount {
		return errors.New("catalog descriptor counts are invalid")
	}
	return nil
}

// ValidateCatalogPackageFile proves that the descriptor points to the exact immutable catalog bytes.
func ValidateCatalogPackageFile(descriptor CatalogDescriptor) error {
	raw, err := os.ReadFile(descriptor.CatalogPackagePath)
	if err != nil {
		return fmt.Errorf("read catalog package: %w", err)
	}
	if actual := digestBytes(raw); actual != descriptor.CatalogPackageSHA256 {
		return fmt.Errorf("catalog package checksum %s does not match descriptor %s", actual, descriptor.CatalogPackageSHA256)
	}
	return nil
}

func validateInputBinding(descriptor CatalogDescriptor, input CanonicalInput) error {
	if input.SchemaVersion != CanonicalInputSchemaV1 {
		return fmt.Errorf("input schema_version %q is not %q", input.SchemaVersion, CanonicalInputSchemaV1)
	}
	pairs := [][3]string{
		{"provider", descriptor.Provider, input.Provider},
		{"catalog_id", descriptor.CatalogID, input.CatalogID},
		{"component_id", descriptor.ComponentID, input.ComponentID},
		{"component_version", descriptor.ComponentVersion, input.ComponentVersion},
		{"catalog_package_sha256", descriptor.CatalogPackageSHA256, input.CatalogPackageSHA256},
		{"normalization_profile", descriptor.NormalizationProfile, input.NormalizationProfile},
	}
	for _, pair := range pairs {
		if pair[1] != pair[2] {
			return fmt.Errorf("canonical input %s %q does not match catalog descriptor %q", pair[0], pair[2], pair[1])
		}
	}
	return nil
}

func marshalCanonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func digestCandidateIDs(ids []string) string {
	return digestBytes([]byte(strings.Join(ids, "\n") + "\n"))
}

func digestBytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func isSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
