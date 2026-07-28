package providerentity

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
)

var ErrInvalidProviderCatalog = errors.New("invalid provider-entity catalog")

func LoadSnapshot(r io.Reader) (Snapshot, error) {
	var snapshot Snapshot
	if err := decodeStrict(r, &snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("%w: decode snapshot: %v", ErrInvalidProviderCatalog, err)
	}
	if err := ValidateSnapshot(snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func LoadCatalog(r io.Reader) (Catalog, error) {
	var catalog Catalog
	if err := decodeStrict(r, &catalog); err != nil {
		return Catalog{}, fmt.Errorf("%w: decode catalog: %v", ErrInvalidProviderCatalog, err)
	}
	if err := ValidateCatalog(catalog); err != nil {
		return Catalog{}, err
	}
	return catalog, nil
}

func LoadHybridCatalog(r io.Reader) (HybridCatalog, error) {
	var catalog HybridCatalog
	if err := decodeStrict(r, &catalog); err != nil {
		return HybridCatalog{}, fmt.Errorf("%w: decode hybrid catalog: %v", ErrInvalidProviderCatalog, err)
	}
	if err := ValidateHybridCatalog(catalog); err != nil {
		return HybridCatalog{}, err
	}
	return catalog, nil
}

func Project(snapshot Snapshot) (Catalog, error) {
	return projectWithAdapter(snapshot, AdapterVersion)
}

func projectLegacy(snapshot Snapshot) (Catalog, error) {
	if err := ValidateSnapshot(snapshot); err != nil {
		return Catalog{}, err
	}
	entities := make([]Entity, 0, len(snapshot.Entities))
	for _, source := range snapshot.Entities {
		entity := Entity{
			ProviderRecordID:  "provider:" + snapshot.ProviderName + ":" + source.EntityID,
			ProviderEntityID:  source.EntityID,
			EntityType:        source.EntityType,
			PrimaryName:       strings.TrimSpace(source.PrimaryName),
			Aliases:           append([]Alias(nil), source.Aliases...),
			Addresses:         append([]Address(nil), source.Addresses...),
			Identifiers:       append([]Identifier(nil), source.Identifiers...),
			DatesOfBirth:      sortedUnique(source.DatesOfBirth),
			Remarks:           strings.TrimSpace(source.Remarks),
			SourceMemberships: append([]SourceMembership(nil), source.SourceMemberships...),
			Attributes:        cloneMap(source.Attributes),
		}
		canonicalizeEntity(&entity)
		entities = append(entities, entity)
	}
	sort.Slice(entities, func(i, j int) bool { return entities[i].ProviderEntityID < entities[j].ProviderEntityID })
	catalog := Catalog{
		SchemaVersion:     CatalogSchemaVersion,
		CatalogID:         "provider-entity-" + snapshot.ProviderName,
		CatalogVersion:    snapshot.SnapshotVersion + "-" + snapshot.SnapshotChecksum[:12],
		CatalogMode:       matcherprovider.CatalogModeProviderEntity,
		AdapterVersion:    AdapterVersion,
		ProviderName:      snapshot.ProviderName,
		SourceSnapshotID:  snapshot.SnapshotID,
		SourceSnapshotSHA: snapshot.SnapshotChecksum,
		RecordCount:       len(entities),
		Entities:          entities,
	}
	catalog.CatalogChecksum = catalogChecksum(catalog)
	if err := ValidateCatalog(catalog); err != nil {
		return Catalog{}, err
	}
	return catalog, nil
}

func BuildHybridCatalog(base Catalog, overlay matcherprovider.CatalogReference) (HybridCatalog, error) {
	if err := ValidateCatalog(base); err != nil {
		return HybridCatalog{}, err
	}
	if overlay.CatalogMode != matcherprovider.CatalogModeDirectList || overlay.CatalogID == "" || overlay.CatalogVersion == "" || len(overlay.CatalogChecksum) != 64 {
		return HybridCatalog{}, fmt.Errorf("%w: invalid direct overlay reference", ErrInvalidProviderCatalog)
	}
	h := HybridCatalog{
		SchemaVersion:        HybridSchemaVersion,
		CatalogID:            base.CatalogID + "+" + overlay.CatalogID,
		CatalogVersion:       base.CatalogVersion + "+" + overlay.CatalogVersion,
		CatalogMode:          matcherprovider.CatalogModeHybridOverlay,
		BaseCatalog:          matcherprovider.CatalogReference{CatalogID: base.CatalogID, CatalogVersion: base.CatalogVersion, CatalogChecksum: base.CatalogChecksum, CatalogMode: base.CatalogMode},
		OfficialOverlay:      overlay,
		LinkPolicy:           "source_id_list_id_source_record_id",
		UnlinkedRecordPolicy: "retain_official_record",
	}
	h.CatalogChecksum = hybridChecksum(h)
	if err := ValidateHybridCatalog(h); err != nil {
		return HybridCatalog{}, err
	}
	return h, nil
}

func ValidateSnapshot(snapshot Snapshot) error {
	if snapshot.SchemaVersion != SnapshotSchemaVersion || snapshot.SnapshotID == "" || snapshot.SnapshotVersion == "" || snapshot.ProviderName == "" {
		return fmt.Errorf("%w: invalid snapshot header", ErrInvalidProviderCatalog)
	}
	if snapshot.EntityCount < 1 || snapshot.EntityCount != len(snapshot.Entities) {
		return fmt.Errorf("%w: snapshot entity_count mismatch", ErrInvalidProviderCatalog)
	}
	seen := map[string]bool{}
	last := ""
	for i, entity := range snapshot.Entities {
		if entity.EntityID == "" || entity.Schema == "" || entity.PrimaryName == "" || !validEntityType(entity.EntityType) || len(entity.SourceMemberships) == 0 {
			return fmt.Errorf("%w: entities[%d] is incomplete", ErrInvalidProviderCatalog, i)
		}
		if seen[entity.EntityID] || (last != "" && entity.EntityID < last) {
			return fmt.Errorf("%w: entities must be unique and sorted", ErrInvalidProviderCatalog)
		}
		seen[entity.EntityID] = true
		last = entity.EntityID
		if err := validateMemberships(entity.SourceMemberships); err != nil {
			return fmt.Errorf("%w: entities[%d]: %v", ErrInvalidProviderCatalog, i, err)
		}
	}
	if snapshot.SnapshotChecksum != snapshotChecksum(snapshot) {
		return fmt.Errorf("%w: snapshot checksum mismatch", ErrInvalidProviderCatalog)
	}
	return nil
}

func ValidateCatalog(catalog Catalog) error {
	if catalog.SchemaVersion != CatalogSchemaVersion || catalog.CatalogMode != matcherprovider.CatalogModeProviderEntity || (catalog.AdapterVersion != AdapterVersion && catalog.AdapterVersion != FTMAdapterVersion) {
		return fmt.Errorf("%w: invalid catalog header", ErrInvalidProviderCatalog)
	}
	if catalog.CatalogID == "" || catalog.CatalogVersion == "" || catalog.ProviderName == "" || catalog.SourceSnapshotID == "" || len(catalog.SourceSnapshotSHA) != 64 {
		return fmt.Errorf("%w: catalog lineage is incomplete", ErrInvalidProviderCatalog)
	}
	if catalog.RecordCount < 1 || catalog.RecordCount != len(catalog.Entities) {
		return fmt.Errorf("%w: record_count mismatch", ErrInvalidProviderCatalog)
	}
	seen := map[string]bool{}
	last := ""
	for i, entity := range catalog.Entities {
		if entity.ProviderEntityID == "" || entity.ProviderRecordID != "provider:"+catalog.ProviderName+":"+entity.ProviderEntityID || entity.PrimaryName == "" || !validEntityType(entity.EntityType) {
			return fmt.Errorf("%w: entities[%d] is invalid", ErrInvalidProviderCatalog, i)
		}
		if seen[entity.ProviderEntityID] || (last != "" && entity.ProviderEntityID < last) {
			return fmt.Errorf("%w: entities must be unique and sorted", ErrInvalidProviderCatalog)
		}
		seen[entity.ProviderEntityID] = true
		last = entity.ProviderEntityID
		if err := validateMemberships(entity.SourceMemberships); err != nil {
			return fmt.Errorf("%w: entities[%d]: %v", ErrInvalidProviderCatalog, i, err)
		}
	}
	if catalog.CatalogChecksum != catalogChecksum(catalog) {
		return fmt.Errorf("%w: catalog checksum mismatch", ErrInvalidProviderCatalog)
	}
	return nil
}

func ValidateHybridCatalog(catalog HybridCatalog) error {
	if catalog.SchemaVersion != HybridSchemaVersion || catalog.CatalogMode != matcherprovider.CatalogModeHybridOverlay || catalog.CatalogID == "" || catalog.CatalogVersion == "" {
		return fmt.Errorf("%w: invalid hybrid header", ErrInvalidProviderCatalog)
	}
	if catalog.BaseCatalog.CatalogMode != matcherprovider.CatalogModeProviderEntity || catalog.OfficialOverlay.CatalogMode != matcherprovider.CatalogModeDirectList {
		return fmt.Errorf("%w: invalid hybrid catalog modes", ErrInvalidProviderCatalog)
	}
	if catalog.LinkPolicy != "source_id_list_id_source_record_id" || catalog.UnlinkedRecordPolicy != "retain_official_record" {
		return fmt.Errorf("%w: unsupported hybrid policy", ErrInvalidProviderCatalog)
	}
	if catalog.CatalogChecksum != hybridChecksum(catalog) {
		return fmt.Errorf("%w: hybrid checksum mismatch", ErrInvalidProviderCatalog)
	}
	return nil
}

func SnapshotChecksum(snapshot Snapshot) string { return snapshotChecksum(snapshot) }
func CatalogChecksum(catalog Catalog) string    { return catalogChecksum(catalog) }

func snapshotChecksum(snapshot Snapshot) string {
	copy := snapshot
	copy.SnapshotChecksum = ""
	return digest(copy)
}

func catalogChecksum(catalog Catalog) string {
	copy := catalog
	copy.CatalogChecksum = ""
	return digest(copy)
}

func hybridChecksum(catalog HybridCatalog) string {
	copy := catalog
	copy.CatalogChecksum = ""
	return digest(copy)
}

func decodeStrict(r io.Reader, target any) error {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func validateMemberships(values []SourceMembership) error {
	seen := map[string]bool{}
	last := ""
	active := 0
	for i, membership := range values {
		if membership.SourceID == "" || membership.Authority == "" || membership.ListID == "" || membership.SourceRecordID == "" {
			return fmt.Errorf("source_memberships[%d] is incomplete", i)
		}
		key := membershipKey(membership)
		if seen[key] || (last != "" && key < last) {
			return fmt.Errorf("source_memberships must be unique and sorted")
		}
		seen[key] = true
		last = key
		if membership.Active {
			active++
		}
	}
	if active == 0 {
		return fmt.Errorf("at least one active source membership is required")
	}
	return nil
}

func membershipKey(value SourceMembership) string {
	return value.SourceID + "\x1f" + value.ListID + "\x1f" + value.SourceRecordID
}

func validEntityType(value canonical.CandidateType) bool {
	switch value {
	case canonical.CandidateAircraft, canonical.CandidateFinancialInstitution, canonical.CandidateGovernmentEntity, canonical.CandidateIndividual, canonical.CandidateJurisdiction, canonical.CandidateOrganization, canonical.CandidateVessel:
		return true
	default:
		return false
	}
}

func canonicalizeEntity(entity *Entity) {
	sort.Slice(entity.Aliases, func(i, j int) bool { return entity.Aliases[i].Name < entity.Aliases[j].Name })
	sort.Slice(entity.Addresses, func(i, j int) bool { return digest(entity.Addresses[i]) < digest(entity.Addresses[j]) })
	sort.Slice(entity.Identifiers, func(i, j int) bool {
		if entity.Identifiers[i].Type != entity.Identifiers[j].Type {
			return entity.Identifiers[i].Type < entity.Identifiers[j].Type
		}
		return entity.Identifiers[i].Value < entity.Identifiers[j].Value
	})
	sort.Slice(entity.SourceMemberships, func(i, j int) bool {
		return membershipKey(entity.SourceMemberships[i]) < membershipKey(entity.SourceMemberships[j])
	})
	for i := range entity.SourceMemberships {
		entity.SourceMemberships[i].Programs = sortedUnique(entity.SourceMemberships[i].Programs)
	}
}

func sortedUnique(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func cloneMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
