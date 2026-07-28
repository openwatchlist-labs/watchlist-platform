package providerentity

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
)

const FTMAdapterVersion = "opensanctions-ftm-adapter/v0.1.2"

type FTMImportOptions struct {
	DatasetID       string
	DatasetTitle    string
	SnapshotVersion string
	SourceChecksum  string
	ProviderName    string
}

type ftmEntity struct {
	ID         string              `json:"id"`
	Schema     string              `json:"schema"`
	Caption    string              `json:"caption,omitempty"`
	Datasets   []string            `json:"datasets,omitempty"`
	Referents  []string            `json:"referents,omitempty"`
	Properties map[string][]string `json:"properties"`
	FirstSeen  string              `json:"first_seen,omitempty"`
	LastSeen   string              `json:"last_seen,omitempty"`
	LastChange string              `json:"last_change,omitempty"`
}

func ImportFTM(reader io.Reader, options FTMImportOptions) (Snapshot, error) {
	if strings.TrimSpace(options.DatasetID) == "" || strings.TrimSpace(options.SnapshotVersion) == "" || len(strings.TrimSpace(options.SourceChecksum)) != 64 {
		return Snapshot{}, fmt.Errorf("%w: incomplete FtM import options", ErrInvalidProviderCatalog)
	}
	if strings.TrimSpace(options.ProviderName) == "" {
		options.ProviderName = "opensanctions-" + options.DatasetID
	}
	all := map[string]ftmEntity{}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		var entity ftmEntity
		if err := json.Unmarshal([]byte(raw), &entity); err != nil {
			return Snapshot{}, fmt.Errorf("%w: decode FtM line %d: %v", ErrInvalidProviderCatalog, line, err)
		}
		if entity.ID == "" || entity.Schema == "" || entity.Properties == nil {
			return Snapshot{}, fmt.Errorf("%w: incomplete FtM line %d", ErrInvalidProviderCatalog, line)
		}
		if _, exists := all[entity.ID]; exists {
			return Snapshot{}, fmt.Errorf("%w: duplicate FtM entity %q", ErrInvalidProviderCatalog, entity.ID)
		}
		all[entity.ID] = entity
	}
	if err := scanner.Err(); err != nil {
		return Snapshot{}, fmt.Errorf("%w: scan FtM: %v", ErrInvalidProviderCatalog, err)
	}

	addresses := map[string]Address{}
	targets := buildFTMTargetResolver(all)
	sanctionsByTarget := map[string][]ftmEntity{}
	for _, entity := range all {
		switch entity.Schema {
		case "Address":
			addresses[entity.ID] = addressFromFTM(entity)
		case "Sanction":
			for _, targetReference := range entity.Properties["entity"] {
				if targetID, ok := targets.resolve(targetReference); ok {
					sanctionsByTarget[targetID] = append(sanctionsByTarget[targetID], entity)
				}
			}
		}
	}

	entities := make([]SnapshotEntity, 0)
	for _, raw := range all {
		entityType, ok := ftmCandidateType(raw.Schema)
		if !ok {
			continue
		}
		primary := strings.TrimSpace(raw.Caption)
		if primary == "" {
			primary = first(raw.Properties["name"])
		}
		if primary == "" {
			return Snapshot{}, fmt.Errorf("%w: target %q has no name", ErrInvalidProviderCatalog, raw.ID)
		}
		entity := SnapshotEntity{
			EntityID:     raw.ID,
			Schema:       raw.Schema,
			EntityType:   entityType,
			PrimaryName:  primary,
			Aliases:      aliasesFromFTM(raw, primary),
			Addresses:    addressesFromFTM(raw, addresses),
			Identifiers:  identifiersFromFTM(raw),
			DatesOfBirth: sortedUnique(raw.Properties["birthDate"]),
			Remarks:      strings.Join(sortedUnique(raw.Properties["notes"]), " | "),
			Attributes: map[string]string{
				"ftm_adapter_version": FTMAdapterVersion,
				"ftm_schema":          raw.Schema,
			},
		}
		if len(raw.Datasets) > 0 {
			entity.Attributes["datasets"] = strings.Join(sortedUnique(raw.Datasets), ",")
		}
		if len(raw.Referents) > 0 {
			entity.Attributes["referents"] = strings.Join(sortedUnique(raw.Referents), ",")
		}
		memberships := []SourceMembership{{
			SourceID:       "opensanctions",
			Authority:      "OpenSanctions",
			ListID:         options.DatasetID,
			SourceRecordID: raw.ID,
			Active:         true,
		}}
		targetRecordIDs := []string(nil)
		if options.DatasetID == "us_ofac_sdn" {
			targetRecordIDs = append(targetRecordIDs, numericRecordIDs(raw.Properties["recordId"])...)
			targetRecordIDs = append(targetRecordIDs, ofacRecordIDsFromReferents(raw.Referents)...)
			targetRecordIDs = sortedUnique(targetRecordIDs)
			for _, recordID := range targetRecordIDs {
				memberships = append(memberships, ofacMembership(recordID, canonicalOFACPrograms(raw.Properties["program"])))
			}
		}
		var providerProgramIDs []string
		providerProgramIDs = append(providerProgramIDs, raw.Properties["programId"]...)
		for _, sanction := range sanctionsByTarget[raw.ID] {
			programs := canonicalOFACPrograms(sanction.Properties["program"])
			providerProgramIDs = append(providerProgramIDs, sanction.Properties["programId"]...)
			recordIDs := numericRecordIDs(sanction.Properties["recordId"])
			if len(recordIDs) == 0 {
				recordIDs = targetRecordIDs
			}
			for _, recordID := range recordIDs {
				memberships = append(memberships, ofacMembership(recordID, programs))
			}
		}
		if values := sortedUnique(providerProgramIDs); len(values) > 0 {
			entity.Attributes["ofac_program_ids"] = strings.Join(values, ",")
		}
		entity.SourceMemberships = mergeSourceMemberships(memberships)
		canonicalizeSnapshotEntity(&entity)
		entities = append(entities, entity)
	}
	if len(entities) == 0 {
		return Snapshot{}, fmt.Errorf("%w: no supported target entities in FtM input", ErrInvalidProviderCatalog)
	}
	sort.Slice(entities, func(i, j int) bool { return entities[i].EntityID < entities[j].EntityID })
	snapshot := Snapshot{
		SchemaVersion:   SnapshotSchemaVersion,
		SnapshotVersion: strings.TrimSpace(options.SnapshotVersion),
		ProviderName:    strings.TrimSpace(options.ProviderName),
		EntityCount:     len(entities),
		Entities:        entities,
	}
	snapshot.SnapshotID = hashID("provider_snapshot_", struct {
		DatasetID      string `json:"dataset_id"`
		SourceChecksum string `json:"source_checksum"`
		Version        string `json:"version"`
	}{options.DatasetID, options.SourceChecksum, options.SnapshotVersion})
	snapshot.SnapshotChecksum = SnapshotChecksum(snapshot)
	if err := ValidateSnapshot(snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

type ftmTargetResolver struct {
	aliases   map[string]string
	ambiguous map[string]bool
}

func buildFTMTargetResolver(all map[string]ftmEntity) ftmTargetResolver {
	resolver := ftmTargetResolver{aliases: map[string]string{}, ambiguous: map[string]bool{}}
	for _, entity := range all {
		if _, ok := ftmCandidateType(entity.Schema); !ok {
			continue
		}
		aliases := append([]string{entity.ID}, entity.Referents...)
		for _, alias := range aliases {
			key := normalizeFTMReference(alias)
			if key == "" || resolver.ambiguous[key] {
				continue
			}
			if current, exists := resolver.aliases[key]; exists && current != entity.ID {
				delete(resolver.aliases, key)
				resolver.ambiguous[key] = true
				continue
			}
			resolver.aliases[key] = entity.ID
		}
	}
	return resolver
}

func (resolver ftmTargetResolver) resolve(reference string) (string, bool) {
	key := normalizeFTMReference(reference)
	if key == "" || resolver.ambiguous[key] {
		return "", false
	}
	value, ok := resolver.aliases[key]
	return value, ok
}

func normalizeFTMReference(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func numericRecordIDs(values []string) []string {
	var recordIDs []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		valid := true
		for _, r := range value {
			if r < '0' || r > '9' {
				valid = false
				break
			}
		}
		if valid {
			recordIDs = append(recordIDs, value)
		}
	}
	return sortedUnique(recordIDs)
}

func canonicalOFACPrograms(values []string) []string {
	// OpenSanctions exposes the source program code in Sanction.program and
	// a provider taxonomy identifier (for example US-GLOMAG) in
	// Sanction.programId. Only the source program code belongs in the OFAC
	// source membership used for direct-list comparison. Provider taxonomy
	// identifiers are retained separately in entity attributes.
	return sortedUnique(values)
}

func ofacMembership(recordID string, programs []string) SourceMembership {
	return SourceMembership{
		SourceID:       "ofac-sls",
		Authority:      "U.S. Department of the Treasury, Office of Foreign Assets Control",
		ListID:         "SDN",
		SourceRecordID: strings.TrimSpace(recordID),
		Programs:       sortedUnique(programs),
		Active:         true,
	}
}

func ofacRecordIDsFromReferents(referents []string) []string {
	var recordIDs []string
	for _, referent := range referents {
		value := strings.ToLower(strings.TrimSpace(referent))
		if !strings.HasPrefix(value, "ofac-") {
			continue
		}
		recordIDs = append(recordIDs, numericRecordIDs([]string{strings.TrimPrefix(value, "ofac-")})...)
	}
	return sortedUnique(recordIDs)
}

func mergeSourceMemberships(values []SourceMembership) []SourceMembership {
	byKey := make(map[string]SourceMembership, len(values))
	for _, value := range values {
		if strings.TrimSpace(value.SourceRecordID) == "" {
			continue
		}
		value.Programs = sortedUnique(value.Programs)
		key := membershipKey(value)
		if current, ok := byKey[key]; ok {
			current.Programs = sortedUnique(append(current.Programs, value.Programs...))
			current.Active = current.Active || value.Active
			byKey[key] = current
			continue
		}
		byKey[key] = value
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]SourceMembership, 0, len(keys))
	for _, key := range keys {
		out = append(out, byKey[key])
	}
	return out
}

func ProjectFTM(snapshot Snapshot) (Catalog, error) {
	return projectWithAdapter(snapshot, FTMAdapterVersion)
}

func projectWithAdapter(snapshot Snapshot, adapterVersion string) (Catalog, error) {
	if err := ValidateSnapshot(snapshot); err != nil {
		return Catalog{}, err
	}
	entities := make([]Entity, 0, len(snapshot.Entities))
	for _, source := range snapshot.Entities {
		entity := Entity{ProviderRecordID: "provider:" + snapshot.ProviderName + ":" + source.EntityID, ProviderEntityID: source.EntityID, EntityType: source.EntityType, PrimaryName: strings.TrimSpace(source.PrimaryName), Aliases: append([]Alias(nil), source.Aliases...), Addresses: append([]Address(nil), source.Addresses...), Identifiers: append([]Identifier(nil), source.Identifiers...), DatesOfBirth: sortedUnique(source.DatesOfBirth), Remarks: strings.TrimSpace(source.Remarks), SourceMemberships: append([]SourceMembership(nil), source.SourceMemberships...), Attributes: cloneMap(source.Attributes)}
		canonicalizeEntity(&entity)
		entities = append(entities, entity)
	}
	sort.Slice(entities, func(i, j int) bool { return entities[i].ProviderEntityID < entities[j].ProviderEntityID })
	catalog := Catalog{SchemaVersion: CatalogSchemaVersion, CatalogID: "provider-entity-" + snapshot.ProviderName, CatalogVersion: snapshot.SnapshotVersion + "-" + snapshot.SnapshotChecksum[:12], CatalogMode: matcherprovider.CatalogModeProviderEntity, AdapterVersion: adapterVersion, ProviderName: snapshot.ProviderName, SourceSnapshotID: snapshot.SnapshotID, SourceSnapshotSHA: snapshot.SnapshotChecksum, RecordCount: len(entities), Entities: entities}
	catalog.CatalogChecksum = CatalogChecksum(catalog)
	if err := ValidateCatalog(catalog); err != nil {
		return Catalog{}, err
	}
	return catalog, nil
}

func ftmCandidateType(schema string) (canonical.CandidateType, bool) {
	switch schema {
	case "Person":
		return canonical.CandidateIndividual, true
	case "Company", "Organization", "LegalEntity":
		return canonical.CandidateOrganization, true
	case "PublicBody":
		return canonical.CandidateGovernmentEntity, true
	case "Vessel":
		return canonical.CandidateVessel, true
	case "Airplane", "Aircraft":
		return canonical.CandidateAircraft, true
	default:
		return "", false
	}
}

func aliasesFromFTM(entity ftmEntity, primary string) []Alias {
	var aliases []Alias
	for _, spec := range []struct{ key, kind, strength string }{{"name", "name", "strong"}, {"alias", "alias", "strong"}, {"previousName", "previous_name", "medium"}, {"weakAlias", "weak_alias", "weak"}} {
		for _, value := range sortedUnique(entity.Properties[spec.key]) {
			if value != primary {
				aliases = append(aliases, Alias{Name: value, Type: spec.kind, Strength: spec.strength})
			}
		}
	}
	sort.Slice(aliases, func(i, j int) bool {
		if aliases[i].Name != aliases[j].Name {
			return aliases[i].Name < aliases[j].Name
		}
		return aliases[i].Type < aliases[j].Type
	})
	return dedupeAliases(aliases)
}

func addressesFromFTM(entity ftmEntity, indexed map[string]Address) []Address {
	var values []Address
	for _, id := range entity.Properties["addressEntity"] {
		if address, ok := indexed[id]; ok && address != (Address{}) {
			values = append(values, address)
		}
	}
	if inline := addressFromFTM(entity); inline != (Address{}) {
		values = append(values, inline)
	}
	sort.Slice(values, func(i, j int) bool { return digest(values[i]) < digest(values[j]) })
	return dedupeAddresses(values)
}

func addressFromFTM(entity ftmEntity) Address {
	address := Address{Line1: firstNonEmptyFTM(first(entity.Properties["full"]), first(entity.Properties["address"])), Line2: first(entity.Properties["street2"]), City: first(entity.Properties["city"]), Region: first(entity.Properties["region"]), PostalCode: first(entity.Properties["postalCode"])}
	if address.Line1 != "" || address.Line2 != "" || address.City != "" || address.Region != "" || address.PostalCode != "" {
		address.Country = first(entity.Properties["country"])
	}
	return address
}

func identifiersFromFTM(entity ftmEntity) []Identifier {
	mapping := []struct{ key, typ string }{{"leiCode", "Legal Entity Identifier"}, {"bic", "BIC"}, {"imoNumber", "IMO Number"}, {"passportNumber", "Passport Number"}, {"registrationNumber", "Registration Number"}, {"taxNumber", "Tax Number"}, {"accountNumber", "Account Number"}, {"idNumber", "ID Number"}}
	var out []Identifier
	for _, spec := range mapping {
		for _, value := range sortedUnique(entity.Properties[spec.key]) {
			out = append(out, Identifier{Type: spec.typ, Value: value})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Value < out[j].Value
	})
	return out
}

func canonicalizeSnapshotEntity(entity *SnapshotEntity) {
	sort.Slice(entity.Aliases, func(i, j int) bool {
		if entity.Aliases[i].Name != entity.Aliases[j].Name {
			return entity.Aliases[i].Name < entity.Aliases[j].Name
		}
		return entity.Aliases[i].Type < entity.Aliases[j].Type
	})
	sort.Slice(entity.Addresses, func(i, j int) bool { return digest(entity.Addresses[i]) < digest(entity.Addresses[j]) })
	sort.Slice(entity.Identifiers, func(i, j int) bool {
		if entity.Identifiers[i].Type != entity.Identifiers[j].Type {
			return entity.Identifiers[i].Type < entity.Identifiers[j].Type
		}
		return entity.Identifiers[i].Value < entity.Identifiers[j].Value
	})
	entity.DatesOfBirth = sortedUnique(entity.DatesOfBirth)
	entity.SourceMemberships = mergeSourceMemberships(entity.SourceMemberships)
}

func dedupeAliases(values []Alias) []Alias {
	seen := map[string]bool{}
	out := values[:0]
	for _, v := range values {
		k := v.Name + "\x1f" + v.Type
		if !seen[k] {
			seen[k] = true
			out = append(out, v)
		}
	}
	return out
}
func dedupeAddresses(values []Address) []Address {
	seen := map[string]bool{}
	out := values[:0]
	for _, v := range values {
		k := digest(v)
		if !seen[k] {
			seen[k] = true
			out = append(out, v)
		}
	}
	return out
}
func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}
func firstNonEmptyFTM(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
func SHA256Hex(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
