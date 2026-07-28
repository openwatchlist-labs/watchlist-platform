package ofacadvanced

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
)

const ParitySchemaVersion = "ofac-advanced-parity/v1alpha1"

type ParitySummary struct {
	AdvancedRecords            int `json:"advanced_records"`
	LegacyRecords              int `json:"legacy_records"`
	LinkedUIDs                 int `json:"linked_uids"`
	AdvancedOnly               int `json:"advanced_only"`
	LegacyOnly                 int `json:"legacy_only"`
	PrimaryNameDifferences     int `json:"primary_name_differences"`
	EntityTypeDifferences      int `json:"entity_type_differences"`
	ProgramDifferences         int `json:"program_differences"`
	AliasCountDifferences      int `json:"alias_count_differences"`
	AddressCountDifferences    int `json:"address_count_differences"`
	IdentifierCountDifferences int `json:"identifier_count_differences"`
}

type ParityLink struct {
	UID                  string `json:"uid"`
	PrimaryNameEqual     bool   `json:"primary_name_equal"`
	EntityTypeEqual      bool   `json:"entity_type_equal"`
	ProgramsEqual        bool   `json:"programs_equal"`
	AliasCountEqual      bool   `json:"alias_count_equal"`
	AddressCountEqual    bool   `json:"address_count_equal"`
	IdentifierCountEqual bool   `json:"identifier_count_equal"`
}

type ParityReport struct {
	SchemaVersion    string        `json:"schema_version"`
	ReportID         string        `json:"report_id"`
	ReportChecksum   string        `json:"report_checksum"`
	AdvancedCatalog  string        `json:"advanced_catalog_checksum"`
	LegacyCatalog    string        `json:"legacy_catalog_checksum"`
	Summary          ParitySummary `json:"summary"`
	Links            []ParityLink  `json:"links"`
	AdvancedOnlyUIDs []string      `json:"advanced_only_uids,omitempty"`
	LegacyOnlyUIDs   []string      `json:"legacy_only_uids,omitempty"`
}

func CompareCatalogs(advanced, legacy ofaccatalog.Catalog) (ParityReport, error) {
	if err := ofaccatalog.ValidateCatalog(advanced); err != nil {
		return ParityReport{}, fmt.Errorf("validate advanced catalog: %w", err)
	}
	if err := ofaccatalog.ValidateCatalog(legacy); err != nil {
		return ParityReport{}, fmt.Errorf("validate legacy catalog: %w", err)
	}
	am := map[string]ofaccatalog.DirectListRecord{}
	lm := map[string]ofaccatalog.DirectListRecord{}
	for _, r := range advanced.Records {
		am[r.SourceUID] = r
	}
	for _, r := range legacy.Records {
		lm[r.SourceUID] = r
	}
	r := ParityReport{SchemaVersion: ParitySchemaVersion, AdvancedCatalog: advanced.CatalogChecksum, LegacyCatalog: legacy.CatalogChecksum, Summary: ParitySummary{AdvancedRecords: len(advanced.Records), LegacyRecords: len(legacy.Records)}}
	for uid, ar := range am {
		lr, ok := lm[uid]
		if !ok {
			r.AdvancedOnlyUIDs = append(r.AdvancedOnlyUIDs, uid)
			continue
		}
		link := ParityLink{UID: uid, PrimaryNameEqual: ar.PrimaryName == lr.PrimaryName, EntityTypeEqual: ar.EntityType == lr.EntityType, ProgramsEqual: equalStrings(ar.Programs, lr.Programs), AliasCountEqual: len(ar.Aliases) == len(lr.Aliases), AddressCountEqual: len(ar.Addresses) == len(lr.Addresses), IdentifierCountEqual: len(ar.Identifiers) == len(lr.Identifiers)}
		r.Links = append(r.Links, link)
		r.Summary.LinkedUIDs++
		if !link.PrimaryNameEqual {
			r.Summary.PrimaryNameDifferences++
		}
		if !link.EntityTypeEqual {
			r.Summary.EntityTypeDifferences++
		}
		if !link.ProgramsEqual {
			r.Summary.ProgramDifferences++
		}
		if !link.AliasCountEqual {
			r.Summary.AliasCountDifferences++
		}
		if !link.AddressCountEqual {
			r.Summary.AddressCountDifferences++
		}
		if !link.IdentifierCountEqual {
			r.Summary.IdentifierCountDifferences++
		}
	}
	for uid := range lm {
		if _, ok := am[uid]; !ok {
			r.LegacyOnlyUIDs = append(r.LegacyOnlyUIDs, uid)
		}
	}
	r.Summary.AdvancedOnly = len(r.AdvancedOnlyUIDs)
	r.Summary.LegacyOnly = len(r.LegacyOnlyUIDs)
	sort.Strings(r.AdvancedOnlyUIDs)
	sort.Strings(r.LegacyOnlyUIDs)
	sort.Slice(r.Links, func(i, j int) bool {
		return numericOrFallback(r.Links[i].UID, 0) < numericOrFallback(r.Links[j].UID, 0)
	})
	material := r
	material.ReportID = ""
	material.ReportChecksum = ""
	b, err := json.Marshal(material)
	if err != nil {
		return ParityReport{}, err
	}
	sum := sha256.Sum256(b)
	r.ReportChecksum = hex.EncodeToString(sum[:])
	r.ReportID = "ofac_advanced_parity_" + r.ReportChecksum[:24]
	return r, nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
