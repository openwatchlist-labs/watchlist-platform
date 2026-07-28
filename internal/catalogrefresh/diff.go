package catalogrefresh

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
)

func CatalogReference(c ofaccatalog.Catalog) CatalogRef {
	return CatalogRef{CatalogID: c.CatalogID, CatalogVersion: c.CatalogVersion, CatalogChecksum: c.CatalogChecksum, RecordCount: c.RecordCount}
}

func Diff(base, target ofaccatalog.Catalog) (DiffReport, error) {
	if err := ofaccatalog.ValidateCatalog(base); err != nil {
		return DiffReport{}, fmt.Errorf("base catalog: %w", err)
	}
	if err := ofaccatalog.ValidateCatalog(target); err != nil {
		return DiffReport{}, fmt.Errorf("target catalog: %w", err)
	}
	baseMap := recordMap(base.Records)
	targetMap := recordMap(target.Records)
	report := DiffReport{SchemaVersion: DiffSchemaVersion, Base: CatalogReference(base), Target: CatalogReference(target)}
	fieldCounts := map[string]int{}
	for id, before := range baseMap {
		after, ok := targetMap[id]
		if !ok {
			report.Removed++
			report.RemovedRecordIDs = append(report.RemovedRecordIDs, id)
			continue
		}
		if recordsEqual(before, after) {
			report.Unchanged++
			continue
		}
		report.Modified++
		report.ModifiedRecordIDs = append(report.ModifiedRecordIDs, id)
		for _, name := range changedFields(before, after) {
			fieldCounts[name]++
		}
	}
	for id := range targetMap {
		if _, ok := baseMap[id]; !ok {
			report.Added++
			report.AddedRecordIDs = append(report.AddedRecordIDs, id)
		}
	}
	sort.Strings(report.AddedRecordIDs)
	sort.Strings(report.ModifiedRecordIDs)
	sort.Strings(report.RemovedRecordIDs)
	for name, count := range fieldCounts {
		report.ModifiedFieldCounts = append(report.ModifiedFieldCounts, NamedCount{Name: name, Count: count})
	}
	sort.Slice(report.ModifiedFieldCounts, func(i, j int) bool { return report.ModifiedFieldCounts[i].Name < report.ModifiedFieldCounts[j].Name })
	report.TotalChanges = report.Added + report.Modified + report.Removed
	denominator := base.RecordCount
	if target.RecordCount > denominator {
		denominator = target.RecordCount
	}
	if denominator > 0 {
		report.ChangeRatioBasisPoints = report.TotalChanges * 10000 / denominator
	}
	if base.RecordCount > 0 {
		report.DeletionRatioBasisPoints = report.Removed * 10000 / base.RecordCount
	}
	report.ReportID = stableID("catalog_diff", struct {
		Base, Target                        CatalogRef
		Added, Modified, Removed, Unchanged int
		Fields                              []NamedCount
	}{report.Base, report.Target, report.Added, report.Modified, report.Removed, report.Unchanged, report.ModifiedFieldCounts})
	return report, ValidateDiff(report)
}

func recordMap(records []ofaccatalog.DirectListRecord) map[string]ofaccatalog.DirectListRecord {
	out := make(map[string]ofaccatalog.DirectListRecord, len(records))
	for _, record := range records {
		out[record.ProviderRecordID] = record
	}
	return out
}

func recordsEqual(a, b ofaccatalog.DirectListRecord) bool { return reflect.DeepEqual(a, b) }

func changedFields(a, b ofaccatalog.DirectListRecord) []string {
	fields := []struct {
		name string
		a, b any
	}{
		{"entity_type", a.EntityType, b.EntityType}, {"sdn_type", a.SDNType, b.SDNType}, {"primary_name", a.PrimaryName, b.PrimaryName},
		{"title", a.Title, b.Title}, {"remarks", a.Remarks, b.Remarks}, {"programs", a.Programs, b.Programs},
		{"aliases", a.Aliases, b.Aliases}, {"addresses", a.Addresses, b.Addresses}, {"identifiers", a.Identifiers, b.Identifiers},
		{"dates_of_birth", a.DatesOfBirth, b.DatesOfBirth}, {"places_of_birth", a.PlacesOfBirth, b.PlacesOfBirth},
		{"nationalities", a.Nationalities, b.Nationalities}, {"citizenships", a.Citizenships, b.Citizenships},
		{"vessel_attributes", a.VesselAttributes, b.VesselAttributes}, {"source_assertion", a.SourceAssertion, b.SourceAssertion},
	}
	var out []string
	for _, field := range fields {
		if !reflect.DeepEqual(field.a, field.b) {
			out = append(out, field.name)
		}
	}
	return out
}

func canonicalJSON(value any) ([]byte, error) { return json.Marshal(value) }
